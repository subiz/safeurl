package safeurl

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	urllib "net/url"
	"strings"
	"sync"
	"syscall"
	"time"
)

var DefaultClient *WrappedClient

func init() {
	cfg := GetConfigBuilder().
		EnableIPv6(true).
		Build()

	DefaultClient = Client(cfg)
}

func buildHttpClient(wc *WrappedClient) *http.Client {
	client := &http.Client{
		Timeout:       wc.config.Timeout,
		CheckRedirect: wc.config.CheckRedirect,
		Jar:           wc.config.Jar,
		Transport: &http.Transport{
			TLSClientConfig: wc.tlsConfig,
			DialContext: (&net.Dialer{
				Resolver: wc.resolver,
				Control:  buildRunFunc(wc),
			}).DialContext,
		},
	}

	return client
}

func buildRunFunc(wc *WrappedClient) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		wc.log(fmt.Sprintf("connection to address: %v", address))

		if !wc.config.IsIPv6Enabled && network == "tcp6" {
			wc.log("ipv6 is disabled")
			return &IPv6BlockedError{ip: address}
		}

		host, port, _ := net.SplitHostPort(address)

		if !isPortAllowed(port, wc.config.AllowedPorts) {
			wc.log(fmt.Sprintf("disallowed port: %v", port))
			return &AllowedPortError{port: port}
		}

		ip := net.ParseIP(host)
		if ip == nil {
			panic(fmt.Sprintf("invalid ip: %v", host))
		}

		if isIPAllowed(ip, wc.config.AllowedIPs, wc.config.AllowedIPsCIDR) {
			return nil
		}

		// allowlist set in the config, but target IP was not found on the list
		isConfigAllowListSet := wc.config.AllowedIPs != nil || wc.config.AllowedIPsCIDR != nil
		if isConfigAllowListSet {
			wc.log(fmt.Sprintf("ip: %v not found in allowlist", ip))
			return &AllowedIPError{ip: ip.String()}
		}

		if isIPBlocked(ip, wc.config.BlockedIPs, wc.config.BlockedIPsCIDR) {
			wc.log(fmt.Sprintf("ip: %v found in blocklist", ip))
			return &AllowedIPError{ip: ip.String()}
		}

		return nil
	}
}

/* validators */

func validateCredentials(parsed *urllib.URL, config *Config, debugLogFunc func(string)) error {
	if config.AllowSendingCredentials {
		return nil
	}

	username := strings.TrimSpace(parsed.User.Username())
	password, _ := parsed.User.Password()
	password = strings.TrimSpace(password)

	if username != "" || password != "" {
		debugLogFunc("credentials found in supplied url.")
		return &SendingCredentialsBlockedError{}
	}

	return nil
}

func isSchemeValid(parsed *urllib.URL, config *Config, debugLogFunc func(string)) error {
	scheme := parsed.Scheme
	if len(scheme) > 0 && !isSchemeAllowed(scheme, config.AllowedSchemes) {
		debugLogFunc(fmt.Sprintf("disallowed scheme: %v", scheme))
		return &AllowedSchemeError{scheme: scheme}
	}
	return nil
}

func isHostValid(parsed *urllib.URL, config *Config, debugLogFunc func(string)) error {
	host := parsed.Hostname()
	if host == "" {
		debugLogFunc("empty host received")
		return &InvalidHostError{host: ""}
	}

	if config.AllowedHosts != nil && !isAllowedHost(host, config.AllowedHosts) {
		debugLogFunc(fmt.Sprintf("disallowed host: %s", host))
		return &AllowedHostError{host: host}
	}

	return nil
}

/* wrapper */

type WrappedClient struct {
	Client *http.Client

	config    *Config
	tlsConfig *tls.Config
	resolver  *net.Resolver

	// used for track DNS resolutions for testing purposes
	tracer *tracer
}

func Client(config *Config) *WrappedClient {
	tlsConfig := config.TlsConfig

	var resolver *net.Resolver = nil
	if config.InTestMode {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, "udp", "localhost:8053")
			},
		}
	}

	wc := &WrappedClient{
		config:    config,
		tlsConfig: tlsConfig,
		resolver:  resolver,
	}

	wc.Client = buildHttpClient(wc)
	return wc
}

func (wc *WrappedClient) Head(url string) (resp *http.Response, err error) {
	wc.log("calling proxied Head...")

	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return nil, err
	}

	return wc.Do(req)
}

func (wc *WrappedClient) Get(url string) (resp *http.Response, err error) {
	wc.log("calling proxied Get...")

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	return wc.Do(req)
}

func (wc *WrappedClient) Post(url string, contentType string, body io.Reader) (resp *http.Response, err error) {
	wc.log("calling proxied Post...")

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}

	return wc.Do(req)
}

func (wc *WrappedClient) PostForm(url string, data urllib.Values) (resp *http.Response, err error) {
	return wc.Post(url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}

func (wc *WrappedClient) Do(req *http.Request) (resp *http.Response, err error) {
	wc.log("calling proxied Do...")

	if wc.config.InTestMode {
		wc.tracer = &tracer{}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), wc.tracer.buildTracer()))
	}

	url := req.URL.String()

	parsedURL, err := urllib.Parse(url)

	if err != nil {
		return nil, err
	}

	err = validateCredentials(parsedURL, wc.config, wc.log)
	if err != nil {
		return nil, err
	}

	err = isSchemeValid(parsedURL, wc.config, wc.log)
	if err != nil {
		return nil, err
	}

	err = isHostValid(parsedURL, wc.config, wc.log)
	if err != nil {
		return nil, err
	}

	return wc.Client.Do(req)
}

func (wc *WrappedClient) CloseIdleConnections() {
	wc.Client.CloseIdleConnections()
}

/* testing */

type tracer struct {
	dnsResolutionsCount int
}

func (t *tracer) buildTracer() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
			t.dnsResolutionsCount++
		},
	}
}

/* error */

type AllowedPortError struct {
	port string
}

func (e *AllowedPortError) Error() string {
	return fmt.Sprintf("port: %v not found in allowlist", e.port)
}

type AllowedSchemeError struct {
	scheme string
}

func (e *AllowedSchemeError) Error() string {
	return fmt.Sprintf("scheme: %v not found in allowlist", e.scheme)
}

type InvalidHostError struct {
	host string
}

func (e *InvalidHostError) Error() string {
	return fmt.Sprintf("host: %v is not valid", e.host)
}

type AllowedHostError struct {
	host string
}

func (e *AllowedHostError) Error() string {
	return fmt.Sprintf("host: %v not found in allowlist", e.host)
}

type AllowedIPError struct {
	ip string
}

func (e *AllowedIPError) Error() string {
	return fmt.Sprintf("ip: %v not found in allowlist", e.ip)
}

type IPv6BlockedError struct {
	ip string
}

func (e *IPv6BlockedError) Error() string {
	return fmt.Sprintf("ipv6 blocked. connection to %v dropped", e.ip)
}

type SendingCredentialsBlockedError struct {
}

func (e *SendingCredentialsBlockedError) Error() string {
	return fmt.Sprintf("sending credentials blocked.")
}

func unwrap(err error) error {
	wrapped, ok := err.(interface{ Unwrap() error })
	if !ok {
		return err
	}
	inner := wrapped.Unwrap()
	return unwrap(inner)
}

/* debug */

func (wc *WrappedClient) log(msg string) {
	if wc.config.IsDebugLoggingEnabled {
		fmt.Printf("[safeurl] %v\n", msg)
	}
}

var (
	ipLookupCache      = make(map[string]*cachedLookup)
	ipLookupCacheMutex sync.Mutex
)

type cachedLookup struct {
	ips        []net.IP
	expiration time.Time
}

func lookupIPWithCache(hostname string) ([]net.IP, error) {
	ipLookupCacheMutex.Lock()
	defer ipLookupCacheMutex.Unlock()

	if cached, found := ipLookupCache[hostname]; found && time.Now().Before(cached.expiration) {
		return cached.ips, nil
	}

	ips, err := net.LookupIP(hostname)
	if err != nil {
		return nil, err
	}

	ipLookupCache[hostname] = &cachedLookup{
		ips:        ips,
		expiration: time.Now().Add(15 * time.Minute),
	}
	return ips, nil
}

// ResolveHref resolves an href relative to a base URL (currentUrl). It returns
// the absolute URL and a boolean indicating if the URL is a safe, external
// resource. The function checks for loopback and private IPs to prevent SSRF
// vulnerabilities.
func ResolveHref(currentUrl, href string) (string, bool) {
	base, err := urllib.Parse(currentUrl)
	if err != nil {
		return "", false
	}

	ref, err := urllib.Parse(href)
	if err != nil {
		return "", false
	}

	fullurl := strings.TrimSpace(base.ResolveReference(ref).String())
	u, err := urllib.Parse(fullurl)
	if err != nil {
		return fullurl, false // Disallow invalid URLs
	}

	if u.User.Username() != "" {
		// user:pass@gmail.com -> invalid
		return fullurl, false
	}

	hostname := u.Hostname()
	if !strings.Contains(hostname, ".") {
		return fullurl, false // localhost, api, ...
	}

	var ips []net.IP
	if ip := net.ParseIP(hostname); ip != nil {
		ips = append(ips, ip)
	} else {
		ips, err = lookupIPWithCache(hostname)
		if err != nil {
			return fullurl, false
		}
	}

	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() {
			return fullurl, false
		}
	}
	return fullurl, true
}

func IsSafe(url string) bool {
	u, err := urllib.Parse(url)
	u.Scheme = "http"
	if err != nil {
		return false
	}
	_, safe := ResolveHref(u.String(), "")
	return safe
}

func IsSafeDomain(url string) (string, bool) {
	url = strings.ToLower(strings.TrimSpace(url))
	if url == "" {
		return "", false
	}

	u, err := urllib.Parse(url)
	if err != nil {
		return "", false
	}
	u.RawQuery = ""
	u.Fragment = ""
	u.Scheme = "http"

	// remove port part
	if strings.Contains(u.Host, ":") {
		u.Host = strings.Split(u.Host, ":")[0]
	}

	_, safe := ResolveHref(u.String(), "")
	u, _ = urllib.Parse(u.String())
	if u == nil {
		return "", false
	}
	return u.Host, safe
}

// Package config loads, defaults and validates the tn-mcp-proxy YAML config.
package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Defaults applied when a field is omitted.
const (
	DefaultListen          = "127.0.0.1:8787"
	DefaultLogLevel        = "info"
	DefaultLogFormat       = "json"
	DefaultAccessTokenTTL  = time.Hour
	DefaultRefreshTokenTTL = 720 * time.Hour
	DefaultCodeTTL         = 5 * time.Minute
	DefaultReloadInterval  = time.Minute

	// DefaultValidateTimeout bounds one credential check; MaxValidateTimeout
	// is the largest accepted validate.timeout.
	DefaultValidateTimeout = 10 * time.Second
	MaxValidateTimeout     = 60 * time.Second

	// Default per-IP rate limits of the OAuth endpoints (requests per minute
	// and burst). They are generous because claude.ai and ChatGPT call register
	// and token from shared egress addresses.
	DefaultRegisterPerMinute  = 60
	DefaultRegisterBurst      = 30
	DefaultTokenPerMinute     = 300
	DefaultTokenBurst         = 100
	DefaultAuthorizePerMinute = 30
	DefaultAuthorizeBurst     = 10

	// KeySize is the required decoded size of every token key (AES-256).
	KeySize = 32
)

// DefaultRedirectURIs returns the redirect URIs allowed when none are configured.
func DefaultRedirectURIs() []string {
	return []string{
		"https://claude.ai/api/mcp/auth_callback",
		"https://claude.com/api/mcp/auth_callback",
		// ChatGPT's stable callback, used for servers that implement RFC 9207
		// issuer identification (this one does).
		"https://chatgpt.com/connector_platform_oauth_redirect",
	}
}

// DefaultTrustedProxies returns the trusted_proxies used when none are
// configured: loopback only (a reverse proxy on the same host).
func DefaultTrustedProxies() []string { return []string{"127.0.0.0/8", "::1/128"} }

// reservedPrefixes are paths owned by the service itself.
var reservedPrefixes = []string{"/oauth", "/.well-known", "/healthz"}

// forbiddenHeaders (lowercase) can never be upstream credential headers.
var forbiddenHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true, "cookie": true, "host": true,
	"content-length": true, "content-type": true, "transfer-encoding": true,
	"connection": true, "keep-alive": true, "upgrade": true, "te": true, "trailer": true,
	"accept": true, "mcp-session-id": true, "mcp-protocol-version": true,
	"forwarded": true, "x-real-ip": true,
}

func headerForbidden(h string) bool {
	l := strings.ToLower(h)
	return forbiddenHeaders[l] || strings.HasPrefix(l, "x-forwarded-")
}

var (
	nameRe = regexp.MustCompile(`^[a-z0-9-]+$`)
	// toolRe is the accepted shape of validate.tool.
	toolRe = regexp.MustCompile(`^[A-Za-z0-9_./-]{1,128}$`)
	// pathRe allows only literal segments: no wildcards, ':', or non-ASCII.
	pathRe = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)+$`)
	// quotedRe matches backtick-quoted values in yaml errors (may echo secrets).
	quotedRe = regexp.MustCompile("`[^`]*`")
)

// Config is the root configuration.
type Config struct {
	Listen    string     `yaml:"listen"`
	PublicURL string     `yaml:"public_url"`
	Log       Log        `yaml:"log"`
	Secrets   Secrets    `yaml:"secrets"`
	OAuth     OAuth      `yaml:"oauth"`
	Upstreams []Upstream `yaml:"upstreams"`
	TLS       TLS        `yaml:"tls"`

	// TrustedProxies lists the CIDRs (or bare IPs) of reverse proxies whose
	// X-Forwarded-For / X-Real-IP headers are honoured. Empty means loopback.
	TrustedProxies []string `yaml:"trusted_proxies"`
	// TrustedNets is TrustedProxies parsed and masked. Filled by Parse.
	TrustedNets []netip.Prefix `yaml:"-"`
}

// Log configures logging.
type Log struct {
	Level  string `yaml:"level"`  // debug|info|warn|error
	Format string `yaml:"format"` // json|text
}

// Secrets holds token encryption keys. Exactly one of TokenKeys and
// TokenKeysFile must be set. Generate keys with `openssl rand -base64 32`.
type Secrets struct {
	TokenKeys     []string `yaml:"token_keys"`
	TokenKeysFile string   `yaml:"token_keys_file"`

	// Keys are the decoded keys (each KeySize bytes) in config order; the
	// first one encrypts, the rest only decrypt. Filled by Load/Parse.
	// TokenKeys is cleared after a successful Parse; Keys holds the result.
	Keys [][]byte `json:"-" yaml:"-"`
}

const redacted = "[redacted]"

// String redacts key material.
func (Secrets) String() string { return redacted }

// GoString redacts key material for %#v.
func (Secrets) GoString() string { return "config.Secrets{" + redacted + "}" }

// LogValue implements slog.LogValuer with a redacted value.
func (Secrets) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalJSON redacts key material.
func (Secrets) MarshalJSON() ([]byte, error) { return json.Marshal(redacted) }

// MarshalYAML redacts key material.
func (Secrets) MarshalYAML() (any, error) { return redacted, nil }

// OAuth configures token lifetimes and redirect URI allow-list.
// A TTL of 0 or unset means the default; negative values are errors.
type OAuth struct {
	AccessTokenTTL      time.Duration `yaml:"access_token_ttl"`
	RefreshTokenTTL     time.Duration `yaml:"refresh_token_ttl"`
	CodeTTL             time.Duration `yaml:"code_ttl"`
	AllowedRedirectURIs []string      `yaml:"allowed_redirect_uris"`
	RateLimit           RateLimit     `yaml:"rate_limit"`
}

// RateLimit configures the per-IP token-bucket limits of the OAuth endpoints.
// Zero or unset values mean the defaults; negative values are errors.
type RateLimit struct {
	Disabled  bool  `yaml:"disabled"`
	Register  Limit `yaml:"register"`  // POST /oauth/register
	Authorize Limit `yaml:"authorize"` // POST /oauth/authorize
	Token     Limit `yaml:"token"`     // POST /oauth/token
}

// Limit is one endpoint's bucket: sustained PerMinute requests, bursts up to Burst.
type Limit struct {
	PerMinute int `yaml:"per_minute"`
	Burst     int `yaml:"burst"`
}

// Resolved returns r with every zero value replaced by its default.
func (r RateLimit) Resolved() RateLimit {
	fill := func(l *Limit, perMinute, burst int) {
		if l.PerMinute == 0 {
			l.PerMinute = perMinute
		}
		if l.Burst == 0 {
			l.Burst = burst
		}
	}
	fill(&r.Register, DefaultRegisterPerMinute, DefaultRegisterBurst)
	fill(&r.Authorize, DefaultAuthorizePerMinute, DefaultAuthorizeBurst)
	fill(&r.Token, DefaultTokenPerMinute, DefaultTokenBurst)
	return r
}

// Upstream describes one proxied MCP server.
type Upstream struct {
	Name        string       `yaml:"name"`
	Title       string       `yaml:"title"`
	Path        string       `yaml:"path"`
	URL         string       `yaml:"url"`
	Credentials []Credential `yaml:"credentials"`
	// Validate, when set, makes the authorize form verify the entered
	// credentials against the upstream before a code is issued.
	Validate *Validate `yaml:"validate"`
}

// Validate configures the credential check: one MCP tools/call made with the
// entered credentials. Tool must be read-only. Timeout bounds the whole check
// (the MCP handshake included); 0 or unset means DefaultValidateTimeout.
type Validate struct {
	Tool      string         `yaml:"tool"`
	Arguments map[string]any `yaml:"arguments"`
	Timeout   time.Duration  `yaml:"timeout"`
}

// Credential is one header the user supplies for an upstream.
type Credential struct {
	Header   string `yaml:"header"`
	Label    string `yaml:"label"`
	Secret   bool   `yaml:"secret"`
	Optional bool   `yaml:"optional"`
}

// TLS configures optional built-in TLS termination. Relative file paths are
// resolved against the config directory. ReloadInterval 0 or unset means the
// default (1m) when TLS is enabled.
type TLS struct {
	CertFile       string        `yaml:"cert_file"`
	KeyFile        string        `yaml:"key_file"`
	ReloadInterval time.Duration `yaml:"reload_interval"`
}

// TLSEnabled reports whether built-in TLS is configured.
func (c *Config) TLSEnabled() bool { return c.TLS.CertFile != "" && c.TLS.KeyFile != "" }

// ResourceURL returns the public MCP resource URL of the upstream.
func (u Upstream) ResourceURL(publicURL string) string {
	return strings.TrimRight(publicURL, "/") + u.Path
}

// SlogLevel maps Log.Level to a slog.Level (info for unknown values).
func (l Log) SlogLevel() slog.Level {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(l.Level)); err != nil {
		return slog.LevelInfo
	}
	return lvl
}

// Load reads, decodes, defaults and validates the config file at p.
// A relative secrets.token_keys_file is resolved against the file's directory.
func Load(p string) (*Config, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	cfg, err := Parse(data, filepath.Dir(p))
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", p, err)
	}
	return cfg, nil
}

// Parse decodes config data strictly, applies defaults, loads keys and
// validates. baseDir resolves a relative secrets.token_keys_file.
func Parse(data []byte, baseDir string) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	err := dec.Decode(&cfg)
	if err == nil {
		// A second document must not exist.
		var extra yaml.Node
		if err2 := dec.Decode(&extra); !errors.Is(err2, io.EOF) {
			if err2 != nil {
				return nil, decodeError(err2)
			}
			return nil, errors.New("decoding yaml: multiple documents are not supported")
		}
	} else if !errors.Is(err, io.EOF) {
		return nil, decodeError(err)
	}
	cfg.resolvePaths(baseDir)
	cfg.applyDefaults()

	var errs []error
	if err := cfg.loadKeys(); err != nil {
		errs = append(errs, err)
	}
	errs = append(errs, cfg.validate()...)
	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid config: %w", errors.Join(errs...))
	}
	cfg.Secrets.TokenKeys = nil // decoded into Keys; don't keep encoded copies
	return &cfg, nil
}

// decodeError strips backtick-quoted values: yaml echoes offending scalars,
// which may be key material.
func decodeError(err error) error {
	return fmt.Errorf("decoding yaml: %s", quotedRe.ReplaceAllString(err.Error(), "`<redacted>`"))
}

// resolvePaths makes relative file paths absolute against baseDir.
func (c *Config) resolvePaths(baseDir string) {
	for _, p := range []*string{&c.Secrets.TokenKeysFile, &c.TLS.CertFile, &c.TLS.KeyFile} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(baseDir, *p)
		}
	}
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	c.PublicURL = strings.TrimSpace(c.PublicURL)
	if n, err := normalizePublicURL(c.PublicURL); err == nil {
		c.PublicURL = n // invalid values are left as-is and reported by validate
	}
	c.Log.Level = strings.ToLower(strings.TrimSpace(c.Log.Level))
	if c.Log.Level == "" {
		c.Log.Level = DefaultLogLevel
	}
	c.Log.Format = strings.ToLower(strings.TrimSpace(c.Log.Format))
	if c.Log.Format == "" {
		c.Log.Format = DefaultLogFormat
	}
	if c.OAuth.AccessTokenTTL == 0 {
		c.OAuth.AccessTokenTTL = DefaultAccessTokenTTL
	}
	if c.OAuth.RefreshTokenTTL == 0 {
		c.OAuth.RefreshTokenTTL = DefaultRefreshTokenTTL
	}
	if c.OAuth.CodeTTL == 0 {
		c.OAuth.CodeTTL = DefaultCodeTTL
	}
	if len(c.OAuth.AllowedRedirectURIs) == 0 {
		c.OAuth.AllowedRedirectURIs = DefaultRedirectURIs()
	}
	for i := range c.Upstreams {
		u := &c.Upstreams[i]
		if u.Title == "" {
			u.Title = u.Name
		}
		for j := range u.Credentials {
			if cr := &u.Credentials[j]; cr.Label == "" {
				cr.Label = cr.Header
			}
		}
		if u.Validate != nil && u.Validate.Timeout == 0 {
			u.Validate.Timeout = DefaultValidateTimeout
		}
	}
	if c.TLSEnabled() && c.TLS.ReloadInterval == 0 {
		c.TLS.ReloadInterval = DefaultReloadInterval
	}
	if len(c.TrustedProxies) == 0 {
		c.TrustedProxies = DefaultTrustedProxies()
	}
	c.OAuth.RateLimit = c.OAuth.RateLimit.Resolved()
}

// loadKeys resolves the key source and decodes Secrets.Keys.
func (c *Config) loadKeys() error {
	s := &c.Secrets
	hasList, hasFile := len(s.TokenKeys) > 0, s.TokenKeysFile != ""
	switch {
	case hasList && hasFile:
		return errors.New("secrets: exactly one of token_keys and token_keys_file must be set, got both")
	case !hasList && !hasFile:
		return errors.New("secrets: exactly one of token_keys and token_keys_file must be set, got neither")
	}

	// encoded[i] is described by where[i]; error text never includes key text.
	var encoded, where []string
	if hasList {
		encoded = s.TokenKeys
		for i := range encoded {
			where = append(where, fmt.Sprintf("secrets.token_keys[%d]", i))
		}
	} else {
		raw, err := os.ReadFile(s.TokenKeysFile)
		if err != nil {
			return fmt.Errorf("secrets.token_keys_file: reading keys file: %w", err)
		}
		for n, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			encoded = append(encoded, line)
			where = append(where, fmt.Sprintf("secrets.token_keys_file line %d", n+1))
		}
		if len(encoded) == 0 {
			return fmt.Errorf("secrets.token_keys_file: %s contains no keys", s.TokenKeysFile)
		}
	}

	var errs []error
	keys := make([][]byte, 0, len(encoded))
	seen := map[string]string{}
	for i, e := range encoded {
		k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(e))
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: not valid standard base64", where[i]))
		case len(k) != KeySize:
			errs = append(errs, fmt.Errorf("%s: decoded length is %d bytes, want %d", where[i], len(k), KeySize))
		default:
			if prev, dup := seen[string(k)]; dup {
				errs = append(errs, fmt.Errorf("%s: duplicates %s", where[i], prev))
			}
			seen[string(k)] = where[i]
			keys = append(keys, k)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	s.Keys = keys
	return nil
}

func (c *Config) validate() []error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if _, port, err := net.SplitHostPort(c.Listen); err != nil {
		add("listen: %q must be host:port", c.Listen)
	} else if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		add("listen: port %q must be a number in 0..65535", port)
	}

	if c.PublicURL == "" {
		add("public_url: required")
	} else if _, err := normalizePublicURL(c.PublicURL); err != nil {
		add("public_url: %v", err)
	}

	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		add("log.level: %q must be one of debug|info|warn|error", c.Log.Level)
	}
	switch c.Log.Format {
	case "json", "text":
	default:
		add("log.format: %q must be one of json|text", c.Log.Format)
	}

	for _, d := range []struct {
		field string
		v     time.Duration
	}{
		{"oauth.access_token_ttl", c.OAuth.AccessTokenTTL},
		{"oauth.refresh_token_ttl", c.OAuth.RefreshTokenTTL},
		{"oauth.code_ttl", c.OAuth.CodeTTL},
	} {
		if d.v <= 0 {
			add("%s: must be a positive duration", d.field)
		}
	}
	redirects := map[string]int{}
	for i, r := range c.OAuth.AllowedRedirectURIs {
		if err := checkHTTPURL(r, true); err != nil {
			add("oauth.allowed_redirect_uris[%d]: %v", i, err)
		}
		if j, dup := redirects[r]; dup {
			add("oauth.allowed_redirect_uris[%d]: duplicates [%d]", i, j)
		}
		redirects[r] = i
	}

	if len(c.Upstreams) == 0 {
		add("upstreams: at least one upstream is required")
	}
	names := map[string]int{}
	paths := map[string]int{}
	for i := range c.Upstreams {
		errs = append(errs, c.Upstreams[i].validate(i, names, paths)...)
	}
	// No upstream path may be a segment-wise prefix of another.
	for i := range c.Upstreams {
		for j := i + 1; j < len(c.Upstreams); j++ {
			a, b := c.Upstreams[i].Path, c.Upstreams[j].Path
			if a != b && (segPrefix(a, b) || segPrefix(b, a)) {
				add("upstreams[%d].path: %q overlaps upstreams[%d].path %q", j, b, i, a)
			}
		}
	}

	for _, l := range []struct {
		field string
		v     Limit
	}{
		{"register", c.OAuth.RateLimit.Register},
		{"authorize", c.OAuth.RateLimit.Authorize},
		{"token", c.OAuth.RateLimit.Token},
	} {
		if l.v.PerMinute < 0 {
			add("oauth.rate_limit.%s.per_minute: must not be negative", l.field)
		}
		if l.v.Burst < 0 {
			add("oauth.rate_limit.%s.burst: must not be negative", l.field)
		}
	}

	c.TrustedNets = c.TrustedNets[:0]
	for i, raw := range c.TrustedProxies {
		p, err := parseTrusted(raw)
		if err != nil {
			add("trusted_proxies[%d]: %v", i, err)
			continue
		}
		c.TrustedNets = append(c.TrustedNets, p)
	}

	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		add("tls: cert_file and key_file must be set together")
	}
	if c.TLS.ReloadInterval < 0 {
		add("tls.reload_interval: must be a positive duration")
	}
	return errs
}

func (u *Upstream) validate(i int, names, paths map[string]int) []error {
	var errs []error
	add := func(format string, a ...any) {
		errs = append(errs, fmt.Errorf("upstreams[%d]."+format, append([]any{i}, a...)...))
	}

	switch {
	case u.Name == "":
		add("name: required")
	case !nameRe.MatchString(u.Name):
		add("name: %q must match [a-z0-9-]+", u.Name)
	default:
		if j, dup := names[u.Name]; dup {
			add("name: %q duplicates upstreams[%d]", u.Name, j)
		}
		names[u.Name] = i
	}

	switch {
	case u.Path == "":
		add("path: required")
	case !strings.HasPrefix(u.Path, "/"):
		add("path: %q must start with '/'", u.Path)
	case strings.HasSuffix(u.Path, "/"):
		add("path: %q must not end with '/'", u.Path)
	case !pathRe.MatchString(u.Path) || hasDotSegment(u.Path):
		add("path: %q must consist of literal segments [A-Za-z0-9._~-] (no wildcards, '.' or '..')", u.Path)
	default:
		if j, dup := paths[u.Path]; dup {
			add("path: %q duplicates upstreams[%d]", u.Path, j)
		}
		paths[u.Path] = i
		for _, r := range reservedPrefixes {
			if segPrefix(u.Path, r) || segPrefix(r, u.Path) {
				add("path: %q overlaps reserved path %s", u.Path, r)
				break
			}
		}
	}

	if u.URL == "" {
		add("url: required")
	} else if err := checkHTTPURL(u.URL, true); err != nil {
		add("url: %v", err)
	}

	seen := map[string]int{}
	required := 0
	for j, cr := range u.Credentials {
		if !cr.Optional {
			required++
		}
		switch {
		case cr.Header == "":
			add("credentials[%d].header: required", j)
			continue
		case !validHeaderToken(cr.Header):
			add("credentials[%d].header: %q is not a valid HTTP header name", j, cr.Header)
			continue
		case headerForbidden(cr.Header):
			add("credentials[%d].header: %q is not allowed", j, cr.Header)
			continue
		}
		key := strings.ToLower(cr.Header)
		if k, dup := seen[key]; dup {
			add("credentials[%d].header: %q duplicates credentials[%d]", j, cr.Header, k)
		}
		seen[key] = j
	}
	if required == 0 {
		add("credentials: at least one non-optional credential is required")
	}
	if u.Validate != nil {
		for _, err := range u.Validate.validate() {
			add("validate.%v", err)
		}
	}
	return errs
}

// validate checks v; errors are prefixed by the caller. Argument values are
// never echoed (they could be secrets); the tool name is not secret.
func (v *Validate) validate() []error {
	var errs []error
	switch {
	case v.Tool == "":
		errs = append(errs, errors.New("tool: required"))
	case !toolRe.MatchString(v.Tool):
		errs = append(errs, fmt.Errorf("tool: %q must match %s", v.Tool, toolRe))
	}
	if v.Timeout < 0 || v.Timeout > MaxValidateTimeout {
		errs = append(errs, fmt.Errorf("timeout: must be between 0 and %s", MaxValidateTimeout))
	}
	if _, err := json.Marshal(v.Arguments); err != nil {
		errs = append(errs, errors.New("arguments: must be a JSON-compatible object (string keys, no NaN/Inf)"))
	}
	return errs
}

// segPrefix reports whether p equals prefix or lies under it segment-wise.
func segPrefix(p, prefix string) bool {
	return p == prefix || strings.HasPrefix(p, prefix+"/")
}

func hasDotSegment(p string) bool {
	for seg := range strings.SplitSeq(p, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// normalizePublicURL validates raw and returns the canonical form: lowercase
// scheme and host, default port dropped, no trailing slash. A path is
// rejected: RFC 8414/9728 well-known URIs live at the host root.
func normalizePublicURL(raw string) (string, error) {
	if err := checkHTTPURL(raw, false); err != nil {
		return "", err
	}
	u, _ := url.Parse(raw) // checked above
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]" // IPv6 literal
	}
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	defaultPort := scheme == "http" && port == "80" || scheme == "https" && port == "443"
	if port != "" && !defaultPort {
		host += ":" + port
	}
	if strings.TrimRight(u.EscapedPath(), "/") != "" {
		return "", errors.New("must be an origin without a path (well-known metadata is served at the host root)")
	}
	return scheme + "://" + host, nil
}

// checkHTTPURL requires an absolute http(s) URL without userinfo or fragment
// (and without query unless allowQuery). Errors never include the value, as
// it may carry credentials; the field path identifies it.
func checkHTTPURL(raw string, allowQuery bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("is not a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("must be an absolute http(s) URL")
	}
	if u.User != nil {
		return errors.New("must not contain userinfo")
	}
	if u.Host == "" {
		return errors.New("has no host")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return errors.New("must not contain a fragment")
	}
	if !allowQuery && (u.RawQuery != "" || strings.Contains(raw, "?")) {
		return errors.New("must not contain a query")
	}
	if strings.HasSuffix(u.Host, ":") {
		return errors.New("has an empty port")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.ParseUint(p, 10, 16); err != nil || n == 0 {
			return errors.New("port must be in 1..65535")
		}
	}
	return nil
}

// validHeaderToken reports whether s is an RFC 7230 token.
func validHeaderToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// parseTrusted parses a CIDR or a bare IP (taken as /32 or /128). IPv4-mapped
// IPv6 notation is rejected: write the IPv4 form instead.
func parseTrusted(raw string) (netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	var p netip.Prefix
	if strings.Contains(raw, "/") {
		var err error
		if p, err = netip.ParsePrefix(raw); err != nil {
			return netip.Prefix{}, errors.New("is not a valid CIDR or IP address")
		}
	} else {
		a, err := netip.ParseAddr(raw)
		if err != nil || a.Zone() != "" {
			return netip.Prefix{}, errors.New("is not a valid CIDR or IP address")
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4In6() {
		return netip.Prefix{}, errors.New("must not use IPv4-mapped IPv6 notation; write the IPv4 form")
	}
	if p.Bits() == 0 {
		return netip.Prefix{}, errors.New("must not match every address (prefix length 0 would make X-Forwarded-For fully spoofable)")
	}
	return p.Masked(), nil
}

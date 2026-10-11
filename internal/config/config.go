// Package config loads, defaults and validates the tn-mcp-proxy YAML config.
package config

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Defaults applied when a field is omitted.
const (
	DefaultListen          = "127.0.0.1:8787"
	DefaultLogLevel        = "info"
	DefaultLogFormat       = "json"
	DefaultAccessTokenTTL  = time.Hour
	DefaultRefreshTokenTTL = 720 * time.Hour
	DefaultMaxSessionTTL   = 2160 * time.Hour // 90 days
	DefaultCodeTTL         = 5 * time.Minute
	// MaxCodeTTL and MaxAccessTokenTTL are the largest accepted lifetimes: OAuth
	// 2.1 recommends authorization codes of at most 10 minutes, and an access
	// token cannot be revoked, so its TTL is the window of a thief.
	MaxCodeTTL            = 10 * time.Minute
	MaxAccessTokenTTL     = 24 * time.Hour
	DefaultReloadInterval = time.Minute

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
	// DefaultAuthorizeFormPerMinute/Burst limit GET /oauth/authorize (rendering
	// the form seals a request, so it is not free), far above the POST limit
	// because a browser may load the form repeatedly.
	DefaultAuthorizeFormPerMinute = 300
	DefaultAuthorizeFormBurst     = 100

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
	Listen    string      `yaml:"listen"`
	PublicURL string      `yaml:"public_url"`
	Log       Log         `yaml:"log"`
	Secrets   Secrets     `yaml:"secrets"`
	OAuth     OAuth       `yaml:"oauth"`
	Limits    ProxyLimits `yaml:"limits"`
	Audit     Audit       `yaml:"audit"`
	Upstreams []Upstream  `yaml:"upstreams"`
	TLS       TLS         `yaml:"tls"`

	// AllowInsecureHTTP lets public_url, allowed_redirect_uris and upstream
	// URLs use plain http for non-loopback hosts (loopback hosts may always
	// use http). Off by default.
	AllowInsecureHTTP bool `yaml:"allow_insecure_http"`

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

// Audit configures the opt-in audit log: info-level records ("audit" with an
// event field) that tie a client IP to the credentials marked audit: true, so
// an operator can answer "who used account X through this server, and when".
// The proxy never deletes records: log rotation is the operator's.
type Audit struct {
	Enabled bool `yaml:"enabled"`
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
	MaxSessionTTL       time.Duration `yaml:"max_session_ttl"` // absolute lifetime of a refresh chain, counted from the code exchange
	CodeTTL             time.Duration `yaml:"code_ttl"`
	AllowedRedirectURIs []string      `yaml:"allowed_redirect_uris"`
	RateLimit           RateLimit     `yaml:"rate_limit"`
	// Page is the operator's contact and notice on the authorize page.
	Page Page `yaml:"page"`
}

// RateLimit configures the per-IP token-bucket limits of the OAuth endpoints.
// Zero or unset values mean the defaults; negative values are errors.
type RateLimit struct {
	// Disabled switches off every limit below, the global authorize ceiling
	// included.
	Disabled  bool  `yaml:"disabled"`
	Register  Limit `yaml:"register"`  // POST /oauth/register
	Authorize Limit `yaml:"authorize"` // POST /oauth/authorize
	Token     Limit `yaml:"token"`     // POST /oauth/token
	// AuthorizeForm limits GET /oauth/authorize (the credentials form).
	AuthorizeForm Limit `yaml:"authorize_form"`

	// AuthorizeGlobal is the unkeyed ceiling on all POST /oauth/authorize
	// requests together. Zero values mean a default derived from code_ttl.
	AuthorizeGlobal Limit `yaml:"authorize_global"`
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
	fill(&r.AuthorizeForm, DefaultAuthorizeFormPerMinute, DefaultAuthorizeFormBurst)
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
	// ForbiddenArguments lists tool argument names that the proxy refuses in
	// tools/call requests (top-level keys of params.arguments, matched
	// case-insensitively), so a token holder cannot pass credentials as tool
	// arguments around the injected headers. Setting it makes the proxy read
	// and parse every POST body, and fail closed on bodies it cannot inspect.
	ForbiddenArguments []string `yaml:"forbidden_arguments"`
}

// Limits on forbidden_arguments.
const (
	MaxForbiddenArguments   = 32
	MaxForbiddenArgumentLen = 128
)

// Validate configures the credential check: one MCP tools/call made with the
// entered credentials. Tool must be read-only. Timeout bounds the whole check
// (the MCP handshake included); 0 or unset means DefaultValidateTimeout.
//
// RecheckOnToolError also runs the same check when a proxied response carries
// a tool error (isError: true): if the upstream then rejects the stored
// credentials, the client gets 401 invalid_token and re-authorizes. Needed for
// upstreams that report bad keys as HTTP 200 tool errors instead of 401.
type Validate struct {
	Tool               string         `yaml:"tool"`
	Arguments          map[string]any `yaml:"arguments"`
	Timeout            time.Duration  `yaml:"timeout"`
	RecheckOnToolError bool           `yaml:"recheck_on_tool_error"`
}

// Credential is one header the user supplies for an upstream.
//
// AllowedValues, when non-empty, restricts the credential to those exact
// values (compared after trimming surrounding whitespace, like the authorize
// form does). It is allowed only on non-secret credentials, so no secret ends
// up in the config file.
//
// Audit makes the audit log (see Audit) record the value, so it is not allowed
// together with Secret. A credential with neither flag is never logged.
type Credential struct {
	Header        string   `yaml:"header"`
	Label         string   `yaml:"label"`
	Secret        bool     `yaml:"secret"`
	Audit         bool     `yaml:"audit"`
	Optional      bool     `yaml:"optional"`
	AllowedValues []string `yaml:"allowed_values"`
}

// MaxCredentialValueLen is the longest credential value (bytes) the authorize
// form accepts; allowed_values entries are held to the same cap.
const MaxCredentialValueLen = 4096

// AuditedCredentials returns the credentials whose values the audit log records.
func (u Upstream) AuditedCredentials() []Credential {
	var out []Credential
	for _, cr := range u.Credentials {
		if cr.Audit && !cr.Secret {
			out = append(out, cr)
		}
	}
	return out
}

// MaxCredentialLabelLen is the longest credential label, in characters.
const MaxCredentialLabelLen = 128

// DisplayLabel is the label of cr shown on the authorize page: Label, else the
// header name (Parse already fills Label that way).
func (cr Credential) DisplayLabel() string {
	if cr.Label != "" {
		return cr.Label
	}
	return cr.Header
}

// NeverLoggedLabels returns the labels of the credentials whose values the
// server never writes to its logs: every credential that is not audited, in
// config order. Secret ones included; none of them is stored either, they only
// travel in the tokens.
func (u Upstream) NeverLoggedLabels() []string {
	var out []string
	for _, cr := range u.Credentials {
		if cr.Audit && !cr.Secret {
			continue
		}
		out = append(out, cr.DisplayLabel())
	}
	return out
}

// AuditedLabels returns the labels of the audited credentials, in config
// order, for the authorize page.
func (u Upstream) AuditedLabels() []string {
	var out []string
	for _, cr := range u.AuditedCredentials() {
		out = append(out, cr.DisplayLabel())
	}
	return out
}

// HasAllowList reports whether any credential of u restricts its values.
func (u Upstream) HasAllowList() bool {
	for _, cr := range u.Credentials {
		if len(cr.AllowedValues) > 0 {
			return true
		}
	}
	return false
}

// CredsAllowed reports whether creds (canonical header name -> value, as stored
// in token payloads) satisfy every allowed_values list of u. With no lists it is
// always true. A credential that has a list must be present and match one entry
// exactly. Comparison is constant-time per candidate and does not stop at the
// first match, so timing reveals nothing about the configured values.
func (u Upstream) CredsAllowed(creds map[string]string) bool {
	ok := true
	for _, cr := range u.Credentials {
		if len(cr.AllowedValues) == 0 {
			continue
		}
		got := sha256.Sum256([]byte(strings.TrimSpace(creds[http.CanonicalHeaderKey(cr.Header)])))
		match := 0
		for _, want := range cr.AllowedValues {
			w := sha256.Sum256([]byte(strings.TrimSpace(want)))
			match |= subtle.ConstantTimeCompare(got[:], w[:])
		}
		if match != 1 {
			ok = false
		}
	}
	return ok
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
	errs = append(errs, cfg.OAuth.Page.loadTerms()...)
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
	c.OAuth.Page.resolveTermsPath(baseDir)
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
	c.OAuth.Page.normalize()
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
	if c.OAuth.MaxSessionTTL == 0 {
		c.OAuth.MaxSessionTTL = DefaultMaxSessionTTL
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
			cr := &u.Credentials[j]
			cr.Label = strings.TrimSpace(cr.Label)
			if cr.Label == "" {
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
	c.Limits = c.Limits.Resolved()
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
		case insecureKey(k):
			errs = append(errs, fmt.Errorf("%s: is a known insecure key (the published example key, or an all-zero, repeated-byte or incrementing pattern); generate one with `openssl rand -base64 32`", where[i]))
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

// exampleKey is the key that older example configs shipped (bytes 0x00..0x1f).
// It is public, so it must never protect real tokens. insecureKey's
// constant-step rule already covers it; the explicit match is kept so the
// shipped example key stays rejected even if that heuristic changes.
const exampleKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

// insecureKey reports whether k is a known-weak token key: the published
// example key, or any constant-stride byte sequence (all zero, all the same
// byte, 0,1,2,... and the like).
func insecureKey(k []byte) bool {
	if ex, err := base64.StdEncoding.DecodeString(exampleKey); err == nil && bytes.Equal(k, ex) {
		return true
	}
	for i := 2; i < len(k); i++ {
		if k[i]-k[i-1] != k[1]-k[0] {
			return false
		}
	}
	return len(k) > 0
}

// errInsecureScheme is returned for a non-https URL that is not exempt.
var errInsecureScheme = errors.New("must use https (http is allowed only for loopback hosts or with allow_insecure_http)")

// checkTransport requires https unless the host is loopback or allowInsecure
// is set. raw must already have passed checkHTTPURL.
func checkTransport(raw string, allowInsecure bool) error {
	u, err := url.Parse(raw)
	if err != nil || strings.EqualFold(u.Scheme, "https") || allowInsecure {
		return nil
	}
	if isLoopbackHost(u.Hostname()) {
		return nil
	}
	return errInsecureScheme
}

// isLoopbackHost reports whether h is localhost or a loopback IP literal.
func isLoopbackHost(h string) bool {
	if strings.EqualFold(strings.TrimSuffix(h, "."), "localhost") {
		return true
	}
	a, err := netip.ParseAddr(h)
	return err == nil && a.Unmap().IsLoopback()
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
	} else if err := checkTransport(c.PublicURL, c.AllowInsecureHTTP); err != nil {
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

	errs = append(errs, c.OAuth.Page.validate()...)
	if c.Audit.Enabled && (c.Log.Level == "warn" || c.Log.Level == "error") {
		add("audit.enabled: needs log.level debug or info, audit records are written at info level")
	}

	for _, d := range []struct {
		field string
		v     time.Duration
	}{
		{"oauth.access_token_ttl", c.OAuth.AccessTokenTTL},
		{"oauth.refresh_token_ttl", c.OAuth.RefreshTokenTTL},
		{"oauth.max_session_ttl", c.OAuth.MaxSessionTTL},
		{"oauth.code_ttl", c.OAuth.CodeTTL},
	} {
		if d.v <= 0 {
			add("%s: must be a positive duration", d.field)
		}
	}
	if c.OAuth.CodeTTL > MaxCodeTTL {
		add("oauth.code_ttl: %s exceeds the maximum of %s", c.OAuth.CodeTTL, MaxCodeTTL)
	}
	if c.OAuth.AccessTokenTTL > MaxAccessTokenTTL {
		add("oauth.access_token_ttl: %s exceeds the maximum of %s", c.OAuth.AccessTokenTTL, MaxAccessTokenTTL)
	}
	redirects := map[string]int{}
	for i, r := range c.OAuth.AllowedRedirectURIs {
		if err := checkHTTPURL(r, true); err != nil {
			add("oauth.allowed_redirect_uris[%d]: %v", i, err)
		} else if err := checkTransport(r, c.AllowInsecureHTTP); err != nil {
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
		// Upstream.validate already checks URL syntax (and reports it); this
		// second parse only adds the scheme rule, which needs the config-wide
		// allow_insecure_http. It runs only when the syntax is fine, so one
		// bad URL never yields two errors.
		if u := c.Upstreams[i].URL; u != "" && checkHTTPURL(u, true) == nil {
			if err := checkTransport(u, c.AllowInsecureHTTP); err != nil {
				add("upstreams[%d].url: %v", i, err)
			}
		}
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
		{"authorize_form", c.OAuth.RateLimit.AuthorizeForm},
		{"authorize_global", c.OAuth.RateLimit.AuthorizeGlobal},
	} {
		if l.v.PerMinute < 0 {
			add("oauth.rate_limit.%s.per_minute: must not be negative", l.field)
		}
		if l.v.Burst < 0 {
			add("oauth.rate_limit.%s.burst: must not be negative", l.field)
		}
	}

	if g := c.OAuth.RateLimit.AuthorizeGlobal; g.PerMinute == 0 && g.Burst > 0 {
		add("oauth.rate_limit.authorize_global.burst: needs per_minute to be set too")
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
	errs = append(errs, c.Limits.validate()...)
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
		if cr.Audit && cr.Secret {
			add("credentials[%d].audit: not allowed together with secret (a secret is never logged)", j)
		}
		switch {
		case utf8.RuneCountInString(cr.Label) > MaxCredentialLabelLen:
			add("credentials[%d].label: longer than %d characters", j, MaxCredentialLabelLen)
		case badText(cr.Label, false):
			add("credentials[%d].label: must be valid UTF-8 printable text without control or format characters", j)
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
		for _, err := range cr.validateAllowed() {
			add("credentials[%d].%v", j, err)
		}
	}
	if required == 0 {
		add("credentials: at least one non-optional credential is required")
	}
	if u.Validate != nil {
		for _, err := range u.Validate.validate() {
			add("validate.%v", err)
		}
	}
	if u.HasAllowList() && u.Validate == nil {
		add("allowed_values requires validate (otherwise any secret paired with an allowed key gets a token)")
	}
	for _, err := range validateForbidden(u.ForbiddenArguments) {
		add("forbidden_arguments%v", err)
	}
	return errs
}

// validateForbidden checks forbidden_arguments. Each error starts with an
// index suffix or a colon, so the caller prefixes the field name.
func validateForbidden(names []string) []error {
	var errs []error
	if len(names) > MaxForbiddenArguments {
		errs = append(errs, fmt.Errorf(": at most %d names", MaxForbiddenArguments))
	}
	for k, n := range names {
		switch {
		case n == "":
			errs = append(errs, fmt.Errorf("[%d]: must not be empty", k))
		case len(n) > MaxForbiddenArgumentLen:
			errs = append(errs, fmt.Errorf("[%d]: longer than %d bytes", k, MaxForbiddenArgumentLen))
		case !utf8.ValidString(n):
			errs = append(errs, fmt.Errorf("[%d]: invalid UTF-8", k))
		case n != strings.TrimSpace(n):
			errs = append(errs, fmt.Errorf("[%d]: must not have leading or trailing whitespace", k))
		case strings.IndexFunc(n, unicode.IsControl) >= 0:
			errs = append(errs, fmt.Errorf("[%d]: must not contain control characters", k))
		default:
			for j := range k {
				if strings.EqualFold(names[j], n) {
					errs = append(errs, fmt.Errorf("[%d]: duplicates forbidden_arguments[%d] (case-insensitive)", k, j))
					break
				}
			}
		}
	}
	return errs
}

// validateAllowed checks AllowedValues. Errors name entries by index and never
// echo a value.
func (cr Credential) validateAllowed() []error {
	if len(cr.AllowedValues) == 0 {
		return nil
	}
	var errs []error
	if cr.Secret {
		errs = append(errs, errors.New("allowed_values: not allowed on a secret credential (set secret: false; the values are stored in the config)"))
	}
	seen := map[string]int{}
	for k, v := range cr.AllowedValues {
		t := strings.TrimSpace(v)
		switch {
		case !utf8.ValidString(v) || strings.IndexFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0:
			errs = append(errs, fmt.Errorf("allowed_values[%d]: contains control characters or invalid UTF-8", k))
		case t == "":
			errs = append(errs, fmt.Errorf("allowed_values[%d]: must not be empty", k))
		case len(t) > MaxCredentialValueLen:
			errs = append(errs, fmt.Errorf("allowed_values[%d]: longer than %d bytes", k, MaxCredentialValueLen))
		default:
			if j, dup := seen[t]; dup {
				errs = append(errs, fmt.Errorf("allowed_values[%d]: duplicates allowed_values[%d]", k, j))
			}
			seen[t] = k
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

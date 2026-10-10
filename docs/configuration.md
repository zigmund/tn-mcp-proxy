# Configuration

tn-mcp-proxy reads a single YAML file (see `deploy/config.example.yaml`).
Unknown keys, multiple YAML documents and invalid values are startup errors;
all validation problems are reported together with field paths.
Error messages never echo URL or key material.

## Fields

| Field | Default | Notes |
|---|---|---|
| `listen` | `127.0.0.1:8787` | `host:port`, port 0..65535 |
| `public_url` | required | Absolute http(s) origin: no path (the proxy owns the host-root `/.well-known/*` and `/oauth/*` paths), userinfo, query or fragment. Normalized: lowercase scheme/host, default port (80/443) dropped, trailing slash stripped |
| `log.level` | `info` | `debug`, `info`, `warn`, `error` (case-insensitive; other values are rejected; `debug` enables the access log) |
| `log.format` | `json` | `json`, `text` (case-insensitive; other values are rejected) |
| `secrets.token_keys` | | Base64 (standard) of 32 bytes each; first key encrypts, others only decrypt |
| `secrets.token_keys_file` | | File with one base64 key per line; `#` comments and blank lines ignored |
| `oauth.access_token_ttl` | `1h` | Positive duration |
| `oauth.refresh_token_ttl` | `720h` | Positive duration; refresh tokens are single-use (reuse revokes the login's token family) and every refresh restarts this lifetime (sliding expiry) |
| `oauth.code_ttl` | `5m` | Positive duration; lifetime of an authorization code from submission of the credentials form. Codes are single-use |
| `oauth.allowed_redirect_uris` | claude.ai and claude.com `/api/mcp/auth_callback` | Absolute http(s) URLs, no duplicates |
| `oauth.rate_limit.disabled` | `false` | Turns the in-app per-IP rate limiting of the OAuth endpoints off. See [Rate limiting](#rate-limiting) |
| `oauth.rate_limit.register` | `per_minute: 60`, `burst: 30` | Limit for `POST /oauth/register` |
| `oauth.rate_limit.token` | `per_minute: 300`, `burst: 100` | Limit for `POST /oauth/token` |
| `oauth.rate_limit.authorize` | `per_minute: 30`, `burst: 10` | Limit for `POST /oauth/authorize` (the credentials form submission) |
| `trusted_proxies` | `["127.0.0.0/8", "::1/128"]` | Top-level list of CIDRs (or bare IPs, taken as `/32` or `/128`) of reverse proxies whose `X-Forwarded-For` / `X-Real-IP` are honoured. Empty or unset means loopback only. See [Client IP](#client-ip) |
| `upstreams[]` | at least one | See below |
| `tls.cert_file`, `tls.key_file` | empty | Set both or neither |
| `tls.reload_interval` | `1m` | Used when TLS is enabled |

For all durations, `0` or unset means the default; negative values are rejected.
The same holds for `per_minute` and `burst` of every rate limit (a zero value is
replaced by its default; to switch limiting off use `oauth.rate_limit.disabled`).

Relative `secrets.token_keys_file`, `tls.cert_file` and `tls.key_file` paths are
resolved against the config file's directory.

Exactly one of `secrets.token_keys` and `secrets.token_keys_file` must be set.
Keys must be unique. After loading, the decoded keys are available only as
`Config.Secrets.Keys`; the encoded strings are dropped and secrets are redacted
in logs, `fmt`, JSON and YAML output.

### Upstream

| Field | Default | Rules |
|---|---|---|
| `name` | required | Unique, `[a-z0-9-]+` |
| `title` | `name` | Shown on the authorize form. Clients select the upstream with the `resource` parameter (`public_url` + `path`), which may be omitted only with exactly one upstream |
| `path` | required | Matches `^(/[A-Za-z0-9._~-]+)+$`, no `.`/`..` segments, no trailing slash. Must not equal or overlap `/oauth`, `/.well-known`, `/healthz`; no upstream path may be a segment-wise prefix of another |
| `url` | required | Absolute http(s) URL, no userinfo/fragment |
| `credentials[]` | at least one non-optional | Headers the user supplies |

Credential fields: `header` (required, valid HTTP header name, unique
case-insensitively per upstream), `label` (default: header), `secret` (mask
input), `optional`. Each credential becomes one input on the authorize form; values are trimmed and must not contain control characters.

Forbidden credential headers: `Authorization`, `Proxy-Authorization`, `Cookie`,
`Host`, `Content-Length`, `Content-Type`, `Transfer-Encoding`, `Connection`,
`Keep-Alive`, `Upgrade`, `TE`, `Trailer`, `Accept`, `Mcp-Session-Id`,
`Mcp-Protocol-Version`, `Forwarded`, `X-Real-IP` and `X-Forwarded-*`.

## Keys

Generate a key:

```sh
openssl rand -base64 32
```

Rotation: prepend a new key to `token_keys` (or the keys file) so it becomes the
encrypting key, keep the old key for decryption, and drop the old key once
`oauth.refresh_token_ttl` has passed, when no token sealed with it remains valid.

## Logging

The service logs through `log/slog`; `log.level` is the threshold and
`log.format` selects JSON or text records. The service writes its log output
to stderr.

At `debug` an access log is enabled: one `http request` record per request,
written when the request finishes (a long-lived SSE stream is therefore logged
only once it closes). Fields: `method`, `path`, `status`, `bytes` (response
body size), `duration`, `remote`, `user_agent` and `proto`. A handler panic is
logged with `panic=true` (or `aborted=true` for an aborted response) and then
propagates as usual. At any other level the middleware does nothing beyond
calling the handler.

Never recorded: the query string (OAuth codes and state travel there; only the
URL path is logged), request or response headers (`Authorization`, `Cookie`,
...), request or response bodies, and tokens.

`remote` holds the client IP only, without a port, resolved as described in
[Client IP](#client-ip); the rate limiter uses the same value.

## Client IP

The access log and the rate limiter share one client IP resolver driven by
`trusted_proxies` (default: loopback, `127.0.0.0/8` and `::1/128`). Entries are
CIDRs or bare IPs (`192.0.2.7` means `192.0.2.7/32`, `2001:db8::1` means
`2001:db8::1/128`); zones, IPv4-mapped IPv6 notation and prefix length 0
(`0.0.0.0/0`, `::/0`, which would make the header fully spoofable) are rejected, and every
problem is reported with its field path at startup.

1. If the TCP peer is **not** in `trusted_proxies`, the peer address is the
   client and `X-Forwarded-For` / `X-Real-IP` are ignored entirely, so a client
   cannot spoof its address (and thereby dodge the limiter).
2. If the peer is trusted, the `X-Forwarded-For` entries (all header lines,
   comma-separated) are read from the right. Entries in `trusted_proxies` are
   skipped (they are proxies in the chain); the first untrusted entry is the
   client. Entries to its left are client-controlled and ignored. If every
   entry is trusted, the left-most one is used.
3. An entry that is not a valid IP (including an empty one) stops the walk and
   the header is treated as unusable, even if trusted entries were already
   skipped. Entries with a port (`203.0.113.9:443`) or brackets (`[2001:db8::1]`)
   are not valid IPs and count as invalid. Then a valid `X-Real-IP` is used, and otherwise the peer itself.

IPv6 zones are dropped and IPv4-mapped addresses unmapped. Examples with
`trusted_proxies: ["10.0.0.0/8"]` and peer `10.1.2.3`: `X-Forwarded-For:
203.0.113.9, 10.0.0.5` gives `203.0.113.9`; `X-Forwarded-For: 6.6.6.6,
203.0.113.9` gives `203.0.113.9` (the right-most untrusted entry, not the
spoofed `6.6.6.6`).

With a single proxy that overwrites the header (the nginx snippet below), the
default is all you need. Behind a second tier (CDN, load balancer) add its
addresses to `trusted_proxies`. Note that setting `trusted_proxies` replaces the
default, so list loopback too if the local proxy still connects from there.

## Rate limiting

`POST /oauth/register`, `POST /oauth/authorize` (the credentials form) and
`POST /oauth/token` are limited per client IP with a token bucket: `per_minute`
is the sustained rate and `burst` the number of requests that may arrive at
once. Each endpoint has its own bucket set. `GET /oauth/authorize`, the
metadata documents, `/healthz`, CORS preflights, non-POST requests to the token
endpoint (a plain 405) and the proxied MCP paths are not limited.

IPv4 clients are keyed by address and IPv6 clients by their `/64` prefix (one
attacker usually controls a whole `/64`). The key table holds at most 10 000
clients: when full, buckets that have already refilled are dropped, and
otherwise the least recently seen client is evicted. A new client is therefore
never refused because of table size; a flood of distinct addresses can only
reset the buckets of the oldest clients.

A limited request gets `429 Too Many Requests` with `Retry-After` (whole
seconds, rounded up):

- token and register: the usual JSON error body with the endpoint's usual
  headers (`Cache-Control: no-store`, ...):
  `{"error":"temporarily_unavailable","error_description":"rate limit exceeded"}`.
  RFC 6749 has no throttling code; `temporarily_unavailable` is the closest
  registered one and means retry later.
- authorize: the HTML error page ("Too many requests. ..."); the user agent is
  never redirected to the client.

Each hit is logged at `debug` as `rate limit exceeded` (endpoint, client IP,
retry delay; never the query, headers or body), and the 429 shows up in the
access log.

The defaults are generous because claude.ai calls register and token from
shared egress addresses: all connecting users then share one bucket. Raise them
if many users connect at once; lower them on a private deployment.

```yaml
oauth:
  rate_limit:
    register:  { per_minute: 60,  burst: 30 }
    token:     { per_minute: 300, burst: 100 }
    authorize: { per_minute: 30,  burst: 10 }
    # disabled: true
trusted_proxies: ["127.0.0.0/8", "::1/128"]
```

## Reverse proxy

The service speaks plain HTTP (built-in TLS is not implemented yet; setting
`tls.*` is a startup error), so put a TLS-terminating reverse proxy in front.
Certificates, HTTP->HTTPS redirects and HSTS are your own setup; the nginx
snippet below shows only what this service needs. The proxy must forward every
path (`/.well-known/*`, `/oauth/*` and the upstream paths) to the service.
The service does not depend on the proxy for rate limiting (see
[Rate limiting](#rate-limiting)), but it needs the proxy's address in
`trusted_proxies` (loopback by default) to see real client IPs.

```nginx
# http{} context (conf.d/*.conf is already inside it). Optional extra layer: the
# service rate-limits /oauth/* itself (see Rate limiting), this one sheds load earlier.
limit_req_zone $binary_remote_addr zone=tn_oauth:10m rate=30r/m;
limit_req_status 429;

server {
    listen 443 ssl;                     # HTTP/2 is optional: `http2 on;` here (nginx >= 1.25.1) or `listen 443 ssl http2;` on older nginx
    server_name mcp.example.com;
    ssl_certificate     /etc/letsencrypt/live/mcp.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mcp.example.com/privkey.pem;

    client_max_body_size 10m;           # the service rejects bodies over 10 MiB (413)

    # Proxy settings at server level are inherited by both locations below
    # (proxy_set_header only while a location defines no proxy_set_header of its own).
    proxy_http_version 1.1;
    proxy_set_header Connection        "";               # keepalive to the service
    proxy_set_header Host              $host;
    # Overwrite, do not append: the service trusts a loopback peer (see
    # trusted_proxies) and takes the right-most untrusted entry, so a
    # client-supplied header must not add one.
    proxy_set_header X-Forwarded-For   $remote_addr;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    # MCP uses SSE / streamable HTTP: no buffering, long idle streams.
    proxy_buffering         off;
    proxy_request_buffering off;
    proxy_read_timeout      1h;
    proxy_send_timeout      1h;

    # Optional: /healthz is for local checks, no need to expose it.
    location = /healthz { return 404; }

    # OAuth endpoints. The service limits them per client IP on its own; this
    # nginx limit is optional defence in depth. Keep it generous: claude.ai
    # calls register/token from shared egress IPs, so all users share one
    # bucket. Behind a CDN or load balancer restore the real client IP first
    # (ngx_http_realip_module), otherwise everyone shares a bucket.
    location /oauth/ {
        limit_req zone=tn_oauth burst=30 nodelay;
        proxy_pass http://127.0.0.1:8787;
    }

    location / {                        # /.well-known/* and MCP upstream paths
        proxy_pass http://127.0.0.1:8787;
    }
}
```

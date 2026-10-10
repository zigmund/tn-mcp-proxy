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
| `upstreams[]` | at least one | See below |
| `tls.cert_file`, `tls.key_file` | empty | Set both or neither |
| `tls.reload_interval` | `1m` | Used when TLS is enabled |

For all durations, `0` or unset means the default; negative values are rejected.

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

`remote` holds the client IP only, without a port. It is the TCP peer address,
except when the peer is a loopback address (a reverse proxy on the same host):
then the right-most `X-Forwarded-For` entry is used, falling back to
`X-Real-IP`. Earlier entries are client-controlled, so the proxy must
overwrite the header with the address it saw instead of appending to a
client-supplied one. Values that are not valid IPs are ignored, IPv6 zones are
dropped. From a non-loopback peer both headers are ignored, so they cannot be
spoofed.

## Reverse proxy

The service speaks plain HTTP (built-in TLS is not implemented yet; setting
`tls.*` is a startup error), so put a TLS-terminating reverse proxy in front.
Certificates, HTTP->HTTPS redirects and HSTS are your own setup; the nginx
snippet below shows only what this service needs. The proxy must forward every
path (`/.well-known/*`, `/oauth/*` and the upstream paths) to the service.

```nginx
# http{} context (conf.d/*.conf is already inside it). Rate limit for /oauth/*.
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
    # Overwrite, do not append: the service trusts the right-most entry from a
    # loopback peer, so a client-supplied header must not add one.
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

    # OAuth endpoints. Abuse can fill the service's bounded in-memory code and
    # refresh-family caches (it then answers 503 to legitimate users).
    # Keep the limit generous: claude.ai calls register/token from shared
    # egress IPs, so all users share one bucket. Behind a CDN or load balancer
    # restore the real client IP first (ngx_http_realip_module), otherwise
    # everyone shares a bucket.
    location /oauth/ {
        limit_req zone=tn_oauth burst=30 nodelay;
        proxy_pass http://127.0.0.1:8787;
    }

    location / {                        # /.well-known/* and MCP upstream paths
        proxy_pass http://127.0.0.1:8787;
    }
}
```

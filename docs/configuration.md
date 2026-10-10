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
| `oauth.refresh_token_ttl` | `720h` | Positive duration |
| `oauth.code_ttl` | `5m` | Positive duration |
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
| `title` | `name` | Shown on the authorize form |
| `path` | required | Matches `^(/[A-Za-z0-9._~-]+)+$`, no `.`/`..` segments, no trailing slash. Must not equal or overlap `/oauth`, `/.well-known`, `/healthz`; no upstream path may be a segment-wise prefix of another |
| `url` | required | Absolute http(s) URL, no userinfo/fragment |
| `credentials[]` | at least one non-optional | Headers the user supplies |

Credential fields: `header` (required, valid HTTP header name, unique
case-insensitively per upstream), `label` (default: header), `secret` (mask
input), `optional`.

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
except when the peer is a loopback address (nginx on the same host): then the
right-most `X-Forwarded-For` entry is used (the one nginx appended; earlier
entries are client-controlled), falling back to `X-Real-IP`. Values that are
not valid IPs are ignored, IPv6 zones are dropped. From a non-loopback peer
both headers are ignored, so they cannot be spoofed. nginx should set both:

```nginx
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Real-IP       $remote_addr;
```

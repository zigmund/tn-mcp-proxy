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
| `log.level` | `info` | `debug`, `info`, `warn`, `error` (`debug` enables the access log) |
| `log.format` | `json` | `json`, `text` |
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

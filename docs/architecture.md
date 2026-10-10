# Architecture

## Overview

_To be written._

## OAuth flow

Discovery sequence (claude.ai custom connector):

1. The client calls the MCP endpoint without a token and gets `401` with
   `WWW-Authenticate: Bearer resource_metadata="<public_url>/.well-known/oauth-protected-resource<upstream.path>"`.
2. It fetches the protected resource metadata (RFC 9728), which names the
   proxy (`public_url`) as the authorization server.
3. It fetches the authorization server metadata (RFC 8414). Clients following
   the 2025-03-26 spec skip steps 1-2 and request
   `/.well-known/oauth-authorization-server` directly.
4. It registers via dynamic client registration (`/oauth/register`).
5. It sends the user to `/oauth/authorize` (PKCE S256 required); the user
   enters the upstream credentials on the proxy's form.
6. It exchanges the code at `/oauth/token`, then refreshes with
   `grant_type=refresh_token`.

| Endpoint | Path | Notes |
| --- | --- | --- |
| Protected resource metadata | `/.well-known/oauth-protected-resource<upstream.path>` | One per upstream; the bare path is served only with exactly one upstream |
| AS metadata | `/.well-known/oauth-authorization-server` | Same document also at `/.well-known/openid-configuration`, a fallback for MCP 2025-06-18 clients (the proxy is not a full OIDC provider) |
| Client registration | `/oauth/register` | DCR (RFC 7591) |
| Authorization | `/oauth/authorize` | Authorization code + PKCE S256 |
| Token | `/oauth/token` | `authorization_code` and `refresh_token` grants |

Metadata documents are static, built once at startup from `public_url` and
the upstream list, and served with `Cache-Control: public, max-age=300` and
`Access-Control-Allow-Origin: *` (GET/HEAD, plus `OPTIONS` for CORS preflight). All endpoint URLs are
absolute and derived from `public_url`, which must be an origin without a path:
RFC 8414 and RFC 9728 place `/.well-known/*` at the host root, so the proxy
must own the root `/.well-known/*` and `/oauth/*` paths of its host.

The flow is stateless: client ids, authorization codes and tokens are sealed
blobs (see Token sealing), so no server-side session or storage exists.
Details of register, authorize and token are documented as those endpoints land.

## Proxying

Each upstream gets one handler (`proxy.New`) mounted at its `path`.

**Request path.** Only the exact `path` is served; anything else (sub-paths,
encoded or unclean variants such as `%2f` or `//`) gets 404 and never reaches
the upstream. A request with an `Upgrade` header gets 400. Otherwise the
request is authenticated and then sent by `httputil.ReverseProxy` to the
upstream `url` exactly, with its path and escaping untouched. The client's
query string is forwarded only if the upstream `url` has no query of its own;
otherwise the configured query is used as is. Any method passes through (POST,
GET for the SSE stream, DELETE for session end). The request body is capped at
10 MiB (413 beyond that).

**Auth.** `Authorization: Bearer <token>` (scheme case-insensitive) is opened
as a `seal.KindAccess` token into `tokens.Access`. Checks: authentic and
unexpired, `Upstream` equals the upstream name, every non-optional credential
header present in the token (values with CR/LF/NUL are rejected; the log names
only the header). Only headers configured for the upstream are injected;
extras in the token are ignored. A payload that does not decode (for example
after a deploy changed its shape) is logged at error level and answered like
any invalid token, so the client re-authorizes.

**Header handling.** `Authorization`, `Cookie`, `Proxy-Authorization`,
`X-Real-IP`, all `X-Forwarded-*` and `Forwarded` are stripped from the inbound
request, as is every configured credential header (including optional ones),
and then the token's credentials are set. Credentials are applied after
`ReverseProxy` removes hop-by-hop headers, so a `Connection:` header cannot
drop them. Client IPs are never forwarded (`SetXForwarded` is not used).
`Host` is the upstream host. Everything else passes through, notably
`Mcp-Session-Id`, `Mcp-Protocol-Version`, `Accept`, `Content-Type`,
`Last-Event-ID`, `Origin` and `Referer`. `Set-Cookie` is stripped from
responses.

**Streaming and timeouts.** `FlushInterval: -1` flushes every write, so SSE
events reach the client immediately. The upstream transport has no overall
timeout and no response header timeout (slow tool calls and idle streams are
legitimate); only dial (10s) and TLS handshake (10s) are bounded, with 30s
keepalive and up to 64 idle connections per host. Compression is not
negotiated or touched by the proxy: bytes pass through opaquely. A client
disconnect cancels the upstream request through the request context.

**Upstream 401.** If the upstream answers 401 (the stored credentials were
revoked or are wrong), its `WWW-Authenticate` is replaced with
`Bearer error="invalid_token", error_description="upstream rejected credentials", resource_metadata="..."`
and a warning is logged. claude.ai then re-runs authorization and the user can
enter new keys.

**Errors.**

| Status | When | `WWW-Authenticate` |
|--------|------|--------------------|
| 400 | `Upgrade` header present | none |
| 401 | no Bearer token | `Bearer resource_metadata="<public_url>/.well-known/oauth-protected-resource<path>"` |
| 401 | invalid, expired, wrong kind, wrong upstream, bad payload, missing credentials, or upstream 401 | `Bearer error="invalid_token", error_description="...", resource_metadata="..."` |
| 404 | path is not exactly `path` | none |
| 413 | request body over 10 MiB | none |
| 500 | the sealer itself is broken (server bug) | none |
| 502 | upstream unreachable or failed (logged at warn) | none |
| 504 | upstream timeout (logged at warn) | none |

A client that disconnects mid-request gets no response (logged at debug).
Tokens and credentials are never logged. Debug logs carry only the upstream
name and response status.

## Token sealing

The service is stateless: OAuth client ids, authorization codes, access tokens
and refresh tokens are self-contained blobs produced by `internal/seal`. Access
and refresh tokens carry upstream credentials, so they are both encrypted and
authenticated.

**Format.** `base64url(version || keyID || nonce || ciphertext+tag)`, no padding.
Version is 1 byte (currently `1`), key id 4 bytes, nonce 12 random bytes, and the
cipher is AES-256-GCM. The plaintext is the JSON envelope
`{"exp": <unix seconds>, "d": <payload>}`; `exp` of 0 or absent means the token
never expires (used for DCR client ids).

**Kind binding.** The AAD is `version || keyID || kind`, where kind is one of
`client`, `code`, `access`, `refresh`. A token sealed as one kind fails
authentication when opened as another, and the header cannot be altered.

**Sub-keys.** Each configured 32-byte secret is expanded with HKDF-SHA256 into
an AES-256-GCM key, an HMAC-SHA256 key and the key id, each with its own info
label (`tn-mcp-proxy seal v1 aead|mac|key id`).

**Key ids and rotation.** The key id is 4 bytes of HKDF output, so `Open` picks
the right key directly. The first configured secret is primary: it seals tokens
and computes MACs. All secrets are accepted for opening and MAC verification.
To rotate: prepend a new secret, deploy, and remove the old one once its tokens
have expired. Duplicate secrets or key id collisions are rejected at startup.

**Size limit.** Encoded tokens are at most 16 KiB. `Seal` refuses to produce
larger tokens and `Open` rejects them before decoding.

**Strict encoding.** Only canonical base64url is accepted (no padding, CR/LF or
non-zero trailing bits), so each token has exactly one string form and is safe
to use as a cache key (for example single-use codes).

**Error contract.**

- `ErrInvalid`: malformed, tampered, wrong kind, unknown key id or bad version.
  Callers must not distinguish these cases (maps to `invalid_grant` /
  `invalid_token`).
- `ErrExpired`: authentic token whose expiry has passed (checked only after
  authentication; a token is expired when `now >= exp`).
- `ErrPayload`: authentic, unexpired token whose payload does not decode into
  the caller's type. This is a server-side bug and should surface as a 500.

**Nonce volume.** Nonces are random 96-bit values, which bounds safe usage to
roughly 2^32 seals per key. Rotation switches sealing to a new key and resets
the count.

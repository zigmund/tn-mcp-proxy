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

_To be written._

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

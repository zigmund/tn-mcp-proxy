# Architecture

## Overview

_To be written._

## OAuth flow

_To be written._

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

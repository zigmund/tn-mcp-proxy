# Architecture

## Overview

_To be written._

## OAuth flow

Discovery sequence (claude.ai and ChatGPT custom connectors):

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
blobs (see Token sealing), so no server-side session or storage exists. The
one exception is a small in-memory cache of used code ids and refresh token
families (see Token endpoint).

### Authorization

`GET /oauth/authorize` validates the request and renders the credentials form;
`POST /oauth/authorize` turns the submitted form into an authorization code.
Other methods get `405`. No CORS headers are set (the endpoint is only
navigated to).

**Validation and error policy.** The client is checked first: `client_id` must
open as a `client` seal (`openClient`) and `redirect_uri` must exactly match
one of its URIs and still be in `oauth.allowed_redirect_uris`
(`redirectAllowed`). Until both hold, errors are rendered as an HTML error page
(`400`) and never redirected, so the endpoint cannot be used as an open
redirector. Repeated `client_id`/`redirect_uri` parameters are errors too.
After that, errors are redirected to the `redirect_uri` with `error`,
`error_description`, `state` and `iss` (RFC 6749 section 4.1.2.1, RFC 9207):
`unsupported_response_type` (`response_type` is not `code`),
`invalid_request` (PKCE missing or not `S256`, malformed `code_challenge`,
`state` over 1 KiB, repeated parameters; an invalid `state` is not echoed back), `invalid_target` (RFC 8707: unknown
`resource`). `resource` must equal an upstream's public MCP URL
(`public_url` + `path`) byte for byte (no trailing-slash or origin-only
normalization); it may be omitted only when exactly one upstream is
configured.

**ChatGPT and RFC 9207.** ChatGPT uses the stable redirect URI
`https://chatgpt.com/connector_platform_oauth_redirect` only with servers that
implement issuer identification (RFC 9207); otherwise it may fall back to a
per-connector callback that cannot be allowlisted exactly. The proxy meets the
requirements: the AS metadata (both documents) has
`authorization_response_iss_parameter_supported: true`; its `issuer` is
`public_url` and is byte-identical to the `authorization_servers` entry of the
protected resource metadata; and `iss` (= `public_url`) is added to every
redirect from the authorize endpoint, success and error alike, GET and POST.
Client ID Metadata Documents are not supported and not advertised, so ChatGPT
registers through DCR.

**Form.** Fields come from the upstream's `credentials` (secrets are password
inputs). The page leads with the host the user returns to as the identity of the
application ("<host> is requesting access to <upstream title>"), because
the application name is attacker-controlled (open DCR; a homoglyph name can
imitate a known client). The name is shown only as a secondary line labelled
"self-declared, unverified", stripped of control characters and HTML-escaped. The validated request is sealed (`seal.KindAuthRequest`, 15 minute
expiry) into a hidden `request` field. Responses carry `Cache-Control:
no-store`, `X-Frame-Options: DENY` and a CSP with `default-src 'none'`, the
single inline stylesheet allowed by hash (no inline script),
`frame-ancestors 'none'`, `base-uri 'none'` and `form-action 'self'` plus the
origin of the `redirect_uri` (Chrome applies `form-action` to the redirect
that follows the POST, so the client's origin must be listed).

**Submission.** The POST body is capped at 32 KiB. Only the sealed `request`
and the `cred_N` fields are read; the client, redirect and upstream are
re-validated against the current config, so a revoked redirect or removed
upstream fails even for an already rendered form. Values are trimmed; a
required one that is empty, longer than 4 KiB or containing control characters
re-renders the form (`400`) with a message and without echoing secrets.
If the upstream has `validate`, the credentials are then checked against it
(see Credential validation below); only accepted credentials reach the code
step. On success the proxy answers `303 See Other` to `redirect_uri?code=...&state=...&iss=...`
(also for errors found at POST time, so the browser never re-sends the
credentials; errors found at GET time use `302`). The AS metadata advertises
`authorization_response_iss_parameter_supported: true` (RFC 9207).

**Credential validation.** Without it the form would accept anything and
anyone could mint a working token, using the proxy as a relay to the upstream.
With `validate` configured (internal/oauth/credcheck.go) `authorizeSubmit`
makes one authenticated MCP exchange before issuing a code: `initialize`,
`notifications/initialized`, then `tools/call` of the configured read-only
tool, all with the entered credential headers, and a best-effort `DELETE` when
the upstream issued a session. Classification: HTTP `401`/`403` at any step or
a tool result with `isError: true` means rejected (form re-rendered, `400`);
everything else that is not a clean result (JSON-RPC error, non-2xx, `3xx`,
transport error, timeout, malformed or over-1-MiB body, no response with the
matching id) means unavailable (form re-rendered, `503`), so the check fails
closed. The upstream client never follows redirects (the credential headers
would travel to the redirect target), the whole check is bounded by
`validate.timeout` and the request context, and at most 16 checks run
concurrently (waiting for a slot counts toward `validate.timeout`; the slot is
released before the best-effort session `DELETE`, which may add up to 2 s to
the response). The `503` carries `Retry-After`. The credentials, the URL path
and query, response bodies and upstream error text are never logged; the
transport error may name the upstream host or IP. The price: one extra upstream round trip per submission, and
the form becomes a credential-validity oracle for whoever can reach it, bounded
by the per-IP authorize rate limit. Tokens are thus issued only for
credentials the upstream accepts. Upstreams without `validate` behave as
before and are never contacted from the authorize endpoint.

**CSRF.** No cookies or sessions exist, so there is no ambient authority to
abuse: the only secret in the POST is the credentials the user types, and the
resulting code goes to an allowlisted redirect whose client verifies its own
`state`. The sealed field binds every request parameter (a forged or edited
POST cannot change client, redirect, PKCE challenge or upstream) and expires.
As defence in depth, a POST declared `Sec-Fetch-Site: cross-site` or
`same-site` is refused (an absent header, as in older browsers, is allowed:
this check is defence in depth only). Clickjacking is blocked by `frame-ancestors` and
`X-Frame-Options`. Credentials are never logged.

**Authorization code.** `seal.KindCode` with `tokens.Code`:
`c` client_id, `r` redirect_uri, `ch` PKCE S256 challenge, `u` upstream name,
`h` credentials (canonical header name to value, optional empty ones omitted),
`j` random 128-bit jti, `e` expiry (unix seconds, mirrors the seal envelope).
It expires `oauth.code_ttl` after issue. The code is single-use, enforced by
the token endpoint's in-memory cache (see Token endpoint).

### Client registration

`POST /oauth/register` (RFC 7591) takes a JSON body (`Content-Type:
application/json`, at most 64 KiB, unknown fields ignored) and stores nothing.
The `client_id` is a sealed `client` record, `{redirect_uris, client_name,
token_endpoint_auth_method, issued_at}`, with no expiry. Opening it
(`openClient`) both authenticates it as ours and yields the registered
metadata, so authorize and token never need a lookup. The response is `201`
with `Cache-Control: no-store`; errors are `400` JSON `{error,
error_description}` (`invalid_redirect_uri`, `invalid_client_metadata`), `415`
for a wrong content type. CORS is open (`Access-Control-Allow-Origin: *`,
preflight answered) for browser-based MCP inspectors; no cookies or
credentials are involved.

- **Redirect allowlist.** `redirect_uris` is required (1 to 10 entries); each
  must exactly equal an entry of `oauth.allowed_redirect_uris` (default: the
  claude.ai and claude.com callbacks and ChatGPT's stable
  `https://chatgpt.com/connector_platform_oauth_redirect`). No patterns, no
  normalization. The authorize endpoint checks the redirect URI against both the client's
  registered list and the current config, so removing a URI from the config
  revokes it for clients that registered earlier.
- **Auth methods.** `token_endpoint_auth_method` is `none`,
  `client_secret_post` or `client_secret_basic` (the RFC 7591 default when
  omitted). Anything else is rejected. At the token endpoint a `none` client
  must authenticate with `client_id` only. A secret client must present its
  secret but may send it via Basic or the form body, whichever it uses (some
  clients ignore the registered method); sending it both ways is refused, and
  an empty `client_secret` field counts as absent.
- **Client secret.** For the two secret-based methods the response includes
  `client_secret` = `base64url(MAC("client_secret", client_id))` under the
  seal MAC key, with `client_secret_expires_at: 0`. It is derived, not stored,
  and verified in constant time (`VerifyMAC`, so any still-configured key
  works). Basic credentials are form-urlencoded before base64 (RFC 6749
  section 2.3.1). A `none` client has no secret and relies on PKCE.
- **Grants.** `grant_types` must be a subset of `authorization_code`,
  `refresh_token` and `response_types` a subset of `code` (which requires `authorization_code`
  among the grants); when omitted the
  response reports both grants (we support refresh, unlike the RFC default).
  The grants are validated but neither stored in the client id nor enforced:
  any registered client may use `authorization_code` and `refresh_token`.
  `scope` is ignored. `client_name` is trimmed, stripped of control and
  invisible format characters, capped at 100 runes and shown (HTML-escaped) on
  the authorize page.
- **Key rotation.** The secret and the client id are bound to the token keys.
  While the old key stays configured, registered clients keep working. Once it
  is dropped, their ids stop opening. The first place this surfaces is
  `/oauth/authorize`: with an unverifiable `client_id` it cannot redirect
  (the redirect URI is untrusted), so it renders an error page. The token
  endpoint answers `invalid_client` for such ids; claude.ai handles that by
  registering again.

### Token endpoint

`POST /oauth/token` (`application/x-www-form-urlencoded`, body at most 16 KiB;
only body parameters count, the query string is ignored) serves two grants.
Any other method gets `405` with `Allow: POST`; a wrong content type or a
malformed body gets `400 invalid_request`, an oversized one `413`. Every
response, errors included, carries `Cache-Control: no-store` and
`Pragma: no-cache`. Errors are RFC 6749 section 5.2 JSON
`{error, error_description}`; descriptions are fixed strings and never echo
codes, tokens, verifiers or secrets. A parameter sent twice is
`invalid_request`.

**CORS.** No `Access-Control-*` headers and no preflight (`OPTIONS` gets 405).
claude.ai calls the endpoint server-side; the request carries client
credentials and a PKCE verifier, so browser pages have no business reading
it. Consistent with `/oauth/authorize`; only the registration endpoint is open.

**Client authentication** is `authenticateClient` (see Client registration):
`none`, `client_secret_post` or `client_secret_basic`. Failures are `401
invalid_client` with `WWW-Authenticate: Basic realm="oauth"` when Basic
credentials were used. A `client_id` that does not open (unknown, tampered,
or sealed under a dropped key) is `invalid_client` too, and claude.ai then
registers again.

**`authorization_code`.** Requires `code`, `redirect_uri` and `code_verifier`
(missing: `invalid_request`). The code must open as `seal.KindCode` and be
unexpired. These then all fail as `invalid_grant`, deliberately without saying
which one: `client_id` equals the code's client; `redirect_uri` equals the
code's; the verifier is 43-128 characters of `[A-Za-z0-9-._~]` and
`BASE64URL(SHA256(verifier))` equals the challenge (constant-time compare);
the redirect URI is still registered for the client and still in
`oauth.allowed_redirect_uris`; the upstream still exists in the config.
Last, the code's jti is claimed in the cache. Validation comes first, so a
request that fails (for example a wrong verifier) does not burn the code.

**`refresh_token`.** Requires `refresh_token`. It must open as
`seal.KindRefresh`, be unexpired, belong to the presenting client and name an
upstream that still exists (else `invalid_grant`). It is then redeemed against
the family cache (see Single-use caches) before the new pair is issued.

**`resource` (RFC 8707).** Optional on both grants. When present it must equal
the upstream's resource URI (`public_url` + upstream `path`, the mapping
authorize uses) or the answer is `invalid_target`; when absent the grant's
upstream applies.

**Issue.** Success returns `{access_token, token_type: "Bearer", expires_in,
refresh_token}` (`scope` is omitted: scopes are unused). The access token is
`seal.KindAccess` with `tokens.Access` (what the proxy opens, checking the
upstream name), expiring after `oauth.access_token_ttl`; `expires_in` is that
TTL in seconds. The refresh token is `seal.KindRefresh` with `tokens.Refresh`
(`u`, `c`, `h`, family `f`, generation `g`, expiry `e`, login start `s`),
expiring after `oauth.refresh_token_ttl`. Every refresh rotates the pair and
restarts the refresh expiry (sliding expiry), but the chain has an absolute
lifetime: `s` is the unix time of the code exchange, copied unchanged on every
rotation, and a refresh at or after `s + oauth.max_session_ttl` is an
`invalid_grant`. Refresh expiry, access expiry (and so `expires_in`) are
capped at that session end. A legacy refresh token without `s` (issued before
the field existed) is migrated once: its first refresh treats that moment as
the start, so the new chain is bounded from there on. The credentials travel
from the code into both tokens unchanged. Nothing is revoked server-side when
a client disconnects; the chain simply runs out at the idle or absolute limit.

**Single-use caches.** Both are in memory, per process, guarded by a mutex,
and bounded by constants (not config). Entries expire with the tokens and are
pruned lazily (at most once a minute, once a second while full).

- *Codes:* a map of code jti to code expiry (cap 50,000, about 5 MiB). The
  jti is claimed atomically, so of two concurrent exchanges exactly one
  succeeds; a replay is `invalid_grant`. Validation runs first, so a request
  that fails (for example a wrong verifier) does not burn the code.
- *Refresh tokens:* token families. Each login gets a random family id `f` at
  code exchange; its first refresh token has generation `g=0` and every
  rotation issues `g+1`. The cache holds one entry per family that has
  refreshed: highest used generation and expiry (the newest token's, extended
  on every rotation); cap 100,000, about 200 bytes each, near 20 MiB. Revoked
  families are kept apart, see Revoked families. Redeeming `(f, g)` is atomic:
  a revoked family is `invalid_grant`; `g` not greater than the highest used
  generation is a reuse, which revokes the family (recorded in the revocation
  set; the successor held by the legitimate client stops working too; logged
  at warn with short digests as `client_id` and `family`, the first 8 hex
  characters of their SHA-256, never the raw values) and is `invalid_grant`;
  otherwise
  `g` is recorded and the successor `g+1` issued. A refresh loop therefore
  touches one entry, not one per request. A family with no live entry (never
  refreshed, after a restart, or evicted, see Full cache) is accepted as new.
- *Spent first:* the refresh token is spent before the new pair is sealed.
  A sealing failure, or a client that loses the response, leaves a spent
  token and the client must re-authorize. Claiming after issuing would let
  concurrent requests both succeed.
- *Full cache (codes):* the endpoint fails closed with `503 server_error`
  (not `invalid_grant`: the client did nothing wrong) and the event is logged
  at error. Failing open would accept an untracked code and defeat
  single-use; PKCE and the allowlisted redirect still bind a code, but a leaked
  code plus verifier could then be redeemed repeatedly within `code_ttl`, so
  the cache stays the last line and refuses. The state should be
  unreachable: a global ceiling on `POST /oauth/authorize` (see Cache filling)
  bounds the live codes to at most half the cache. There is no `Retry-After`
  because no honest value exists; slots free up as codes expire (minutes).
- *Full cache (active refresh families):* never a 503 because of the LRU
  itself (a 503 can only come from a full revocation set, see Revoked
  families). A new family evicts the
  least recently used entry. "Used" means created or successfully refreshed.
  The entries live in an intrusive LRU list (`container/list`), so eviction is
  O(1) under the mutex even while an attacker keeps the cache full; expired
  entries are swept lazily, at most once a minute. Evictions are logged at warn
  at most once a minute with a count (never ids). Accepted trade-off: reuse
  detection is lost for an evicted chain. A rotated (old) refresh token of an
  evicted family is accepted once as a new family, exactly as after a restart.
- *Revoked families:* a reuse moves the family out of the LRU into a separate
  revocation set: an 8-byte hash (keyed per process) of the family id plus the
  family's refresh expiry (cap 1,000,000 entries, about 40 MiB). Revoked
  chains are therefore not subject to LRU eviction: no number of attacker-created
  active or revoked families pushes a revoked family out; an entry leaves the
  set only at its natural expiry (all its tokens are dead then), pruned lazily
  (at most once a minute, once a second while full). If the set is full of live
  entries nothing is evicted to make room. Instead an unknown family, which
  could be a revoked one with no record, is refused (`503`, same path as a
  full code cache) until entries expire. "Unknown" includes active chains
  already evicted from the LRU, which get the 503 on their next refresh while
  the set is full; chains still in the LRU keep working.
  This favours integrity over availability: reaching the bound takes
  sustained abuse (see Cache filling) and it never re-opens a stolen chain
  before its expiry. A reuse detected while the set is full is kept as a
  flagged LRU entry that is never evicted for room and moves to the set when
  it has room; if only flagged entries remain, new families fail closed too, so
  memory stays bounded. While the set is full of live entries the prune that
  looks for expired ones scans the whole map once a second, so refreshes of
  unknown families may stall briefly.

## Security considerations

- **Per-process replay state.** The caches live in one process's memory.
  The proxy is meant to run as a single instance; with several replicas a
  code or refresh token could be redeemed once per replica. A restart forgets
  everything: a code used before the restart can be redeemed again until
  `oauth.code_ttl` has passed (PKCE still binds it to the original client),
  and a refresh token used before the restart is accepted once more until its
  expiry (up to `oauth.refresh_token_ttl`, and never past the session end),
  even if its family was revoked.
- **Reuse detection revokes the family, not issued access tokens.** Reusing a
  spent refresh token revokes its family, so the legitimate client's next
  refresh fails and it re-authorizes (the OAuth 2.1 / BCP behavior). Access
  tokens already issued stay valid until they expire (at most
  `oauth.access_token_ttl`), because the proxy is stateless. An attacker who
  steals a refresh token and redeems it first obtains a working chain until
  the legitimate client refreshes and the reuse is detected.
- **Lost refresh responses.** A client that loses the response to a refresh
  request (network failure after the server spent the token) holds a spent
  token and must re-authorize.
- **Cache filling.** Registration is open and, for upstreams without
  `validate`, the credentials form accepts any values (with `validate` each
  login needs credentials the upstream accepts), so anyone can create logins
  (one code entry each, and one family entry once refreshed). The defences are a hierarchy of rate limits, a global
  ceiling on code issuance and the separate revocation set (above). Rate
  limits (internal/ratelimit, wired in internal/oauth/ratelimit.go) apply to
  `POST /oauth/register`, `POST /oauth/authorize` and `POST /oauth/token`: one
  token bucket per client IP and endpoint, answering 429 with `Retry-After`.
  IPv4 is keyed by address; IPv6 is charged against its `/64`, `/56` and `/48`
  (budgets 1x, 4x and 16x the per-`/64` default), all of which must allow the
  request, so rotating `/64`s inside a routed prefix gets the `/48` budget, not
  one allowance per `/64`. Each key table is bounded (10 000 clients per tier;
  idle entries, then the least recently seen ones, are evicted, so it neither
  fails closed nor grows without bound). The client IP comes from the resolver
  shared with the access log (internal/httplog): forwarding headers are honoured
  only from peers in `trusted_proxies` (default loopback), otherwise a client
  could spoof its address. The defaults are generous because claude.ai uses
  shared egress addresses; see Rate limiting in docs/configuration.md. A
  reverse-proxy `limit_req` stays useful as an extra layer. Per-prefix limits
  alone are not a ceiling for an attacker with many prefixes, so
  `POST /oauth/authorize` also has a global token bucket derived from the code
  cache size and `code_ttl` (`50000 / 4 / minutes(code_ttl)` per minute, 2 500
  by default, burst of one minute): at most 15 000 codes can be live at once,
  30% of the cache. Hitting it answers 429 with `Retry-After` and logs at warn
  (at most once a minute).

  Costs with the defaults (attacker's side; every family needs one login, one
  token exchange and one refresh, so authorize is the binding limit):
  - Code cache: cannot be filled through authorize; at the ceiling 15 000 of
    50 000 slots at most. The ceiling can be saturated, which delays new
    logins (429, recovers right after the flood stops): from IPv4 it takes
    about 83 addresses at 30/min, or 5 to 6 IPv6 `/48`s (480/min each).
  - Active families: a chain touched hourly (the default access token TTL) is
    evicted once 100 000 newer families appear within the hour. One IPv6 `/48`
    creates at most 28 800 per hour, so about 4 `/48`s, 56 IPv4 addresses, or
    the saturated global ceiling (150 000 per hour, about 40 minutes) strip
    reuse detection from every ordinary chain. User-visible impact: no lockout
    and no 503; the evicted client's next refresh is accepted as a new family,
    and only reuse detection is lost (a stolen, already rotated token is then
    not caught).
  - Revocations: not evictable by this. Filling the 1 000 000-entry set takes
    1 000 000 own reuse events: about 6.7 hours with the global ceiling
    saturated (blocking everyone else's new logins throughout), about 35 hours
    from one `/48`; entries then live until the refresh TTL (30 days), so the
    cost is sustained but affordable for a determined attacker. The outcome is
    not a resurrected chain but 503 for unknown families (first refresh of new
    logins) until entries expire; so do active chains already evicted from the LRU,
    while chains still in it keep refreshing.
    Raising `oauth.rate_limit.authorize_global` or the per-prefix limits
    shortens these times proportionally.
  - Rotation across many `/48`s (for example a whole `/32`) multiplies the
    per-prefix allowance; only the global ceiling bounds that.
- **Access tokens are bearer and stateless.** They cannot be revoked before
  their expiry; keep `oauth.access_token_ttl` short.
- **Credentials in tokens.** Access and refresh tokens carry the upstream
  credentials, encrypted (see Token sealing); they are never logged.

## Proxying

Each upstream gets one handler (`proxy.New`) mounted at its `path`.

**Request path.** Only the exact `path` is served; anything else (sub-paths,
encoded or unclean variants such as `%2f` or `//`) gets 404 and never reaches
the upstream. A request with an `Upgrade` header gets 400. Otherwise the
request is authenticated and then sent by `httputil.ReverseProxy` to the
upstream `url` exactly, with its path and escaping untouched. The client's
query string is forwarded only if the upstream `url` has no query of its own;
otherwise the configured query is used as is. Only the MCP Streamable HTTP
methods are relayed: POST (messages), GET (SSE stream) and DELETE (session
end). Any other method (HEAD, OPTIONS, PUT, PATCH, TRACE, ...) gets 405 with
`Allow: GET, POST, DELETE`, decided before authentication, so no token is
parsed and the upstream is never contacted. OPTIONS is included: MCP clients do
not use browser CORS preflight for this endpoint. The request body is capped at
10 MiB (413 beyond that).

**Auth.** `Authorization: Bearer <token>` (scheme case-insensitive) is opened
as a `seal.KindAccess` token into `tokens.Access`. Checks: authentic and
unexpired, `Upstream` equals the upstream name, every non-optional credential
header present in the token (values with CR/LF/NUL are rejected; the log names
only the header). Only headers configured for the upstream are injected;
extras in the token are ignored. A payload that does not decode (for example
after a deploy changed its shape) is logged at error level and answered like
any invalid token, so the client re-authorizes.

**Header handling.** Request headers are filtered with an allow-list
(`forwardedHeaders` in `internal/proxy/proxy.go`): `Accept`, `Accept-Encoding`,
`Content-Type`, `Mcp-Session-Id`, `Mcp-Protocol-Version`, `Last-Event-ID`,
`User-Agent` and `Origin`. Everything else is dropped, including
`Authorization`, `Cookie`, `Proxy-Authorization`, `Forwarded`, `X-Forwarded-*`,
`X-Real-IP`, other client-IP headers, URL or method override headers and any
configured credential header the client sent (optional ones too). The proxy
forwards only what MCP needs, so a token holder cannot steer the upstream, or
make it reflect or misuse the injected credentials, with arbitrary headers.
`Origin` is forwarded because MCP servers validate it and that decision
belongs to the upstream. `Content-Length` and `Transfer-Encoding` are derived
by net/http from the request. A client that sends no `User-Agent` gets none
upstream (Go's default is not substituted). Then the token's credentials are
set, after `ReverseProxy` removes hop-by-hop headers (including any header
named in `Connection:`, even an allow-listed one), so a `Connection:` header
cannot drop them. No client-supplied address header is forwarded and
the proxy adds none (`SetXForwarded` is not used), so the upstream sees the
proxy as the client. `Host` is the upstream host. `Set-Cookie` is stripped
from responses.

**Streaming and timeouts.** `FlushInterval: -1` flushes every write, so SSE
events reach the client immediately. The upstream transport has no overall
timeout and no response header timeout (slow tool calls and idle streams are
legitimate); only dial (10s) and TLS handshake (10s) are bounded, with 30s
keepalive and up to 64 idle connections per host. The transport has
compression handling disabled, so response bytes pass through opaquely (the
one exception is the opt-in tool error inspection below). A client
disconnect cancels the upstream request through the request context.

**Upstream 401.** If the upstream answers 401 (the stored credentials were
revoked or are wrong), its `WWW-Authenticate` is replaced with
`Bearer error="invalid_token", error_description="upstream rejected credentials", resource_metadata="..."`
and a warning is logged. claude.ai then re-runs authorization and the user can
enter new keys.

**Upstream tool errors (`validate.recheck_on_tool_error`).** Tradernet never
answers 401 for revoked or wrong keys: `tools/call` returns HTTP `200`,
`Content-Type: application/json` and a JSON-RPC result with `isError: true`.
Left alone, the connector stays "connected" while every call fails. But a tool
error alone is not evidence: bad tickers and closed markets produce them too.
When an upstream sets `validate.recheck_on_tool_error`, a tool error is only a
trigger and the credential check decides. The error text is never read.

Inspection. A response is inspected only when all of these hold: the request is
a `POST`, the upstream status is `200`, the media type is `application/json`,
and the body is at most 64 KiB (read up to the cap plus one byte). The trigger
is any JSON-RPC response in it (a single object or a batch array) with
`result.isError == true`. Everything else is forwarded unchanged: a larger body
is replayed from the buffered prefix and the remainder streamed, so large and
streaming responses are neither broken nor held back; SSE (`text/event-stream`)
and every `GET` are never inspected; malformed JSON, non-200 statuses and other
content types pass through. A body of up to 64 KiB is buffered before
forwarding (a slow `application/json` response is delayed until it ends or
passes the cap). The buffering is bounded in size, not in time.

Re-check. On a trigger the handler runs the credential checker shared with the
authorize form (`internal/credcheck`) for the token's credentials, which are in
the request context: the MCP session `initialize`, `notifications/initialized`,
`tools/call` of `validate.tool` and a best-effort `DELETE`, bounded by
`validate.timeout` and the client's context. Rejected (the check's tool call
returns `isError`, or an HTTP `401`/`403`): the response becomes the same
`401 invalid_token` challenge as the upstream-401 path (short `unauthorized`
body; the upstream body, `Content-Encoding` and `Content-Length` are replaced;
one warning without any body text, header or credential). Anything else (the
check accepts, is unavailable, times out, is skipped, or the client is gone)
forwards the original response, with a debug log of the outcome (a warning for
"unavailable"). Only responses that carried a tool error wait for the check,
about 0.4 to 1 s with Tradernet. In the worst case, when the upstream hangs, a
triggering tool error is held up to `validate.timeout` (default 10 s).

Cost control (in-process, bounded; the rest of the service stays stateless):

- Verdict cache keyed by an HMAC-SHA256 (random per-process key) of the upstream
  name and the canonical credentials, so plaintext credentials are neither map
  keys nor logged. Accepted and rejected verdicts live 60 s; "no verdict" 5 s,
  so an outage is not hammered. At most 4096 entries, oldest evicted first.
- Concurrent re-checks for the same key share one session (single flight). The
  session runs detached from any one client and is bounded by
  `validate.timeout`, so a waiter leaving does not waste it.
- At most 8 re-checks at once across all upstreams. When saturated the
  re-check is skipped and the response passes through.

So a burst of tool errors from one token costs at most one validation session
per minute.

Compression: the stdlib has no brotli, and Tradernet answers `br` when the
client offers it. For `POST`s of an upstream with the option on, the proxy
narrows the outbound `Accept-Encoding` to what it can decode: `gzip` if the
client accepted it (explicit `gzip`/`x-gzip` with q>0, or `*`), otherwise
`identity`; `br`, `zstd` and `deflate` are dropped. A gzip body is decoded only
to inspect it (decoded size is capped at 64 KiB too, so a compression bomb is
not inspected) and the original compressed bytes are forwarded when the
response is not replaced. `GET` keeps its `Accept-Encoding` untouched, and with
the option off nothing about compression changes. Trade-off: such a `POST` gets
gzip or identity bodies, never brotli.

Residual risk: the check reads `isError` on its own tool call as a rejection
(that is how Tradernet reports bad keys, and what the authorize form does), so
a transient failure or a throttling/rate-limit error reported that way is
indistinguishable from a revoked key and forces one unnecessary re-login. That
is likelier exactly when a burst of failing calls triggers re-checks. Network
errors, timeouts, 5xx and JSON-RPC errors are "unavailable" and never cause a
`401`. The cache also means a verdict can be up to 60 s old.

**Errors.**

| Status | When | `WWW-Authenticate` |
|--------|------|--------------------|
| 400 | `Upgrade` header present | none |
| 401 | no Bearer token | `Bearer resource_metadata="<public_url>/.well-known/oauth-protected-resource<path>"` |
| 401 | invalid, expired, wrong kind, wrong upstream, bad payload, missing credentials, upstream 401, or a tool error confirmed by the credential re-check (`validate.recheck_on_tool_error`) | `Bearer error="invalid_token", error_description="...", resource_metadata="..."` |
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
`client`, `code`, `access`, `refresh` or `authreq` (the authorize form's hidden
field). A token sealed as one kind fails
authentication when opened as another, and the header cannot be altered.

**Sub-keys.** Each configured 32-byte secret is expanded with HKDF-SHA256 into
an AES-256-GCM key, an HMAC-SHA256 key and the key id, each with its own info
label (`tn-mcp-proxy seal v1 aead|mac|key id`).

**Key ids and rotation.** The key id is 4 bytes of HKDF output, so `Open` picks
the right key directly. The first configured secret is primary: it seals tokens
and computes MACs. All secrets are accepted for opening and MAC verification.
To rotate: prepend a new secret, deploy, and remove the old one once its tokens
have expired. Duplicate secrets or key id collisions are rejected at startup.

**Size limit.** Encoded tokens are at most 16 KiB (`seal.MaxTokenSize`). `Seal`
refuses to produce larger tokens and `Open` rejects them before decoding.
Payloads are encoded without HTML escaping (`<`, `>` and `&` stay one byte;
tokens sealed with escaping still open). The authorize form measures the
credentials against this cap in the worst-case code, access and refresh token
before any upstream check and answers "The credentials together are too long." instead of
failing later with `server_error`.

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

## Server lifecycle

`internal/server` assembles one `http.ServeMux`: the OAuth metadata and
endpoints, one proxy handler per upstream registered at the exact pattern
`upstream.path` (so `path/` and `path/x` are 404), and `GET /healthz`
(HEAD too) which answers `200 ok` without authentication. `/healthz` is
served outside the access-log middleware so probes do not flood the debug log;
everything else is wrapped by `httplog`.

`http.Server` settings: `ReadHeaderTimeout` 10s (slowloris), `IdleTimeout`
120s (above nginx's 60s upstream keepalive), `MaxHeaderBytes` 64 KiB. There is
intentionally no `ReadTimeout`/`WriteTimeout`: they are absolute deadlines and
would cut SSE streams and slow tool calls. OAuth and `/.well-known/*` requests,
which never stream, get a per-request read deadline of 10s instead
(`http.ResponseController.SetReadDeadline`; slow-body protection), and with
built-in TLS every response carries `Strict-Transport-Security`. `net/http` server errors go to the
slog logger at `warn`.

Signals: `SIGINT`/`SIGTERM` start a graceful shutdown (15s). Streams that
outlive the timeout are closed forcibly and the process still exits 0.
`SIGHUP` never terminates the process; it runs the registered reload hooks
(`Server.OnReload`) or logs `reload requested, nothing to reload`. A listen
failure (e.g. address in use) exits non-zero with the error.

Built-in TLS is optional (`tls.cert_file` + `tls.key_file`). `internal/certreload`
holds the current `*tls.Certificate` in an `atomic.Pointer` and exposes it as
`tls.Config.GetCertificate`; `Server.EnableTLS` makes `Serve` use `ServeTLS` with
that config (TLS 1.2 minimum, `h2` and `http/1.1` ALPN). The pair is loaded
before listening and a failure is fatal. A watcher goroutine tied to the run
context hashes the contents of both files (symlinks followed) every
`tls.reload_interval` and swaps in a valid new pair; `SIGHUP` registers as an
`OnReload` hook that forces a reload. A failed reload keeps the old certificate
and is retried on the next tick. The watcher stops on shutdown.

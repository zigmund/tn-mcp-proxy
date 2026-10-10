# tn-mcp-proxy: security audit

> **Status:** all findings in this report (F-01 to F-07 and I-01 to I-07) were addressed afterwards, or accepted and documented. The [second audit](audit-2026-10-7ac37ab.md) re-verified each one against the fixed code; see its section 3, "Status of the previous findings".
>
> Fixed in: F-01 in #26 (credential validation) and #33 (proxy limits); F-02 in #27; F-03 in #25; F-04 in #28; F-05, F-06 and F-07 in #29; I-01 to I-07 in #31.

Line numbers in the `file:line` evidence below refer to the baseline commit `3eeecc2`, not to the current code.

- **Scope:** `internal/{oauth,seal,tokens,proxy,server,httplog,ratelimit,config,certreload}`, `cmd/`, `deploy/`, README.md, docs/*.md
- **Baseline:** main at `3eeecc2`. During the audit main moved to `9d3759c`, but that diff only touches README, `.gitignore` and the SVG diagrams. No Go code changed, and the new README claims are checked in section 4.
- **Method:** white-box review of the full flow (DCR -> authorize GET/POST -> token (code) -> refresh -> proxied call). `go vet ./...` is clean and `go test ./...` passes. Five PoC tests were run privately against a copy of the repository; each one reproduced its finding. The PoC files are not published. Regression tests for the fixes live in the repository (see the second report).

---

## 1. Summary

The core of the design holds up well. All five token kinds go through one AEAD primitive, and the kind is bound into the AAD, so one kind cannot be passed off as another. The HKDF sub-keys are labelled separately, decoding is strict, and secret comparisons are constant-time. PKCE is S256-only and its shape is validated. Redirect URIs are matched exactly, against both the client record and the current config. Authorize errors are never redirected before the client is verified, `iss` is on every authorization response, and frame-ancestors/XFO plus no-store are set. Header stripping is correct: the credentials are set after hop-by-hop removal, and inbound `Authorization` is dropped. Logging is careful. I found no Critical or High issues.

The weaknesses are at the edges of the stateless, open design:

- **Anyone can obtain a working access token.** The form accepts any credentials and the MCP path has no limits, so the proxy is an unauthenticated, unthrottled relay to the upstream (F-01).
- **The in-app rate limiter can be bypassed for free from IPv6.** It keys IPv6 by /64 and evicts least-recently-used keys beyond 10k. Two of the documented "accepted trade-offs" then become cheap, demonstrated attacks: a code-cache 503 lockout of all new logins, and re-opening a refresh family that was revoked after reuse (F-02).
- **Any HTTP method and almost any header pass through.** If the upstream reflects request headers, the token holder can read the plaintext Tradernet keys (F-03).

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Info | 7 |

---

## 2. Findings (ranked)

| ID | Severity | Title |
|---|---|---|
| F-01 | Medium | Anyone can mint valid access tokens, so the proxy is an unthrottled relay to the upstream |
| F-02 | Medium | The IPv6 /64 limiter key plus LRU key eviction makes the in-app limiter free to bypass, which enables code-cache DoS and revoked-family re-opening |
| F-03 | Low | Any HTTP method and nearly all headers are forwarded (TRACE, X-Original-URL, CF-Connecting-IP); upstream reflection would hand plaintext credentials to the token holder |
| F-04 | Low | No absolute lifetime and no revocation for refresh chains: a stolen refresh token outlives a disconnected connector indefinitely |
| F-05 | Low | No read deadline on OAuth request bodies, so unauthenticated slow-body requests can hold connections open |
| F-06 | Low | Transport security not enforced: `http://` accepted for `public_url`, redirect URIs and upstream; no HSTS with built-in TLS |
| F-07 | Low | The example config ships a fixed, public token key that the binary accepts |
| I-01 | Info | The 16 KiB seal cap is below what the form accepts, so long or `<>&`-heavy credentials end in `server_error` |
| I-02 | Info | Registered `grant_types` are not stored or enforced |
| I-03 | Info | GET `/oauth/authorize` is unthrottled and performs a primary-key random-nonce GCM seal per request |
| I-04 | Info | Consent phishing via open DCR: attacker-named clients can share the genuine callback |
| I-05 | Info | The reuse-detection log line includes `family` and the full `client_id`; TLS handshake errors are logged at warn without throttling |
| I-06 | Info | Doc and comment inaccuracies (key-rotation re-login, certreload mtime, "config reloaded at runtime") |
| I-07 | Info | `code_ttl` and `access_token_ttl` have no upper bound |

### F-01: Anyone can mint valid access tokens, so the proxy is an unthrottled relay (Medium)

**Evidence**
- `internal/oauth/authorize.go:329-354` (`collectCreds`) checks only presence, length and control characters. Credentials are never verified.
- `internal/oauth/register.go:72` (open DCR).
- `internal/proxy/proxy.go:103-124`: no rate, concurrency or method limit on the MCP path.
- `docs/configuration.md:135`: "the proxied MCP paths are not limited".
- `internal/proxy/proxy.go:94-101`: no `MaxConnsPerHost` and no ResponseHeaderTimeout. The latter is by design.

**Attack**
1. Register a `none` client.
2. GET authorize with your own PKCE challenge.
3. POST `cred_0=x&cred_1=y`, read the 303 Location to get the code, and exchange it.

This takes about four requests. You now hold a 1-hour access token plus a 30-day sliding refresh token. Every request you send to `/tn/mcp` is forwarded to `tradernet.com/mcp/tn` from the operator's IP. The forwarding is unlimited: any method, a 10 MiB body, your own query string and arbitrary extra headers.

Consequences:
- Upstream abuse is attributed to the operator's IP, and Tradernet's per-IP throttling or bans then hit legitimate users.
- The proxy can be used to hide the attacker's IP.
- With unbounded long-lived upstream requests, the attacker can exhaust goroutines and upstream connections.

The rate limits on `/oauth/*` do not help: one token is enough.

**Fix** (choose by deployment type)
1. **Personal or private deployments:** add an optional `upstreams[].allowed_credentials` list of SHA-256 hashes of the API key value (or of key+secret). Check it in `collectCreds` and reject at authorize time.
2. **Public deployments:** validate the credentials once at authorize time with a cheap authenticated upstream call before issuing the code. Fail closed on 401.
3. **In all cases:** add a per-token rate and concurrency limit on the proxy path (key it by `family` or `client_id`, plus per-IP). Set `Transport.MaxConnsPerHost`.

**Reproduction (private PoC):** arbitrary credentials (`garbage-key`/`garbage-secret`) produced a working token, and the request reached the upstream.

### F-02: The IPv6 /64 limiter key plus LRU key eviction makes the limiter free to bypass (Medium)

**Evidence**
- `internal/ratelimit/ratelimit.go:155-169` (`Key`): IPv6 is keyed by /64.
- `internal/ratelimit/ratelimit.go:122-143` (`makeRoom`): when the table is full (10,000 keys), the least recently used key is evicted, so every new /64 starts with a full burst.
- `internal/oauth/replay.go:95-97`: the code cache fails closed at 50,000 entries.
- `internal/oauth/replay.go:222-224, 241-247`: the revoked-family quota is 10,000, and it is dropped least-recently-used first.

**Attack** (anyone with a routed IPv6 prefix; HE Tunnelbroker hands out /48s for free)

*(a) Login lockout.* Fill the code cache with 50,000 own codes inside one `code_ttl`. Each code costs one authorize POST and one token POST, sent from a fresh /64. Keeping it full takes about 10k/min. With the default 30/min/key, about 333 /64s are enough, so a /55 suffices; the docs talk about "roughly 330 addresses". From then on every legitimate code exchange gets **503** for as long as the flood continues. Users whose refresh chain has died cannot reconnect.

*(b) Revocation bypass.* An attacker holds a stolen refresh token whose family was already revoked by reuse detection. They create 10,001 own revoked families (login, exchange, refresh, then refresh again with the spent token) from fresh /64s. The victim's revoked entry is evicted, and the stolen token is then **accepted as a new family**.

The README (`README.md:225`) and `docs/architecture.md:297` mention a /48 only for evicting active families. They do not say that the same prefix makes both the code-cache lockout and the revocation flush nearly free.

**Fix**
- Add a **global** (unkeyed) ceiling on authorize POSTs that issue codes. Keeping it below 50,000 per `code_ttl` (e.g. 3,000/min) makes the code cache impossible to fill.
- Key IPv6 hierarchically: check the /64, /56 and /48 buckets and apply the most restrictive.
- **Revocations:** keep them in a separate, compact structure that attacker-created families cannot evict. For example, a set of 8-byte family-id hashes with expiry: 1M entries is about 16 MiB. Alternatively, only let a revoked family be evicted by another revoked family that is *older*.
- **Codes:** PKCE plus the allowlisted redirect already bind each code. Consider failing open when the cache is full and logging at error, instead of returning a 503 to everyone.

**Reproduction (private PoCs)**
- Code-cache fill: 50,000 slots filled in 1.4 s with no 429; a single /64 used as a control does get 429. The victim's exchange then returns `503 server_error`.
- Revoked-family re-opening: the stolen, revoked refresh token returns `200` after the flush.

### F-03: Any method and nearly all headers are forwarded; upstream reflection would leak plaintext credentials (Low)

**Evidence**
- `internal/proxy/proxy.go:103-124`: there is no method check, so TRACE, PUT, PATCH and the rest are forwarded.
- `internal/proxy/proxy.go:244-259`: header handling is a deny-list. `CF-Connecting-IP`, `True-Client-IP`, `X-Client-IP`, `X-Original-URL`, `X-Rewrite-URL`, `X-HTTP-Method-Override` and others pass through.

**Attack.** This needs an access token, either a stolen one or the client's own (for example claude.ai or OpenAI acting as token holder). If the upstream, or any hop in front of it, reflects request headers (TRACE echo, or a debug or error page), the response contains `X-TN-API-Key` and `X-TN-API-Secret` in plaintext. A 1-hour stolen access token would then become permanent API keys. It would also break the README's "Who sees what" claim (`README.md:34-38`) that claude.ai/ChatGPT "never" see the plain keys.

Separately, spoofed client-IP headers reach the upstream. That matters if Tradernet applies IP rules to API keys and honours such a header. I could not verify this, and I did not test the live upstream.

**Fix**
- Accept only `POST`, `GET` and `DELETE`, the methods MCP Streamable HTTP uses. Answer anything else with 405 before authentication.
- Switch to an allow-list of forwarded request headers: `Accept`, `Content-Type`, `Content-Length`, `Mcp-Session-Id`, `Mcp-Protocol-Version`, `Last-Event-ID`, `User-Agent`, and, if needed, `Origin`. Alternatively, at least strip the common client-IP and URL-override headers.

**Reproduction (private PoC):** a TRACE request is relayed, and an echo upstream returns both credentials and the spoofed headers.

### F-04: No absolute lifetime and no revocation for refresh chains (Low)

**Evidence**
- `internal/oauth/token.go:264-270, 293`: every refresh extends expiry to `now + refresh_token_ttl`.
- `internal/tokens/tokens.go:32-39`: the refresh payload has no family-creation time.
- There is no revocation endpoint (I grepped for one).

**Attack.** An attacker steals a current refresh token, or the latest one after the legitimate client stops refreshing. When the user disconnects the connector in claude.ai, nothing is revoked on the proxy. With no competing redemption, reuse detection never fires, so the attacker can refresh indefinitely: every 30 days at most, with no absolute cap. The only remedies are global: rotate the token keys (which logs everyone out) or revoke the Tradernet API key upstream.

**Fix**
- Add `fi` (family issued-at) to `tokens.Refresh` and enforce a configurable `oauth.max_session_ttl`, e.g. 90 days, measured from login.
- Optionally add RFC 7009 `/oauth/revoke` that marks the family revoked in the (hardened, see F-02) revocation set.
- Document that disconnecting a connector does not revoke anything.

### F-05: No read deadline on OAuth request bodies (Low)

**Evidence**
- `internal/server/server.go:79-85`: there is no `ReadTimeout`, a deliberate choice for SSE. Only `ReadHeaderTimeout` is set.
- The OAuth handlers read bodies without a deadline: `register.go:87`, `token.go:93`, `authorize.go:220`.

**Attack.** An unauthenticated client sends request headers and then sends 1 byte per few seconds of the body. The connection and its goroutine are held indefinitely. Each one costs only a single rate-limit token, and only on POST. With built-in TLS (no nginx in front) the Go server is directly exposed. Thousands of such connections exhaust file descriptors and memory.

**Fix.** In each OAuth POST handler, call `http.NewResponseController(w).SetReadDeadline(time.Now().Add(15*time.Second))` before reading the body. Alternatively, wrap `/oauth/*` with a short per-request deadline. SSE paths are unaffected. In TLS mode, consider capping total connections with `netutil.LimitListener`.

**Reproduction (private PoC):** the connection is still open after 13 s, which is past `ReadHeaderTimeout`.

### F-06: Transport security not enforced (Low)

**Evidence**
- `internal/config/config.go:616-645` (`checkHTTPURL`) accepts `http` for `public_url`, `allowed_redirect_uris` and `upstreams[].url`. Nothing warns about it (`cmd/tn-mcp-proxy/main.go:82-126`).
- No `Strict-Transport-Security` header is set anywhere (grepped), including when built-in TLS terminates.

**Attack.** One typo, `public_url: http://...` or an http upstream, and the credential form, the tokens (which contain encrypted credentials) or the plaintext `X-TN-*` headers go over cleartext. Without HSTS, an attacker on the network path can SSL-strip the first navigation to the authorize page.

RFC 9700 §2.1 requires https redirect URIs except for loopback. The README already says to keep https (`README.md`, Security notes).

**Fix**
- Reject non-https `public_url`, redirect URIs and upstream URLs unless the host is loopback, or require an explicit `allow_insecure_http: true` and log a warning.
- When `tls.*` is enabled, add `Strict-Transport-Security: max-age=31536000` to all responses.

### F-07: The example config ships a fixed, public token key (Low)

**Evidence**
- `deploy/config.example.yaml:19` contains the key `AAECAwQF…Hh8=` (bytes 0x00..0x1f). It is marked REPLACE ME, but `internal/config/config.go:375-389` accepts it.
- The example also puts keys inline, while `README.md:110-120` tells users to install the config `0644`.

**Attack.** If a deployment is copied from the example, anyone can decrypt intercepted tokens and read the Tradernet keys. They can also derive any client's `client_secret` and forge client ids. Local users can additionally read the key from a world-readable config.

**Fix**
- Refuse known example and test keys at load: compare SHA-256 against a small deny-list, and reject the all-zero and sequential keys.
- Change the example to `token_keys_file` and keep inline keys out of it.

### I-01: The seal size cap is below what the form accepts (Info)

`internal/seal/seal.go:207-226` caps sealed tokens at 16 KiB, but the form accepts 4096 bytes per credential (`authorize.go:27`). JSON HTML-escapes `<`, `>` and `&` into 6-byte sequences. Three 4096-byte values, or one value of 3000 `<`, make code sealing fail, and the user gets `error=server_error`, logged at error.

The comment at `internal/server/server.go:38-41` says "a bearer token sealing 3 maximal values is about 17 KiB", but such a token can never be produced.

Fix: compute a total credential budget per upstream and reject over-long input with a form message. Alternatively, use `json.Encoder.SetEscapeHTML(false)`.

Reproduction (private PoC): long credentials end in `server_error`.

### I-02: Registered `grant_types` are not stored or enforced (Info)

`internal/oauth/client.go:27-32` does not store grants, and `register.go:123` only validates them. A client registered with `grant_types: ["authorization_code"]` can still use `refresh_token` (`token.go:117-121`). There is no security impact, but this is RFC 7591 metadata the server does not honour. Either store the grants as a bit in the client record or document the behaviour.

### I-03: GET authorize is unthrottled and seals with the primary key on every request (Info)

`internal/oauth/oauth.go:82`: every GET seals `authreq` with AES-GCM under the primary key using a random 96-bit nonce (`seal.go:220`). Unauthenticated clients can therefore drive seal volume toward the documented 2^32-per-key bound, and they can drive CPU.

The collision probability at realistic volumes is negligible: about 2^-33 at 2^32 seals. If you want margin, add a generous rate limit on GET, or derive a per-seal subkey (HKDF over a 16-byte random salt carried in the token), or use XAES-256-GCM.

### I-04: Consent phishing via open DCR (Info)

The client name is HTML-escaped (`templates/authorize.html:16`), stripped of control and format characters (`register.go:198-215`) and labelled "unverified". However, homoglyph names such as "Сlaude" are still possible. An attacker-registered client can use the genuine claude.ai or chatgpt.com callback.

The attacker gains anything only if the code later leaks at that callback (logs, Referer or analytics on the client side), because the attacker holds the PKCE verifier. Consider not rendering `client_name` at all and showing only the redirect host as the identity of the application.

### I-05: Log content (Info)

`internal/oauth/token.go:283` logs `family` and the full `client_id` at warn. For `none` clients the `client_id` is the only client authenticator. The docs (`docs/architecture.md:239`) say "with the client id only".

Separately, `http.Server.ErrorLog` (`server.go:84`) logs every TLS handshake error at warn without throttling, so an attacker can flood the logs in built-in TLS mode.

### I-06: Doc and comment inaccuracies (Info)

- `docs/architecture.md:467` says certreload "compares mtime and size". The code hashes the contents (`certreload.go:127-144`); `docs/configuration.md` is correct.
- `internal/oauth/token.go:193` says the config "is reloaded at runtime". SIGHUP reloads only TLS, so the re-validation only matters across restarts.
- `README.md:197-203`, key-rotation step 3: "claude.ai re-registers automatically" implies a seamless switch. But refresh tokens are bound to the old `client_id` (`token.go:252`), so after the old key is removed every user must go through the credentials form again.

### I-07: No upper bound on `code_ttl` and `access_token_ttl` (Info)

`internal/config/config.go:424-435` requires only that both be positive. OAuth 2.1 recommends that codes last at most 10 minutes. Since access tokens cannot be revoked, a long `access_token_ttl` directly extends a thief's window. Consider capping or warning: code_ttl ≤ 10m, access_token_ttl ≤ 24h.

---

## 3. Spec-compliance checklist

| Spec / requirement | Status | Evidence |
|---|---|---|
| **OAuth 2.1** | | |
| Authorization code flow only; no implicit or password grant | PASS | `token.go:117-126`, `authorize.go:161-163` |
| PKCE required for all clients | PASS | `authorize.go:164-174`, `token.go:161-163,189` |
| Exact redirect URI matching | PASS | `client.go:74-84`, `register.go:107-112` |
| Code single-use and short-lived | PASS / I-07 | `replay.go:81-100`, `token.go:207-215`; TTL unbounded in config |
| Refresh tokens for public clients rotated | PASS / F-04 | `token.go:271-293`; no absolute cap |
| No bearer token in query string | PASS | `proxy.go:129` (header only) |
| **RFC 9700 (Security BCP)** | | |
| §2.1 https redirect URIs (non-loopback) | F-06 | `config.go:616-645` |
| §2.1.1 PKCE S256, `plain` refused | PASS | `authorize.go:169-171` |
| §4.1 no open redirector at the AS | PASS | `authorize.go:139-153` (page errors until client and redirect verified) |
| §4.4 mix-up: `iss` on responses | PASS | `authorize.go:478` |
| §4.5 code injection: PKCE + client binding | PASS | `token.go:181-192` |
| §4.7 CSRF | PASS | PKCE + client state; `authorize.go:216-218` Sec-Fetch-Site |
| §4.11 / §4.12 303 after POST (no 307) | PASS | `authorize.go:483-487` |
| §4.13 refresh token protection: rotation + reuse detection | PASS / F-02 / F-04 | `replay.go:204-252`; bypassable by eviction; no absolute lifetime |
| §4.14 client impersonation via DCR | I-04 | open DCR by design |
| §4.16 clickjacking | PASS | `authorize.go:430,433-434` |
| §2.4 / §4.9 resource-owner credentials not sent to the client | PASS / F-03 | conditional on upstream reflection |
| Rate limiting / DoS of the AS | F-02 / F-05 | `ratelimit.go:155-169`, `server.go:79-85` |
| **RFC 7636 (PKCE)** | | |
| §4.1 verifier 43-128 unreserved chars | PASS | `token.go:400-412` |
| §4.2 S256 challenge shape (43 base64url) | PASS | `authorize.go:505-512` |
| §4.6 constant-time comparison | PASS | `token.go:416-420` |
| Missing verifier rejected | PASS | `token.go:161-163` |
| **RFC 8707 (resource indicators)** | | |
| Authorize: resource must identify a known resource; `invalid_target` | PASS | `authorize.go:175-186,301-315` |
| Token: resource consistent with the grant | PASS | `token.go:331-338` |
| Access token audience-restricted | PASS | `proxy.go:154-157` (upstream name) |
| **RFC 9207 (iss)** | | |
| `iss` on success and error responses | PASS | `authorize.go:478` (all redirects) |
| `iss` == metadata `issuer` | PASS | `metadata.go:79` vs `authorize.go:478` |
| `authorization_response_iss_parameter_supported` | PASS | `metadata.go:85` |
| **RFC 9728 (PRM)** | | |
| `resource` == URL the client uses | PASS | `metadata.go:96`, `config.go:212-214` |
| `authorization_servers` == issuer | PASS | `metadata.go:97` |
| WWW-Authenticate `resource_metadata` on 401 | PASS | `proxy.go:212-225` |
| Path-inserted well-known URL | PASS | `metadata.go:101` |
| **RFC 8414 (AS metadata)** | | |
| Issuer has no path / query / fragment | PASS | `config.go:592-611` |
| Required fields present | PASS | `metadata.go:78-89` |
| `code_challenge_methods_supported` | PASS | `metadata.go:87` |
| Same document at `openid-configuration` | N/A (Info) | `metadata.go:92`; not a full OIDC document (no `jwks_uri`); no security impact |
| **RFC 7591 (DCR)** | | |
| `redirect_uris` validated | PASS | `register.go:103-112` |
| Errors `invalid_redirect_uri` / `invalid_client_metadata` | PASS | `register.go:83-137` |
| `client_secret_expires_at` with secret | PASS | `register.go:161-164` |
| Registered metadata honoured | I-02 | grants not enforced |
| Open registration rate limited | PASS / F-02 | `oauth.go:85` |
| Display metadata safe (`client_name`) | PASS / I-04 | escaped + sanitized; logo_uri, client_uri and policy_uri ignored (not rendered) |
| **MCP authorization spec** | | |
| PRM + AS discovery | PASS | `metadata.go:68-108` |
| PKCE S256 + advertised methods | PASS | `metadata.go:87` |
| Resource parameter + audience validation | PASS | see RFC 8707 rows |
| No token passthrough to upstream | PASS | `proxy.go:244-246` (`Authorization` stripped) |
| HTTPS for all AS endpoints | F-06 | not enforced |
| DCR support | PASS | `register.go` |
| Origin validation (Streamable HTTP) | N/A | Bearer-only auth; no ambient credentials; Origin forwarded to the upstream |
| **Crypto / token internals** | | |
| Kind confusion (code as access, client_id as refresh, etc.) | PASS | `seal.go:178-183,266` (AAD = ver‖keyID‖kind; fixed-length prefix, so the encoding is unambiguous) |
| HKDF context separation | PASS | `seal.go:87-89,147-171` |
| Nonces from CSPRNG | PASS / I-03 | `seal.go:220` |
| Strict canonical encoding | PASS | `seal.go:242-250` |
| Key rotation (first seals, all open; MAC verified under all keys) | PASS / I-06 | `seal.go:215,256-264,312-320`; rotation docs understate the re-login |
| client_secret = MAC(client_id), constant-time | PASS | `client.go:88-90,161-166` |
| **Header handling and logging** | | |
| Inbound `Authorization` / `Cookie` / XFF stripped; credentials set after hop-by-hop removal | PASS | `proxy.go:229-260` |
| Client cannot smuggle `X-TN-*` | PASS | `proxy.go:254-256` |
| Method / header allow-list | F-03 | `proxy.go:103-124,244-253` |
| Client IP trust (right-most XFF, loopback default, /0 rejected) | PASS | `httplog.go:131-171`, `config.go:666-688` |
| No secrets, tokens or queries in logs | PASS / I-05 | `httplog.go:58-67`; `token.go:283` logs `client_id` + `family` |
| no-store on token / register / form responses | PASS | `token.go:72-74`, `register.go:57-64`, `authorize.go:428` |
| HSTS | F-06 | absent |
| TLS min version + cert hot reload | PASS | `main.go:104-108`, `certreload.go` |

---

## 4. Docs-claims check

| Claim (location) | Verdict |
|---|---|
| "No database or stored credentials; tokens are self-contained sealed blobs" (README Security notes) | Accurate |
| "Who sees what: claude.ai / ChatGPT never see plain keys, cannot decrypt" (README:34-38) | Accurate for the sealed token. Conditionally false: with header reflection upstream, the token holder sees the keys (F-03) |
| "The token is a bearer secret: whoever holds it can use it until it expires" (README) | Accurate for access tokens. For refresh tokens, "until it expires" is effectively unbounded because expiry slides (F-04) |
| "Tokens, credentials and query strings are never logged" (README:226) | Accurate. `client_id` and family id are logged at warn (I-05) |
| "Refresh tokens are single-use and rotated; presenting an already used one revokes its whole chain" (README) | Accurate, but revocation can be undone by flushing the cache via IPv6 (F-02 PoC) |
| Rate limiting cost: "about 56 sources (or one IPv6 /48)…", "roughly 330 addresses keep [the code cache] full" (README:225, architecture.md:297,319) | Understated. A /55 IPv6 prefix covers the code-cache DoS, and a free /48 covers everything (F-02) |
| "Redirect URIs are restricted to `oauth.allowed_redirect_uris`… exactly equal, no normalization" (README, architecture.md) | Accurate (`register.go:107-112`, `client.go:82-84`) |
| "Errors before client/redirect validation are never redirected (no open redirector)" (architecture.md) | Accurate (`authorize.go:139-153`) |
| "`iss` added to every redirect, success and error, GET and POST" (architecture.md) | Accurate (`authorize.go:478`) |
| CSP / XFO / no-store / form-action incl. redirect origin (architecture.md) | Accurate (`authorize.go:425-435`) |
| "A POST declared cross-site or same-site is refused" (architecture.md) | Accurate (`authorize.go:216`) |
| "Kind binding: a token sealed as one kind fails when opened as another" (architecture.md) | Accurate (`seal.go:266`) |
| "Validation comes first, so a failing request does not burn the code" (architecture.md) | Accurate (`token.go:176-215`) |
| "Credentials are applied after ReverseProxy removes hop-by-hop headers" (architecture.md) | Accurate (Go `ReverseProxy` calls `Rewrite` after `removeHopByHopHeaders`) |
| "Client IPs are never forwarded" (architecture.md:355) | Accurate for the proxy's own forwarding. Client-supplied `CF-Connecting-IP`, `True-Client-IP` and similar pass through (F-03) |
| "Reuse detection… logged at warn with the client id only" (architecture.md:239) | Inaccurate: the family id is logged too (I-05) |
| "certreload compares mtime and size" (architecture.md:467) | Inaccurate: it compares a SHA-256 of the contents (I-06) |
| "MaxHeaderBytes… a bearer token sealing 3 maximal values is about 17 KiB" (server.go:38-41) | Inaccurate: such a token cannot be sealed (16 KiB cap), so the user gets `server_error` (I-01) |
| Key rotation: "no one is logged out… claude.ai re-registers automatically" (README:197-203) | Step 2 is accurate. Step 3 is misleading: after the old key is removed, every user must re-enter credentials, because refresh tokens are bound to the old `client_id` (I-06) |
| "Run a single instance… a restart resets replay protection" (README) | Accurate and honestly disclosed |
| "Access tokens cannot be revoked before expiry" (architecture.md) | Accurate |
| "`trusted_proxies` /0 rejected; right-most untrusted XFF; X-Real-IP fallback" (configuration.md) | Accurate (`config.go:684-686`, `httplog.go:131-171`) |
| "Error messages never echo URL or key material" (configuration.md) | Accurate (`config.go:273-277,616-645`) |
| "Keep `public_url` on https" (README) | Advice only; not enforced (F-06) |
| Example config "REPLACE ME" key (config.example.yaml:19) | The key is accepted at runtime (F-07) |
| "The service runs as a dynamic unprivileged user under a restrictive systemd sandbox" (README) | Accurate (`deploy/tn-mcp-proxy.service`) |

---

## Positive observations

- One AEAD primitive for all five token kinds. The AAD binds kind and header, decoding is strict and canonical, the size cap is applied before decoding, and the error contract keeps the failure cases indistinguishable.
- PKCE handling is strict throughout: S256 only, the challenge and verifier shapes are validated, and the comparison is constant-time.
- Validation runs before the code is claimed, and the claim is atomic.
- Redirect URIs are checked against both the registration and the live config, and stale `code`/`state`/`iss` values in a configured redirect URI's query are removed.
- No open redirect. Invalid `state` is never echoed.
- The authorize page uses `html/template`, a hash-based CSP with no inline script, `frame-ancestors 'none'`, XFO, `Referrer-Policy: no-referrer` and no-store.
- Credential values are checked for control characters at the form and again at the proxy, and never echoed back for secret fields.
- Proxy header hygiene is correct: `Authorization`, cookies and forwarding headers are stripped, configured credential headers are dropped before injection, injection happens after hop-by-hop removal, `Set-Cookie` is removed, the exact path is enforced, and `url.Error` is unwrapped so the URL is not logged.
- The client-IP resolver is correct: right-most untrusted entry, an invalid entry stops the walk, and a /0 trust range is rejected.
- All caches and the limiter are bounded, with amortized O(1) eviction.
- Fuzz targets cover the parsers, and the systemd unit is well hardened.

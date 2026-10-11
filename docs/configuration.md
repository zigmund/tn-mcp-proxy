# Configuration

tn-mcp-proxy reads a single YAML file (see `deploy/config.example.yaml`).
Unknown keys, multiple YAML documents and invalid values are startup errors;
all validation problems are reported together with field paths.
Error messages never echo URL or key material.

## Fields

| Field | Default | Notes |
|---|---|---|
| `listen` | `127.0.0.1:8787` | `host:port`, port 0..65535 |
| `public_url` | required | Absolute https origin (http only for loopback hosts, or with `allow_insecure_http`): no path (the proxy owns the host-root `/.well-known/*` and `/oauth/*` paths), userinfo, query or fragment. Normalized: lowercase scheme/host, default port (80/443) dropped, trailing slash stripped |
| `log.level` | `info` | `debug`, `info`, `warn`, `error` (case-insensitive; other values are rejected; `debug` enables the access log) |
| `log.format` | `json` | `json`, `text` (case-insensitive; other values are rejected) |
| `allow_insecure_http` | `false` | Top-level bool. Accept plain `http://` for non-loopback hosts in `public_url`, `oauth.allowed_redirect_uris` and `upstreams[].url`. Logs one startup warning. See [Transport security](#transport-security) |
| `secrets.token_keys` | | Base64 (standard) of 32 random bytes each (`openssl rand -base64 32`); first key encrypts, others only decrypt. Known-weak keys are rejected, see below |
| `secrets.token_keys_file` | | File with one base64 key per line; `#` comments and blank lines ignored |
| `oauth.access_token_ttl` | `1h` | Positive duration, at most `24h` (access tokens cannot be revoked, so this is a thief's window) |
| `oauth.refresh_token_ttl` | `720h` | Positive duration; refresh tokens are single-use (reuse revokes the login's token family) and every refresh restarts this lifetime (sliding expiry), but never beyond `oauth.max_session_ttl` |
| `oauth.max_session_ttl` | `2160h` (90 days) | Positive duration; absolute lifetime of a login, counted from the code exchange and never extended by refreshing. Once it has passed, the refresh grant fails with `invalid_grant` and the user must reconnect; refresh and access token expiry (and `expires_in`) are capped at the session end. Refresh tokens issued before this setting existed carry no start time: their first refresh after an upgrade starts a fresh window, so existing logins get a full `max_session_ttl` from then on. There is no upper bound |
| `oauth.code_ttl` | `5m` | Positive duration, at most `10m` (OAuth 2.1); lifetime of an authorization code from submission of the credentials form. Codes are single-use |
| `oauth.allowed_redirect_uris` | claude.ai and claude.com `/api/mcp/auth_callback`, and ChatGPT `https://chatgpt.com/connector_platform_oauth_redirect` | Absolute https URLs (http only for loopback or with `allow_insecure_http`), no duplicates |
| `oauth.rate_limit.disabled` | `false` | Turns the in-app rate limiting of the OAuth endpoints off: the per-IP limits and the global authorize ceiling. See [Rate limiting](#rate-limiting) |
| `oauth.rate_limit.register` | `per_minute: 60`, `burst: 30` | Limit for `POST /oauth/register` |
| `oauth.rate_limit.token` | `per_minute: 300`, `burst: 100` | Limit for `POST /oauth/token` |
| `oauth.rate_limit.authorize` | `per_minute: 30`, `burst: 10` | Limit for `POST /oauth/authorize` (the credentials form submission) |
| `oauth.rate_limit.authorize_form` | `per_minute: 300`, `burst: 100` | Limit for `GET /oauth/authorize` (rendering the form; each one seals a request, hence a generous but finite limit) |
| `oauth.rate_limit.authorize_global` | derived from `code_ttl` (`per_minute: 2500`, `burst: 2500` at `5m`) | Unkeyed ceiling on the `POST /oauth/authorize` submissions that are about to get a code. `burst` defaults to `per_minute`; setting `burst` needs `per_minute` too. See [Rate limiting](#rate-limiting) |
| `oauth.page.contact` | | Optional operator contact on the authorize page: `mailto:` address or `https://` URL, at most 256 bytes, no whitespace, control or Unicode format characters. Shown as a link (the text drops `mailto:`) under "Notice from the operator" |
| `oauth.page.notice` | | Optional notice on the authorize page: a map of lowercase language code (2 or 3 letters) to plain text, each at most 4 KiB of UTF-8 without control characters other than newline and tab, at most 32 languages. Paragraphs are separated by blank lines. Text is HTML-escaped, never interpreted. When `notice` is set it must contain an `en` entry (config error otherwise); the page shows the entry for its language, else `en`. Unicode format characters (bidi controls, zero-width) are rejected |
| `oauth.page.terms` | | Optional terms of use the user must accept on the authorize page. Keys `version`, `text`, `url`; see [Languages and terms of use](#languages-and-terms-of-use) |
| `audit.enabled` | `false` | Opt-in audit log tying client IPs to audited credential values. Needs `log.level` `debug` or `info`. See [Audit log](#audit-log) |
| `audit.retention` | | Required when `audit.enabled`. Short free text, at most 64 characters, printable, no control characters (for example `12 months`). It states your retention of the audit records. The proxy does not enforce it: your log rotation does |
| `audit.retention_i18n` | | Optional map of language code to the retention text for that language (same rules as `retention`, per entry). Needs an `en` entry that equals `retention`; `retention` may then be omitted and is taken from it. See [Languages and terms of use](#languages-and-terms-of-use) |
| `limits` | see [Proxy limits](#proxy-limits) | Rate, concurrency and body limits of the proxied MCP paths |
| `trusted_proxies` | `["127.0.0.0/8", "::1/128"]` | Top-level list of CIDRs (or bare IPs, taken as `/32` or `/128`) of reverse proxies whose `X-Forwarded-For` / `X-Real-IP` are honoured. Empty or unset means loopback only. See [Client IP](#client-ip) |
| `upstreams[]` | at least one | See below |
| `tls.cert_file`, `tls.key_file` | empty | PEM certificate (with chain) and private key. Set both or neither; both set enables built-in HTTPS. See [Built-in TLS](#built-in-tls) |
| `tls.reload_interval` | `1m` | How often the files are checked for changes. Positive duration; `0` or unset means the default. SIGHUP reloads immediately regardless |

For all durations, `0` or unset means the default; negative values are rejected.
The same holds for `per_minute` and `burst` of every `oauth.rate_limit` entry (a
zero value is replaced by its default; to switch limiting off use
`oauth.rate_limit.disabled`). `limits.*` differs: `-1` disables an individual
limit (see [Proxy limits](#proxy-limits)).

Relative `secrets.token_keys_file`, `tls.cert_file` and `tls.key_file` paths are
resolved against the config file's directory.

Exactly one of `secrets.token_keys` and `secrets.token_keys_file` must be set.
Keys must be unique. Known-insecure keys are rejected at startup: the public
key that older example configs shipped (bytes `0x00`..`0x1f`), the all-zero
key, and any key whose bytes form a constant-step sequence (all the same byte,
`0,1,2,...`, `31,30,...`). The error names the key's position, never its
value. Generate real keys with `openssl rand -base64 32`. After loading, the
decoded keys are available only as
`Config.Secrets.Keys`; the encoded strings are dropped and secrets are redacted
in logs, `fmt`, JSON and YAML output.

### Upstream

> [!CAUTION]
> Credentials without `allowed_values` make a public deployment an open relay:
> anyone with valid Tradernet credentials, stolen or their own, can obtain a
> token and act through your server. Every upstream request leaves from this
> server's IP and the upstream tools can trade on the account (place and cancel
> orders) and read the portfolio and balances, so in a broker, exchange or police
> inquiry the activity points to you, the operator. Set `allowed_values` on the non-secret credential
> (for example `X-TN-API-Key`) together with `validate` and `forbidden_arguments`,
> or keep the server private. Startup logs a
> warning for each upstream without an allow-list. See
> [Restricting access](#restricting-access).

| Field | Default | Rules |
|---|---|---|
| `name` | required | Unique, `[a-z0-9-]+` |
| `title` | `name` | Shown on the authorize form. Clients select the upstream with the `resource` parameter (`public_url` + `path`), which may be omitted only with exactly one upstream |
| `path` | required | Matches `^(/[A-Za-z0-9._~-]+)+$`, no `.`/`..` segments, no trailing slash. Must not equal or overlap `/oauth`, `/.well-known`, `/healthz`; no upstream path may be a segment-wise prefix of another |
| `url` | required | Absolute URL without userinfo or fragment; `https` unless the host is loopback or `allow_insecure_http` is set (see [Transport security](#transport-security)). Requests go to it exactly as written; the client's query string is forwarded only when this URL has none of its own |
| `credentials[]` | at least one non-optional | Headers the user supplies |
| `validate` | absent (no validation) | Optional. Verify the entered credentials against the upstream before a code is issued. Required when any credential has `allowed_values`. See [Credential validation](#credential-validation) |
| `forbidden_arguments` | absent | Optional list of tool argument names (case-insensitive) rejected in `tools/call` requests, for example `[api_key, api_secret]`. See [Forbidden tool arguments](#forbidden-tool-arguments) |

Credential fields: `header` (required, valid HTTP header name, unique
case-insensitively per upstream), `label` (default: header), `secret` (mask
input), `optional`, `allowed_values` (optional list of accepted values, see
[Restricting access](#restricting-access)), `audit` (write the value to the
audit log, see [Audit log](#audit-log); an error together with `secret: true`), `labels` (optional map of language code to the label for that language, at most 128 characters, printable; needs an `en` entry that equals `label`, and `label` may then be omitted; see [Languages and terms of use](#languages-and-terms-of-use)). Each credential becomes one input on the authorize form; values are trimmed, valid UTF-8, at most 4096 bytes and free of control characters. All values together must also fit the 16 KiB token size budget, else the form answers "The credentials together are too long.".

`validate` fields: `tool` (required, MCP tool called with the entered
credentials, matches `^[A-Za-z0-9_./-]{1,128}$`, must be read-only),
`arguments` (optional JSON object passed to the tool, default `{}`; values are
never echoed in error messages), `timeout` (default `10s`; `0` or unset means
the default, negative values and values above `60s` are rejected),
`recheck_on_tool_error` (bool, default `false`; also re-run the check when a
proxied tool call fails, see [Re-check on tool errors](#re-check-on-tool-errors)).

Forbidden credential headers: `Authorization`, `Proxy-Authorization`, `Cookie`,
`Host`, `Content-Length`, `Content-Type`, `Transfer-Encoding`, `Connection`,
`Keep-Alive`, `Upgrade`, `TE`, `Trailer`, `Accept`, `Mcp-Session-Id`,
`Mcp-Protocol-Version`, `Forwarded`, `X-Real-IP` and `X-Forwarded-*`.

## Restricting access

By default anyone whose credentials work upstream can obtain a token. The form
checks the credentials against the upstream (see below) but not whose they are,
and the upstream then sees requests coming from this server's IP. To restrict
who can use the server, for example when it is public but only meant for you,
list the accepted values on a non-secret credential, with `validate` and
`forbidden_arguments`:

```yaml
credentials:
  - { header: X-TN-API-Key, label: API key, allowed_values: ["REPLACE_WITH_YOUR_API_KEY"] }
  - { header: X-TN-API-Secret, label: API secret, secret: true }
  - { header: X-TN-SID, label: SID, optional: true }
validate: { tool: get_auth_info }
forbidden_arguments: [api_key, api_secret]
```

Rules:

- `allowed_values` is allowed only on credentials with `secret: false` (the
  default): the values are stored in the config file, which must not hold
  secrets. Use the identifying half of a key pair (the API key, not the secret).
- Each value is non-empty after trimming, has no control characters (CR/LF
  included), is at most 4096 bytes and is unique after trimming. Errors name
  entries by index and never print a value.
- Empty or unset means no restriction. Several credentials may have lists; all
  of them must match.
- Matching is exact (case-sensitive) after trimming surrounding whitespace, the
  same normalization the authorize form applies, and constant-time.
- An upstream with `allowed_values` must also set `validate`; otherwise
  startup fails with `allowed_values requires validate`.

The allow-list gates token issuance. It is effective only together with
`validate`: without it, the API key alone (which is not secret) would yield a
token paired with any secret. It does not control request content. A token
holder can still put anything into a tool call, including credentials as tool
arguments, which some upstreams accept as a documented fallback. That is what
`forbidden_arguments` is for (below).

Enforcement: `POST /oauth/authorize` refuses a value outside the list with
status `400` and an explicit message ("These credentials are not allowed on this
server: its operator has restricted access to specific keys."), before any
upstream call and before anything is sealed; the `authorization_code` and
`refresh_token` grants answer `invalid_grant`; every proxied request answers
`401 invalid_token`. So removing a value from the list and restarting cuts off
tokens already issued for it. The comparison is made on SHA-256 digests with
`crypto/subtle`, against every entry (it does not stop at the first match). The
form therefore reveals that an allow-list is in use, on purpose: an operator who
enters a key that is not on it must not mistake the refusal for an upstream
rejection (which keeps the "rejected these credentials" message). Timing differs
as well: a refusal by the list returns without an upstream round trip. The
comparison itself is constant-time and the secret is still required.

Without any list on an upstream, startup logs one `warn` for that upstream
(`upstream has no allowed_values: ...`). An upstream with a list but without
`forbidden_arguments` gets its own `warn`. Both name the upstream and never a
value.

### Forbidden tool arguments

```yaml
forbidden_arguments: [api_key, api_secret]   # upstream-level, next to credentials
```

When set, POST bodies on the MCP path are inspected after the proxy limits have
admitted the request. A JSON-RPC `tools/call` whose `params.arguments` object
contains any listed name (case-insensitive; presence counts even if the value is
null or empty) is answered with HTTP 400 and a JSON-RPC error (`code` -32602,
`argument not allowed: <name>` with the configured name; `id` is the request id
when it is a string, number or null, else null) and never reaches the upstream.
A batch is rejected as a whole if any element offends (`id` null). Only the top
level of `arguments` is checked, and only POST bodies are inspected.

The inspection fails closed, because the upstream's JSON parser may differ from
the proxy's. Unless a row says otherwise the answer is HTTP 400 with a JSON-RPC
error whose `id` is null:

| Body | Answer |
|---|---|
| Not valid UTF-8 JSON (only space, tab, CR and LF may surround it; a byte order mark or UTF-16 is refused), or not a single object or a non-empty array of objects | `-32700 Parse error` |
| Duplicate `method` or `params` key in any message, duplicate `arguments` key in a `tools/call`, or a `method` that is not a string | `-32600 Invalid Request` |
| A message-level key that equals `method` or `params` only under case folding (`METHOD`, `Params`, `paramſ`), or a key inside the `params` of a `tools/call` that equals `arguments` or `name` only under case folding (`Arguments`, `Name`), in single messages and batch elements alike | `-32600 Invalid Request` |
| Forbidden argument name | `-32602`, `id` as above |
| Larger than `limits.max_request_body` | `413` |

The structural keys `method`, `params` and `arguments` are matched exactly
(case-sensitively), as strict parsers do; argument names are matched
case-insensitively. Methods other than `tools/call` and messages without a
`method` (responses) pass once the body is well-formed. The body is read once
into memory, within `limits.max_request_body`, and forwarded byte for byte with
an exact `Content-Length`; every in-flight POST holds its body in memory
meanwhile (see the sizing note under [Proxy limits](#proxy-limits)). Refusals
are logged at `info` with the upstream and, for a forbidden argument, its
configured name, never values. Legitimate clients that authenticate with
headers are unaffected. Names: at most 32, each non-empty, at most 128 bytes,
valid UTF-8, no leading or trailing whitespace, no control characters, unique
case-insensitively.

[Proxy limits](#proxy-limits) bound the volume of abuse but do not replace an
allow-list.

## Credential validation

Without `validate` the authorize form accepts any values, so anyone who can
reach the server could obtain a token. With a `validate` block, `POST
/oauth/authorize` checks the entered credentials against the upstream first and
issues a code only if the upstream accepts them:

```yaml
upstreams:
  - name: tn
    ...
    validate:
      tool: get_auth_info   # read-only MCP tool called with the entered credentials
      # arguments: {}       # optional tool arguments (JSON object)
      # timeout: 10s        # whole check, default 10s, at most 60s
```

The check sends these requests to the upstream `url` exactly as configured
(path and query intact), each carrying the entered credential headers and a
`User-Agent: tn-mcp-proxy/<version>` (the binary's version, the same
one `-version` prints; `dev` for an unversioned build); the POSTs also carry
`Content-Type: application/json` and
`Accept: application/json, text/event-stream`:

1. `initialize` (protocol `2025-06-18`). A `2xx` with a JSON-RPC result is
   required. The `Mcp-Session-Id` response header, if any, and the negotiated
   protocol version are sent as `Mcp-Session-Id` / `Mcp-Protocol-Version` on
   every later request.
2. `notifications/initialized`. Any `2xx` is accepted.
3. `tools/call` with `tool` and `arguments`.
4. If the upstream issued a session id: a best-effort `DELETE` (2 s limit,
   errors ignored).

Responses may be `application/json` or `text/event-stream`; for SSE, events
that are not the response with the request's id (notifications, server
requests) are skipped. A body larger than 1 MiB is an error.

Outcome:

| Upstream behaviour | Result |
|---|---|
| `tools/call` returns a result without `isError` (or `isError: false`) | accepted, code issued |
| `tools/call` returns `isError: true`, or any step answers HTTP `401`/`403` | rejected: the form is shown again (`400`) with "&lt;Title&gt; rejected these credentials. Check them and try again." |
| JSON-RPC `error` object (e.g. unknown tool), other non-2xx status, a redirect, transport error, timeout, malformed or oversized body, no response with the matching id | unavailable: the form is shown again (`503`) with "Could not verify the credentials with &lt;Title&gt; right now. Try again later." |

The check fails closed: whenever there is no clear acceptance, no code is
issued. In both cases non-secret values stay in the form and secret values are
never re-rendered.

- **Timeout.** `validate.timeout` bounds the whole check, handshake included,
  and the incoming request's context too.
- **Concurrency cap.** At most 16 checks run at once across all upstreams; a
  check that cannot start within its timeout is "unavailable". Waiting for a
  slot counts toward `validate.timeout`.
- **Environment proxies are ignored.** Upstream traffic (proxied requests and
  credential checks) never uses `HTTP_PROXY`, `HTTPS_PROXY` or `ALL_PROXY`: the
  credential headers must not pass through a third party. Reach the upstream
  directly or through network-level routing.
- **Redirects are not followed**, so the credential headers can never be
  forwarded to another host; a `3xx` answer is "unavailable".
- **Read-only tool.** The tool runs on every form submission with whatever
  credentials were typed, so it must not change anything upstream.
- **Cost.** One upstream round trip (three requests) per submission. The form
  becomes a credential-validity oracle for anyone who can reach it; the per-IP
  `oauth.rate_limit.authorize` limit bounds the guessing rate.
- **Logs.** A rejection is logged at `info` ("credentials rejected by
  upstream") and an unavailable check at `warn`, with the upstream name, the
  step and a short reason category (plus the transport error, which may name
  the upstream host or IP). Credentials, the URL path and query, response
  bodies and upstream error text are never logged. The `503` carries
  `Retry-After: 30`.

Tradernet example: `get_auth_info` is read-only and answers a bad API key pair
with a tool error (`isError: true`) over HTTP `200`, which is why `isError` is
treated as a rejection (Tradernet never answers `401` for bad keys). It
verifies only the API key and secret: the optional `X-TN-SID` header is not
checked by this tool, so a wrong SID is still accepted at connect time.

## Re-check on tool errors

An upstream that answers `401` for bad credentials needs no setup: the proxy
rewrites the challenge so the client re-runs authorization. Tradernet does not:
for a revoked or wrong key it answers `tools/call` with HTTP `200` and a tool
error (`isError: true`), so the connector stays "connected" while every call
fails. But a tool error alone proves nothing: a bad ticker or a closed market
produces one too. `validate.recheck_on_tool_error` therefore uses a tool error
only as a trigger and lets the [credential check](#credential-validation)
decide:

```yaml
upstreams:
  - name: tn
    ...
    validate:
      tool: get_auth_info
      recheck_on_tool_error: true   # default false
```

The field lives inside `validate`, so it needs a `validate` block (and its
`tool`, `arguments` and `timeout`). The proxy does not read or match the tool
error text.

- **Off by default.** Without the flag nothing is inspected and compression is
  untouched.
- **Trigger.** A `POST` response with status `200`, media type
  `application/json` and a body of at most 64 KiB in which any JSON-RPC
  response (single object or batch) has `result.isError: true`. Larger bodies,
  SSE, `GET`, malformed JSON and everything else are forwarded unchanged and
  never cause a check.
- **Decision.** The proxy runs the same MCP session as the authorize form
  (`initialize`, `notifications/initialized`, `tools/call` of `validate.tool`,
  `DELETE`) with the token's credentials, bounded by `validate.timeout` and the
  client's request. If the upstream rejects the credentials, the client gets
  `401` with `WWW-Authenticate: Bearer error="invalid_token",
  error_description="upstream rejected credentials", resource_metadata="..."`
  and the short `unauthorized` body (the upstream body is dropped), and one
  `warn` line is logged (no error text, headers or credentials). If the check
  accepts the credentials, fails, times out, is skipped or the client went
  away, the original response is forwarded unchanged.
- **Latency.** Only responses that carry a tool error wait for the check: one
  MCP session, roughly 0.4 to 1 s with Tradernet, and up to `validate.timeout`
  (default 10 s) if the upstream hangs. Successful responses are
  unaffected beyond reading up to 64 KiB of the body before forwarding it (a
  slow `application/json` response is held until it ends or passes the cap).
- **Cost control.** All state is in memory and bounded. Verdicts are cached
  for 60 s (accepted, rejected and "no verdict") under a keyed hash of
  the upstream name and credentials, so no plaintext credentials are kept; the
  cache holds at most 4096 entries and evicts the oldest. Concurrent checks for
  the same credentials share one session. At most 8 checks run at once across
  all upstreams; when saturated the check is skipped and the response passes
  through (saturation is not cached). A burst of tool errors from one token costs
  at most one session per minute, also during an upstream outage; a revocation
  can be noticed up to a minute after the upstream recovers. The `refresh_token`
  grant consults the same cache (one checker, shared by all upstreams and by the
  token endpoint) and, while credentials are cached as rejected, answers
  `invalid_grant` (no upstream call), so clients re-run authorization
  instead of refreshing into another 401. The cache is only ever filled for
  upstreams that set `recheck_on_tool_error`, so the refusal applies to those. The refusal is best-effort and
  bounded by the verdict TTL (60 s): once the verdict expires a refresh succeeds
  again, until the next tool error re-triggers the check.
- **Compression.** For these `POST`s the outbound `Accept-Encoding` is narrowed
  to `gzip` (when the client accepted it) or `identity`, because the proxy
  cannot decode brotli or zstd. A gzip body is decoded only to inspect it; the
  original bytes are forwarded when the response is not replaced. `GET`
  requests keep their `Accept-Encoding`.
- **Residual risk.** If the upstream reports a transient failure of the check
  call itself as a tool error (`isError: true`) rather than as an HTTP or
  JSON-RPC error, the check reads it as a rejection and the user is asked to
  log in again once; connection errors, timeouts, 5xx and JSON-RPC errors never
  have that effect. Verdicts can also be up to 60 s old: a key revoked just
  after an accepted check is noticed up to a minute late.

## Keys

Generate a key:

```sh
openssl rand -base64 32
```

Rotation: prepend a new key to `token_keys` (or the keys file) so it becomes the
encrypting key, keep the old key for decryption, and drop the old key once
`oauth.refresh_token_ttl` has passed, when no token sealed with it remains valid.
That is an upper bound: chains also end at `oauth.max_session_ttl` from the
original login, so many end sooner (whichever limit comes first). Dropping a key
also invalidates the registered client ids sealed with it, so every user has to
reconnect; the step-by-step procedure is in the
[README](../README.md#key-rotation).

Upgrade tradeoff: a legacy refresh token (issued before `oauth.max_session_ttl`
existed), including a stolen one, gets a full fresh `max_session_ttl` window
from its first refresh after the upgrade.

Disconnecting a connector in claude.ai or ChatGPT does not revoke anything on
the proxy (there is no revocation endpoint): its refresh chain stays valid until
the `oauth.refresh_token_ttl` idle expiry or `oauth.max_session_ttl`, whichever
comes first. Removing the old token key is the way to cut every login off at once.

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
calling the handler. `/healthz` requests are not access-logged, so probes do not
flood the log.

Never recorded: the query string (OAuth codes and state travel there; only the
URL path is logged), request or response headers (`Authorization`, `Cookie`,
...), request or response bodies, and tokens.

`remote` holds the client IP only, without a port, resolved as described in
[Client IP](#client-ip); the rate limiter uses the same value.

Events above `debug` that an operator may want to alert on (message text is
the start of the record's `msg`; fields in parentheses):

| Level | Event | Meaning |
|---|---|---|
| `info` | `starting` (`version`, `listen`, `public_url`, `upstreams` as `name=path`, `tls`), `stopped`, `shutting down` | Lifecycle |
| `warn` | `allow_insecure_http is set: ...` | Plain http accepted for non-loopback URLs |
| `warn` | `upstream has no allowed_values: ...` / `upstream has allowed_values but no forbidden_arguments: ...` (`upstream`) | Open-relay warnings, see [Restricting access](#restricting-access) |
| `info` | `credentials rejected by upstream`, `authorize refused: credentials not in allowed_values`, `token credentials not in allowed_values` (`upstream`; `step`, `reason` for the first) | Refused logins and tokens |
| `warn` | `credential check unavailable` (`upstream`, `step`, `reason`, `err`) | Authorize-time check without a verdict (fail closed) |
| `warn` | `credential recheck unavailable`, `upstream rejected credentials`, `upstream rejected credentials (tool error, confirmed by re-check)` | Proxy-side re-check and upstream 401 |
| `info` | `tool call with forbidden argument rejected` (`argument`), `request body refused: not inspectable` (`reason`) | `forbidden_arguments` refusals |
| `warn` | `refresh token reuse detected; family revoked` (`upstream`, `client_id`, `family`: 8 hex characters of a SHA-256) | Refresh token replay |
| `info` | `audit` (`event` is `authorize`, `token` or `request`) | Audit records, only with `audit.enabled`, see [Audit log](#audit-log). Some refusal events above also carry `client_ip` and `creds` then: the list is in [Audit log](#audit-log) |
| `warn` | `global authorize ceiling reached; delaying new logins`, `proxy rate limit refused requests`, `proxy concurrency limit refused requests`, `refresh family cache full, ...` (counts, at most once a minute) | Limits hit |
| `warn` | `oauth.rate_limit.authorize_global allows more live codes than half the code cache; ...` | Oversized configured ceiling, at startup |
| `error` | `single-use cache full; rejecting requests`, `access token payload mismatch`, `... payload mismatch`, `sealing ...` | Fail-closed paths and server faults |
| `info` | `shutdown signal received; send it again to force exit` | Graceful shutdown started |
| `warn` | `graceful shutdown timed out, closing connections` (`error`) | In-flight requests outlived the 15 s shutdown |
| `error` | `reload failed` (`hook`, `error`) | A SIGHUP reload hook failed |
| `warn` | `token lacks required credential` (`header`, `upstream`) | Valid token missing a required credential header |
| `warn` | `credential check failed` (`upstream`) | Authorize-time check failed with an unclassified error |
| `info`/`warn` | `tls certificate loaded`, `tls certificate expires soon`, `tls certificate reload failed, ...`, `reloaded`, `reload requested, nothing to reload` | Built-in TLS and SIGHUP |

## Languages and terms of use

The authorize and error pages are built in English (`en`, the default and the
fallback), Russian (`ru`) and Kazakh (`kk`). The switcher at the top of the
authorize page lists them in that order. The language of a request is, in this
order:

1. a valid `lang` parameter (`en`, `ru` or `kk`; the POST form carries it as a
   hidden field, so a re-rendered form keeps its language);
2. the best match of `Accept-Language`: q-values are honoured, a region is
   ignored (`ru-RU` is `ru`, `kk-KZ` is `kk`), `q=0` excludes a language;
3. `en`.

Unknown values are ignored. The language only changes what is displayed; it
never takes part in an authorization decision. Error pages are localized the
same way (a POST that fails before its body is read, such as a rate-limited
one, uses the query and `Accept-Language` only). The switcher links are built on
the server from the validated authorize request (`/oauth/authorize?...&lang=xx`,
never from the raw query), so they also work after a failed submit. The error
page has no switcher, because its link could not be rebuilt without echoing the
raw query.

> [!NOTE]
> The Kazakh texts (the page and the sample agreement) are machine-written and
> need review by a native speaker before you rely on them. The sample
> agreements are samples, not legal advice.

**Operator text per language.** Wherever you set a map of language code to
text, `en` is required, and the page uses the entry for its language, else
`en`. A text shown in another language than the page is wrapped in a `lang`
attribute.

- `oauth.page.notice`: map of language to text (see the fields table).
- `upstreams[].credentials[].labels`: map of language to label, next to `label`
  (the English and default label). `en` must equal `label`, or `label` is
  omitted and taken from `labels.en`.
- `audit.retention_i18n`: map of language to retention text, next to the plain
  string `audit.retention`, which stays valid on its own. `en` must equal
  `retention`, or `retention` is omitted and taken from it.

```yaml
audit:
  enabled: true
  retention: "12 months"
  retention_i18n: { en: "12 months", ru: "12 месяцев", kk: "12 ай" }
upstreams:
  - credentials:
      - { header: X-TN-API-Key, label: API key, labels: { en: API key, ru: Ключ API }, audit: true }
```

**Terms of use.** Optional. When `oauth.page.terms` is set, the form shows a
collapsible "Terms of use (version X)" block (the text, and a "Full text" link
when `url` is set) and a required checkbox before the Authorize button:

```yaml
oauth:
  page:
    terms:
      version: "2026-10-10"            # required, at most 32 printable characters
      text:                            # language -> file; en required
        en: /etc/tn-mcp-proxy/terms.en.txt
        ru: /etc/tn-mcp-proxy/terms.ru.txt
        kk: /etc/tn-mcp-proxy/terms.kk.txt
      url:                             # optional; language -> https URL of the full text; en required if set
        en: https://example.org/terms
```

The files are read when the config is loaded (a relative path is resolved
against the config file's directory), so a change needs a restart. Each is plain text of at most 32 KiB: valid UTF-8 without
control or format characters other than newline and tab; CRLF is normalized;
paragraphs are separated by blank lines. The text is HTML-escaped, never
interpreted. Errors name the field and never echo the content. When the
language has no text or URL, the `en` one is shown.

A submit without `accept_terms=on` is refused: the form is re-rendered
(`400`) with a localized error banner and the checkbox marked invalid, keeping
the non-secret values. The check runs before anything else costs resources (see
[Authorization](architecture.md#authorization)), so a missing checkbox causes no
upstream call and does not spend the global authorize ceiling. The terms
version is sealed into the rendered form: a form shown under a different
version (or before terms were configured) is refused the same way even with
the box ticked, and re-rendered with the current terms. The audit `authorize`
record carries `terms_version`, `terms_lang` and `lang`. Raising the `version`
does not invalidate existing tokens: it applies to the next authorization.

Sample agreements are in `deploy/terms.example.en.txt`, `.ru.txt` and `.kk.txt`
and ship in the release archive. They say the service is free and provided "as
is", that use is at the user's risk including trading losses, that the operator
is not affiliated with the broker, what is logged and for how long (fill the
`[RETENTION]` and `[CONTACT]` placeholders; they assume the audit log is on, so
edit item 4 otherwise), how to stop (revoke or rotate the API key, or ask the
operator), and that the operator may refuse or revoke access. They are
**samples, not legal advice**: have them reviewed for your jurisdiction. The
Kazakh sample is machine-written and needs native review.

## Audit log

When a server is open to anyone's Tradernet keys, a broker or the police may ask
who used account X through your IP, and when. The debug access log cannot
answer: it has no credential. The audit log can. It is off by default:

```yaml
audit:
  enabled: true
  retention: "12 months"     # required; your stated retention, not enforced by the proxy
upstreams:
  - credentials:
      - { header: X-TN-API-Key, label: API key, audit: true }      # value is logged
      - { header: X-TN-API-Secret, label: API secret, secret: true }
```

While `audit.enabled` is true the authorize page always shows a "What this
server logs" panel before the Authorize button: the time and client IP of each
request, "Your <label>" for each audited credential, that tools called are
logged, "Logs are kept for <retention>", and "Never logged or stored:" with the
labels of every other credential (secret ones and, for example, an optional
SID). It cannot be turned off separately, so a user always sees what is
recorded. The hint above the button then says that, apart from what the panel
lists, the server does not log or store any credential values.

Records are written at `info` level with `msg` `audit` and an `event` field, so
they are kept at the default `log.level` (`audit.enabled` is rejected with
`warn` or `error`) and do not depend on the debug access log. Every record has
`client_ip` (see [Client IP](#client-ip)) and `upstream`. Audited values are in
the `creds` group, keyed by the canonical header name (`X-TN-API-Key` is logged
as `X-Tn-Api-Key`).

| `event` | Written when | Other fields |
|---|---|---|
| `authorize` | the credentials form is accepted and a code issued | `client_id`, `redirect_host`, `lang` (the page language), `terms_version` and `terms_lang` (when `oauth.page.terms` is set: the version the user accepted and the language its text was shown in, which can be the `en` fallback) |
| `token` | a token pair is issued | `grant_type` (`authorization_code` or `refresh_token`), `client_id`, `family` |
| `request` | a proxied MCP request ends | `method` (HTTP), `status`, `rpc_method`, `tool`; for a batch `rpc_batch` and `rpc` (`0`, `1`, ... each with `method` and `tool`) |

`client_id` and `family` are 8 hex characters of a SHA-256, enough to correlate
records (the same login keeps one `family` through its refreshes), not to
replay anything. `request` is written once, when the handler returns, so a
long-lived SSE stream is logged when it closes, with the final status (`0`: the
client left before any response). `rpc_method` and `tool` are present only when
`forbidden_arguments` is set, because that inspection already parses the body;
the audit never parses it a second time. For a batch, `rpc_batch` is the number
of messages and `rpc` has one entry per message, at most 8, as `rpc.0.method`,
`rpc.0.tool`, `rpc.1.method`, ... (`tool` is empty when the message is not a
tool call). Names are cut at 128 bytes, and control and format characters
(bidi overrides included) are replaced with U+FFFD.

```json
{"time":"2026-10-10T12:00:00Z","level":"INFO","msg":"audit","event":"authorize","client_ip":"203.0.113.7","upstream":"tn","client_id":"9f2c41ab","redirect_host":"claude.ai","creds":{"X-Tn-Api-Key":"AAAA1111"}}
{"time":"2026-10-10T12:00:01Z","level":"INFO","msg":"audit","event":"token","grant_type":"authorization_code","client_ip":"203.0.113.7","upstream":"tn","client_id":"9f2c41ab","family":"5db3f401","creds":{"X-Tn-Api-Key":"AAAA1111"}}
{"time":"2026-10-10T12:00:09Z","level":"INFO","msg":"audit","event":"request","client_ip":"203.0.113.7","upstream":"tn","method":"POST","status":200,"creds":{"X-Tn-Api-Key":"AAAA1111"},"rpc_method":"tools/call","tool":"portfolio_get"}
```

The existing refusal logs (rejected credentials, `allowed_values`, forbidden
arguments, a body that cannot be inspected, a token without a required or with
an invalid credential, an upstream 401 including the confirmed tool-error
re-check, refresh token reuse) gain `client_ip` and `creds` while audit is on.

Never written: secret credential values, a credential with neither `secret` nor
`audit` (the optional SID, for example), tokens, codes, request or response
bodies, argument values and query strings. Audited values are typed by users,
so they are written through `slog`, which quotes (text) or escapes (JSON) them:
a value cannot add fields or lines. Forms refuse control characters anyway.

**Personal data.** Other people's IPs and API keys are personal data in many
jurisdictions. You decide how long records are kept and where the server (and
its logs) are located; set `retention` to what you really do. The proxy never deletes anything: configure log rotation and
expiry (journald `MaxRetentionSec`, logrotate, your log platform) to match.

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
once. Each endpoint has its own bucket set. `GET /oauth/authorize` (rendering
the form, which seals a request) has its own, much larger budget
(`oauth.rate_limit.authorize_form`), and is not counted against the global
ceiling below. The metadata documents, `/healthz`, CORS preflights, non-POST requests to the token
endpoint (a plain 405) and the proxied MCP paths are not limited.

IPv4 clients are keyed by address. IPv6 clients are charged against three
buckets per endpoint, their `/64`, `/56` and `/48` prefix, and a request passes
only if all three allow it (a refused request costs no tokens). The configured
`per_minute` and `burst` are the `/64` budget; the `/56` bucket gets 4 times
and the `/48` bucket 16 times that, so a site with a few clients behind one
prefix is not squeezed, while rotating through the `/64`s of a routed prefix
stops at the `/48` budget instead of getting a fresh allowance per `/64`. With
the defaults, `authorize` allows 30/min (burst 10) per `/64`, 120/min (burst 40)
per `/56` and 480/min (burst 160) per `/48`. There is deliberately no IPv4
aggregate (for example a `/24`): IPv4 addresses are scarce and costly to rotate,
and the shared egress ranges of claude.ai and ChatGPT would then all share one
bucket. Each tier's key table holds at most 10 000 clients: when full, buckets
that have already refilled are dropped, and otherwise the least recently seen
client is evicted. A new client is therefore never refused because of table
size; a flood of distinct addresses can only reset the buckets of the oldest
clients (a hot `/48` stays in its table).

`POST /oauth/authorize` additionally has a global, unkeyed token bucket
(`oauth.rate_limit.authorize_global`, `per_minute` and `burst`). It is charged
only for a submission that is about to get a code: after the form was parsed and
fitted the size budget, the credentials passed the allow-list (`allowed_values`)
and, when configured, the upstream `validate` check. Foreign, malformed or
upstream-rejected submissions never spend it, so a flood of them cannot lock the
owner out of reconnecting; they are bounded by the per-IP limits above (charged
up front, validation calls included). A valid submission refused by the ceiling
gets the same `429` page with `Retry-After`; its per-IP token stays spent.

The aggregate rate of upstream `validate` calls is not globally capped: it is
bounded by the per-IP tiers and by the checker's 16 concurrent slots. A flood
from many addresses that saturates the slots makes `validate` answer `503`
(also to the owner) until the `validate` timeout frees them. On any public
upstream that uses `validate`, set `allowed_values`: foreign keys are then
refused before any upstream call.

Left at `0` the ceiling is derived so that the single-use code cache (50 000
entries) cannot fill: with `m` = `oauth.code_ttl` rounded up to whole minutes
(at least 1), `per_minute = burst = 50000 / 4 / m`, which is 2 500 for the
default 5 minutes (a longer `code_ttl`
lowers it: 1 250 at `10m`). A code occupies a cache slot for at most `code_ttl`,
so at most `burst + per_minute * m`, at most half the cache (15 000 live codes
by default), exist at once. The price is that a flood from many sources can
make new logins wait (429 with `Retry-After`) instead of filling the cache (only
submissions that pass the credential checks count toward this);
that clears as soon as the flood stops. Raise it only if you really expect
more than that many logins per minute; a value above the derived one gives up
the cache guarantee, and a warning is logged at startup when
`max(burst, per_minute) + per_minute * m` exceeds half the cache (25 000 live
codes). The derived default satisfies that bound for `code_ttl` up to about 17
days. `burst` needs `per_minute` to be set too, and defaults to it. With
`oauth.rate_limit.disabled` there is no ceiling; a full code cache then still
fails closed with `503 server_error` at the token endpoint. When the ceiling is
hit it is logged once a minute at `warn` (`global authorize ceiling reached`,
with a count of refused requests).

A limited request gets `429 Too Many Requests` with `Retry-After` (whole
seconds, rounded up):

- token and register: the usual JSON error body with the endpoint's usual
  headers (`Cache-Control: no-store`, ...):
  `{"error":"temporarily_unavailable","error_description":"rate limit exceeded"}`.
  RFC 6749 has no throttling code; `temporarily_unavailable` is the closest
  registered one and means retry later.
- authorize: the HTML error page ("Too many requests. ..."); the user agent is
  never redirected to the client.

Each per-client hit is logged at `debug` as `rate limit exceeded` (endpoint, client IP,
retry delay; never the query, headers or body), and the 429 shows up in the
access log.

The defaults are generous because claude.ai and ChatGPT call register and token
from shared egress addresses: all connecting users then share one bucket. Raise them
if many users connect at once; lower them on a private deployment.

```yaml
oauth:
  rate_limit:
    register:  { per_minute: 60,  burst: 30 }
    token:     { per_minute: 300, burst: 100 }
    authorize: { per_minute: 30,  burst: 10 }
    authorize_form: { per_minute: 300, burst: 100 }
    # authorize_global: { per_minute: 2500, burst: 2500 }  # default: derived from code_ttl
    # disabled: true
trusted_proxies: ["127.0.0.0/8", "::1/128"]
```

## Proxy limits

The top-level `limits` section bounds what one client can do on the proxied MCP
paths (`upstreams[].path`); the OAuth endpoints have their own
[rate limits](#rate-limiting). The section is shared by all upstreams, because
the per-IP budget and the in-flight cap are global.

| Field | Default | Meaning |
|---|---|---|
| `limits.disabled` | `false` | Switches all four limits below off (the body cap stays) |
| `limits.ip` | `per_minute: 1200`, `burst: 300` | Token bucket per client IP, checked before the bearer token is opened. IPv6 clients are also charged per `/56` and `/48` (4x and 16x the budget), as for the OAuth endpoints |
| `limits.token` | `per_minute: 300`, `burst: 60` | Token bucket per grant |
| `limits.max_concurrent_per_token` | `32` | In-flight requests per grant. An open SSE stream counts as one until it ends |
| `limits.max_in_flight` | `1024` | In-flight requests across all upstreams, open SSE streams included. Also sets `MaxConnsPerHost` of each upstream transport |
| `limits.max_request_body` | `10485760` (10 MiB) | Request body cap in bytes, at least `1024`; larger bodies get 413. Cannot be disabled. With `forbidden_arguments` each in-flight POST is held in memory, so worst-case memory is a small multiple (about 3 to 4 times, body plus parse copies) of `max_in_flight` times this value; size `max_request_body` and `max_in_flight` accordingly on small hosts |

Zero or unset means the default; `-1` disables that one limit (`per_minute: -1`
for the buckets); other negative values are rejected, as is a `burst` below 0.
This differs from `oauth.rate_limit`, which only has the all-or-nothing
`disabled`.

- **Grant.** The per-token limits are keyed by a SHA-256 over the upstream
  name and the required credential headers (names and values) the proxy injects;
  optional credentials (`optional: true`, such as a SID that `validate` does not
  check) are not part of it, so varying them gives no fresh budget. One
  set of upstream credentials is one user: the key stays the same when the
  access token is refreshed and is shared by all OAuth clients of that user,
  so registering more clients does not buy a fresh budget. The raw token and
  the credential values are never used as keys or logged. (Access tokens carry no refresh
  family id; adding one would change the token format.)
- **Order.** Method and path checks, then the per-IP bucket (so unauthenticated
  floods are cut before any decryption), then authentication, the body size
  check, the content-encoding check, the per-grant bucket, per-grant
  concurrency and the global in-flight cap. A request refused at any step gives
  back the tokens and slots taken by the earlier ones, so a denial costs
  nothing at the other tiers and never holds a slot. A `413` for a declared
  `Content-Length` over the cap, or a `415` for a `Content-Encoding` other than
  `identity` (refused for every upstream, since the header is never forwarded),
  also gives the IP token back. The IP token of a request that fails
  authentication stays spent, as does that of a chunked body that turns out too
  large mid-stream.
- **Responses.** Per-IP, per-grant and per-grant concurrency excess: `429` with
  `Retry-After` (the time until a token is available; `1` for concurrency).
  Global cap: `503` with `Retry-After: 1`. The body is a plain text line, as for
  the other proxy errors.
- **Streams and slow calls.** The limits never time a request out. A held SSE
  stream keeps its slots until the upstream ends it or the client disconnects.
  **Open SSE streams count toward both `max_in_flight` and
  `max_concurrent_per_token`**, even when idle: each is an in-flight request
  until it ends. Size `max_concurrent_per_token` for the concurrent streams plus
  tool calls one user may hold, and `max_in_flight` for all connected clients
  plus their calls (the default `1024` leaves room for that many idle streams
  before POSTs start to get `503`). Slots are also released if the handler
  panics or the response is aborted.
- **Global cap and queuing.** Go's `MaxConnsPerHost` makes extra requests wait
  for a free connection, without bound. The proxy therefore enforces the same
  number as an in-flight cap first and answers `503` instead, so the transport
  does not queue. The cap counts requests, not connections, across upstreams;
  each upstream's transport is limited to the same number of connections.
  `MaxConnsPerHost` limits connections, not streams: over HTTP/1.1 a stream
  holds a connection, but over HTTP/2 many streams share one, so there the
  in-flight cap is what actually binds.
- **Body cap.** 10 MiB stays the default: upstreams such as Tradernet expose
  file-upload tools whose payload is base64 inside the JSON-RPC body, so a
  smaller default could break real calls. Bodies are streamed, except on an upstream with
  `forbidden_arguments`, where each POST body is read whole into memory before
  it is forwarded; the caps above bound how many can be in flight. Lower it if your
  upstream takes only small messages.
- **Logs.** A refusal is logged at `debug` (client IP only for the per-IP
  limit) and, at most once a minute per limit, at `warn` as a count
  (`proxy rate limit refused requests`, `proxy concurrency limit refused
  requests`). Grants, tokens and credentials are never logged.
- **Client IP.** The same resolver as the OAuth limits (see [Client IP](#client-ip)).
  claude.ai calls come from shared egress addresses, which is why `limits.ip` is
  generous; tighten `limits.token` first.

```yaml
limits:
  ip:    { per_minute: 1200, burst: 300 }
  token: { per_minute: 300,  burst: 60 }
  max_concurrent_per_token: 32
  max_in_flight: 1024
  max_request_body: 10485760
  # disabled: true          # all limits off except the body cap
  # max_in_flight: -1       # or switch off just one
```

## Transport security

`public_url`, every `oauth.allowed_redirect_uris` entry and every
`upstreams[].url` must use `https`. The exception is loopback hosts, accepted
by name (`localhost`) or literal (`127.0.0.0/8`, `::1`), which may use `http`
for local development. A violation fails startup, for example `public_url: must
use https (http is allowed only for loopback hosts or with
allow_insecure_http)`. Setting the top-level `allow_insecure_http: true` lifts
the rule for non-loopback hosts (for instance an upstream reachable only over a
private network) and logs one startup warning.

When built-in TLS is configured the service adds
`Strict-Transport-Security: max-age=31536000` to every response, proxied ones
included (it replaces any value from an upstream). Without built-in TLS the
service sends no HSTS header: add it at the reverse proxy (see the nginx snippet
below).

OAuth and `/.well-known/*` requests get a 10 second read deadline (a slow-body
client is cut off); the proxied MCP paths have none, so long SSE streams are
unaffected.

## Built-in TLS

Setting both `tls.cert_file` and `tls.key_file` makes the service serve HTTPS on
`listen` (minimum TLS 1.2, Go's default cipher suites, HTTP/2 and HTTP/1.1 via
ALPN). Plain HTTP is not served on that port. `public_url` is independent of
this setting: it must be `https` whether TLS ends here or in a proxy in front
(enforced, see [Transport security](#transport-security)). With built-in TLS
the service sets HSTS.

```yaml
tls:
  cert_file: /etc/letsencrypt/live/mcp.example.com/fullchain.pem
  key_file:  /etc/letsencrypt/live/mcp.example.com/privkey.pem
  reload_interval: 1m
```

- The pair is loaded at startup; a missing, unreadable or mismatched pair is a
  fatal startup error (the service never falls back to plain HTTP).
- Hot reload: every `reload_interval` both files are read and a SHA-256 of
  their contents is compared with the last successful load (content-based, so
  same-second or same-size replacements are not missed; symlinks such as the
  Let's Encrypt `live/` links are followed). On a change the pair is validated
  and swapped atomically; new connections get the new certificate, established
  ones are unaffected. `SIGHUP` (`systemctl reload tn-mcp-proxy`) forces a
  reload immediately, even if nothing changed.
- A failed reload (unreadable, half-written or mismatched pair) logs a `warn`,
  keeps serving the previous certificate and is retried at the next tick.
- Every (re)load logs the subject, DNS names and `not_after` at `info`. A
  certificate with less than 14 days of validity logs a `warn` on load and then
  at most once a day while it stays loaded, so a broken renewal does not go
  unnoticed.

Under systemd with `DynamicUser=yes` the process cannot read `/etc/letsencrypt`
by default. Either:

- add `SupplementaryGroups=tls-certs` with a group that has read access to
  `/etc/letsencrypt/live` and `/etc/letsencrypt/archive` (the unit keeps
  `ProtectSystem=strict`, which leaves `/etc` readable); hot reload works. By
  default both directories are `0700 root` and `privkey*.pem` is `0600`, so
  open them up once:

  ```sh
  groupadd tls-certs
  chgrp -R tls-certs /etc/letsencrypt/live /etc/letsencrypt/archive
  chmod 750 /etc/letsencrypt/live /etc/letsencrypt/archive
  chmod 640 /etc/letsencrypt/archive/mcp.example.com/privkey*.pem
  ```

  Certbot generally carries the group (and mode bits) of the previous private
  key over to the renewed one, but this is not guaranteed across versions and
  setups; the safe option is a deploy hook
  (`/etc/letsencrypt/renewal-hooks/deploy/`) that re-applies the `chgrp`/`chmod`
  above and runs `systemctl reload tn-mcp-proxy`; or
- use `LoadCredential=` and point `tls.*` at
  `/run/credentials/tn-mcp-proxy.service/<name>`. systemd copies the files when
  the service starts, so a renewal is only seen after `systemctl restart`
  (a certbot deploy hook can run it). Note that `$CREDENTIALS_DIRECTORY` is not
  expanded in the config.

With the first option a certbot deploy hook is optional (polling finds the new
files); with either it may run `systemctl reload tn-mcp-proxy` to apply a
renewal without waiting for the interval.

## Reverse proxy

By default the service speaks plain HTTP, so put a TLS-terminating reverse proxy
in front (or enable [built-in TLS](#built-in-tls) and expose it directly).
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

    add_header Strict-Transport-Security "max-age=31536000" always;   # HSTS (the service sends it itself only with built-in TLS)

    client_max_body_size 10m;           # the service rejects bodies over limits.max_request_body, 10 MiB by default (413); raise both together

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
    # nginx limit is optional defence in depth. Keep it generous: claude.ai and
    # ChatGPT call register/token from shared egress IPs, so all users share
    # one bucket. Behind a CDN or load balancer restore the real client IP first
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

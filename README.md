# tn-mcp-proxy

An OAuth 2.1 facade in front of header-authenticated MCP servers. The Tradernet
MCP (`https://tradernet.com/mcp/tn`) authenticates with static request headers
(`X-TN-API-Key`, `X-TN-API-Secret`, optionally `X-TN-SID`), which claude.ai
and ChatGPT custom connectors cannot send; they only speak OAuth. tn-mcp-proxy
sits between the two: it presents a standard OAuth authorization server to
claude.ai or ChatGPT and forwards MCP traffic to the upstream with the user's
headers attached.

tn-mcp-proxy does not implement the Tradernet API itself: it fronts Tradernet's
own [MCP server](https://tradernet.com/tradernet-api/mcp) and forwards MCP
traffic to it with the user's credential headers attached.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/flow-dark.svg">
  <img alt="Flow: you enter Tradernet keys on the proxy's page; it seals them into a token your AI client holds and unseals it on each call." src="docs/images/flow-light.svg">
</picture>

## How it works

1. claude.ai or ChatGPT discovers the OAuth endpoints (`/.well-known/*`),
   registers itself (dynamic client registration) and sends the user to
   `/oauth/authorize`.
2. The user types their Tradernet credentials into a form served by the proxy.
3. The proxy encrypts the credentials into the access and refresh tokens it
   issues (AES-256-GCM, keys from your config). There is no database or persistent
   state; only bounded in-memory replay caches.
4. On each MCP request the AI client sends the token; the proxy opens it, sets
   the credential headers and streams the request to the upstream (SSE supported).

Who sees what:

| | Plain API keys | Sealed token |
| --- | --- | --- |
| You | type them once on the proxy's page | - |
| claude.ai / ChatGPT | never | stores it, cannot decrypt it |
| tn-mcp-proxy | in memory, per request; never stored or logged | opens it with keys from your config |
| Tradernet MCP | in the `X-TN-*` headers, as with a direct call | - |

The token is a bearer secret: whoever holds it can use it until it expires (access tokens: `oauth.access_token_ttl`; a refresh chain: its idle expiry or `oauth.max_session_ttl`, whichever comes first, and nothing is revoked when a connector is disconnected).
A TLS-terminating reverse proxy in front of tn-mcp-proxy also sees the plain
keys while you submit the authorization form.

See [docs/architecture.md](docs/architecture.md) for the details.

## Install

### From a GitHub Release

Archives are published per release for `linux` and `darwin` on `amd64` and
`arm64`: `tn-mcp-proxy_<version>_<os>_<arch>.tar.gz` (version without the `v`
prefix), plus `checksums.txt` (sha256).

```sh
VERSION=X.Y.Z   # replace with a release from the Releases page
OS=linux ARCH=amd64
BASE=https://github.com/zigmund/tn-mcp-proxy/releases/download/v${VERSION}
curl -fsSLO ${BASE}/tn-mcp-proxy_${VERSION}_${OS}_${ARCH}.tar.gz
curl -fsSLO ${BASE}/checksums.txt
sha256sum --ignore-missing -c checksums.txt      # macOS: shasum -a 256 --ignore-missing -c checksums.txt
tar xzf tn-mcp-proxy_${VERSION}_${OS}_${ARCH}.tar.gz
sudo install -m 0755 tn-mcp-proxy_${VERSION}_${OS}_${ARCH}/tn-mcp-proxy /usr/local/bin/
tn-mcp-proxy -version
```

The archive also contains `deploy/` (example config, systemd unit) and `docs/`.

### From source

```sh
git clone https://github.com/zigmund/tn-mcp-proxy && cd tn-mcp-proxy
make build            # binary in bin/
sudo install -m 0755 bin/tn-mcp-proxy /usr/local/bin/
```

(`go install github.com/zigmund/tn-mcp-proxy/cmd/tn-mcp-proxy@latest` also
works but puts the binary in `$GOPATH/bin`; copy it to `/usr/local/bin/`.)

## Configure

Create `/etc/tn-mcp-proxy/config.yaml` (full reference:
[docs/configuration.md](docs/configuration.md), annotated example:
[deploy/config.example.yaml](deploy/config.example.yaml)):

```yaml
listen: 127.0.0.1:8787
public_url: https://mcp.example.com     # origin only, no path
secrets:
  token_keys_file: /run/credentials/tn-mcp-proxy.service/keys
upstreams:
  - name: tn
    title: Tradernet
    path: /tn/mcp
    url: https://tradernet.com/mcp/tn
    credentials:
      - { header: X-TN-API-Key,    label: API key }
      - { header: X-TN-API-Secret, label: API secret, secret: true }
      - { header: X-TN-SID,        label: SID, optional: true }
    validate: { tool: get_auth_info }   # check the keys with Tradernet before issuing a token
```

To accept only your own API key, add `allowed_values: ["REPLACE_WITH_YOUR_API_KEY"]`
to the `X-TN-API-Key` credential (see
[Restricting access](docs/configuration.md#restricting-access)).

Generate the token key (base64 of 32 random bytes) into a root-only file, one
key per line:

```sh
sudo install -d -m 0755 /etc/tn-mcp-proxy
openssl rand -base64 32 | sudo install -m 0600 -o root -g root /dev/stdin /etc/tn-mcp-proxy/keys
```

Install the config so the service's dynamic user can read it (`0644`, root-owned):

```sh
sudo install -m 0644 -o root -g root config.yaml /etc/tn-mcp-proxy/config.yaml
```

Keep the keys out of `config.yaml`: the bundled systemd unit delivers the file
to the service through `LoadCredential=`, and the config points at it by its
absolute path (`/run/credentials/tn-mcp-proxy.service/keys`; environment
variables are not expanded in the config). The config itself then holds no
secrets, which is what makes `0644` safe. Anyone with the keys can decrypt every issued token,
so treat them like passwords.

## Run

The systemd unit lives in [deploy/](deploy/). Run the commands from
the extracted release archive directory or a checkout. The unit needs systemd
247 or newer (`LoadCredential=` with `DynamicUser=`).

```sh
sudo install -m 0644 deploy/tn-mcp-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tn-mcp-proxy
curl -fsS http://127.0.0.1:8787/healthz
journalctl -u tn-mcp-proxy -f
```

Options: `-config <path>` (default `/etc/tn-mcp-proxy/config.yaml`), `-version`, `-h`.
`SIGTERM`/`SIGINT` shut down gracefully; `SIGHUP` reloads the TLS certificate
when built-in TLS is enabled (the unit's `ExecReload` sends it) and is otherwise a no-op.

## Reverse proxy

The service listens on plain HTTP by default, so terminate TLS in front of it.
Alternatively set `tls.cert_file`/`tls.key_file` to serve HTTPS directly, with
certificate hot reload (see [Built-in TLS](docs/configuration.md#built-in-tls)). A tested
nginx snippet (no buffering, long timeouts, `X-Forwarded-For` overwrite, optional
extra rate limit for `/oauth/`) is in [docs/configuration.md](docs/configuration.md#reverse-proxy).
`GET /healthz` returns 200 and is meant for local checks.

## Get Tradernet API keys

Log in to Tradernet and generate an API key pair at
<https://tradernet.com/tradernet-api/auth-api>. You will enter the API key and
API secret (and optionally a SID) on the proxy's authorization page when you
connect. The proxy does not store them (they live only inside the sealed token
your AI client holds), but they do pass through the proxy process, so run the
proxy yourself or use one whose operator you trust.

## Connect claude.ai

1. In claude.ai: Settings -> Connectors -> Add custom connector.
2. URL: `public_url` + the upstream `path`, e.g. `https://mcp.example.com/tn/mcp`.
3. Connect. The browser opens the proxy's authorization page for the upstream:
   enter your Tradernet API key, API secret and (if you use one) SID.
4. Submit. With `validate` configured, the proxy first checks the keys with
   Tradernet and shows the form again if they are rejected. Otherwise claude.ai
   receives tokens and the connector is ready.

Your credentials are not stored on the server. They are sealed (encrypted and
authenticated) inside the tokens that claude.ai holds, and are decrypted only
to attach them to the request being forwarded.

If the keys are later revoked, Tradernet does not answer `401`: it answers
HTTP `200` with a tool error ("Invalid api key provided" and similar), so the
connector would stay "connected" while every tool call fails. With
`validate.recheck_on_tool_error: true` (the example config enables it for
Tradernet) the proxy treats any tool error (`isError: true`) only as a trigger:
it re-runs the upstream's `validate` credential check with the stored
credentials, and only if that check rejects them does it answer `401
invalid_token`, so claude.ai re-runs the flow and you can enter new keys. Other
tool errors (bad ticker, closed market) are forwarded untouched. The proxy does
not read the error text, so a wording change upstream does not break it. Only
failed tool calls wait for the check (about a second; if the upstream hangs,
up to `validate.timeout`, default 10 s); the verdict is cached
for 60 seconds. See
[docs/configuration.md](docs/configuration.md#re-check-on-tool-errors).
An upstream that does answer `401` is handled without any configuration.

## Connect ChatGPT

The UI path below may change; follow the current ChatGPT documentation if it differs.

1. In ChatGPT: Settings -> Apps & Connectors -> Advanced -> enable Developer mode.
2. Create a connector (custom app) with the MCP server URL: `public_url` + the
   upstream `path`, e.g. `https://mcp.example.com/tn/mcp`. Choose OAuth as the
   authentication method.
3. Connect. The browser opens the same authorization page: enter your upstream
   credentials and submit.

ChatGPT registers itself through dynamic client registration and uses the stable
redirect URI `https://chatgpt.com/connector_platform_oauth_redirect`, which is
allowed by default and relies on the RFC 9207 `iss` parameter the proxy
returns. Credentials are handled as described above.

## Key rotation

1. Generate a new key and put it first in the keys file; keep the old one below it:
   ```sh
   sudo sh -c 'umask 077; { openssl rand -base64 32; cat /etc/tn-mcp-proxy/keys; } > /etc/tn-mcp-proxy/keys.new && mv /etc/tn-mcp-proxy/keys.new /etc/tn-mcp-proxy/keys'
   sudo systemctl restart tn-mcp-proxy    # reload does not re-read keys
   ```
   (`umask 077` makes the new file `0600` from the start.)
2. The first key seals new tokens; all listed keys still open existing ones, so
   no one is logged out. Every refresh issues a new refresh token with a fresh (sliding)
   `refresh_token_ttl` (capped at `oauth.max_session_ttl` from the original login), so
   active connectors migrate to the new key by themselves.
3. After `oauth.refresh_token_ttl` (default 720h = 30 days; logins older than
   `oauth.max_session_ttl`, default 90 days, are cut off earlier) no token sealed
   with the old key is still valid. Remove the old key and restart. Registered client
   ids sealed with the old key become invalid too, and refresh tokens are bound
   to the old client id, so this step is not seamless: claude.ai re-registers on
   its own, but every user must go through the credentials form again. Connectors
   idle for longer than the TTL must be reconnected as well.

If a key leaked: add a new key first (first in the file), then remove the
leaked one and restart. Removing a key invalidates every token AND every
registered client id sealed with it, so claude.ai re-registers and users have
to reconnect the connector. Do not rely on a plain restart to cut off a leak
(see the replay-cache note below).

## Security notes

- No database or stored credentials; tokens are self-contained sealed blobs.
- The host sees credentials in plaintext on the authorize form: run the proxy
  only on a host you trust, always behind TLS, and keep `public_url` on `https`
  (enforced: `http` is accepted only for loopback or with
  `allow_insecure_http`; the same goes for redirect URIs and upstream URLs).
  Known-weak token keys, including the old example key, are rejected at startup.
- Set `validate` on every upstream: without it the form accepts any values and
  anyone who can reach the server could mint a token and use it as a relay.
  With it, a code is issued only for credentials the upstream accepts (the check
  is read-only, fails closed and never follows redirects; see
  [docs/configuration.md](docs/configuration.md#credential-validation)).
- Optionally restrict who can use an upstream with `allowed_values` on a
  non-secret credential (for example your own API key). Credentials outside the
  list get no token, and existing tokens stop working once a value is removed.
  Recommended for a single-user deployment that is reachable from the internet;
  without it, anyone with valid upstream credentials can use the server (and its
  IP) and the proxy logs a startup warning. See
  [docs/configuration.md](docs/configuration.md#restricting-access).
- Run a single instance. Single-use authorization codes and refresh-token
  families are tracked in bounded in-memory replay caches, so several instances
  would not see each other's usage.
- A restart resets replay protection. An authorization code can be redeemed again
  within `oauth.code_ttl` (PKCE still binds it to the client), a small window. A refresh token consumed before a restart is accepted
  again (its family is forgotten) for up to `oauth.refresh_token_ttl`. Avoid
  casual restarts after a suspected token leak; rotate keys instead (above).
- Registration is open, so anyone can register a client with any `client_name`, including a look-alike of a known one. The authorize page therefore names the application by the host it returns to ("<host> is requesting access to ..."), shows the self-declared name only as a secondary, labelled "unverified" line, and only allowlisted redirect URIs are accepted. Check the host before entering credentials.
- Refresh tokens are single-use and rotated on every refresh; presenting an already used one revokes its whole chain (the user reconnects).
- A login has an absolute lifetime: refreshing slides the expiry by `oauth.refresh_token_ttl`, but never past `oauth.max_session_ttl` (default 2160h = 90 days) from the original login, after which the user reconnects. Upgrade note: refresh tokens issued before this limit existed get a fresh `max_session_ttl` window at their first refresh.
- Disconnecting a connector in claude.ai or ChatGPT does not revoke anything on the proxy (there is no revocation endpoint). Its refresh chain stays valid until the `oauth.refresh_token_ttl` idle expiry or `oauth.max_session_ttl`, whichever comes first. To cut everyone off, rotate the token keys and remove the old one.
- Redirect URIs are restricted to `oauth.allowed_redirect_uris` (claude.ai, claude.com and ChatGPT callbacks by default; ChatGPT's stable callback relies on the RFC 9207 `iss` parameter the proxy returns).
- `POST /oauth/register`, `/oauth/authorize` and `/oauth/token` (and `GET /oauth/authorize`, with its own, larger budget) are rate limited by the app itself (generous defaults, `oauth.rate_limit`; excess requests get 429 with `Retry-After`). IPv4 clients are limited per address; IPv6 clients per `/64`, `/56` and `/48` (a request must fit all three budgets), so rotating `/64`s inside a routed prefix does not multiply the allowance. `POST /oauth/authorize` additionally has a global ceiling derived from the code cache size and `oauth.code_ttl` (2 500 per minute by default), so the authorization-code cache cannot fill; if it still did, it fails closed with 503. Revoked refresh families are kept in a separate bounded set until their expiry, outside the LRU that attacker-created families can churn: a revoked chain is not re-opened by cache pressure. The active-family cache evicts the least recently used chains when full, at the cost that reuse detection is lost for evicted chains (they just refresh as a new family; nothing locks out). If the revocation set itself ever fills (about a million live revocations), unknown families (new logins, and active chains already evicted from the LRU) are refused with 503 on refresh rather than risking a revoked one; chains still in the LRU keep refreshing. The client IP honours `X-Forwarded-For` only from `trusted_proxies` (loopback by default); add your CDN or load balancer there. A reverse-proxy `limit_req` (the nginx snippet has one) is an optional extra layer. Details and the attacker cost are in [docs/architecture.md](docs/architecture.md). See [docs/configuration.md](docs/configuration.md#rate-limiting).
- Tokens, credentials and query strings are never logged.
- The service runs as a dynamic unprivileged user under a restrictive systemd sandbox.

## Development

```sh
make test                 # go test -race ./... (fuzz seed corpora run as ordinary tests)
make lint                 # golangci-lint, or go vet when it is not installed
make fuzz FUZZTIME=30s    # run every fuzz target in turn, FUZZTIME each (default 30s)
```

A full `make fuzz` at the default 30s takes about 7 minutes or more (14 targets, one after another).
`make fuzz` discovers every `func FuzzXxx(*testing.F)` in the `_test.go` files,
so new targets need no Makefile change. The targets cover token sealing, bearer
and client-authentication parsing, PKCE, redirect construction and the
`/oauth/authorize` and `/oauth/token` handlers. A failing input is saved as
`testdata/fuzz/<FuzzName>/<hash>` next to the package. Fix the bug, then commit
that file as a regression seed: `go test` replays it from then on. Fuzzing is
not part of CI or the release workflow.

## Releasing

Releases are cut from `main` by a GitHub Actions workflow; see
[docs/releasing.md](docs/releasing.md).

## Documentation

- [docs/configuration.md](docs/configuration.md)
- [docs/architecture.md](docs/architecture.md)
- [docs/releasing.md](docs/releasing.md)

## License

MIT, see [LICENSE](LICENSE).

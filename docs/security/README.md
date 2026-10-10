# Security audits

This directory holds the reports of two independent white-box security audits of tn-mcp-proxy, both run on 2026-10-10.

## What was audited

- **Scope:** the Go packages `internal/{oauth,seal,tokens,proxy,server,httplog,ratelimit,config,certreload}` (the second audit adds `credcheck` and `logging`), `cmd/`, `deploy/`, the README and `docs/`.
- **Specs and areas covered:** OAuth 2.1, RFC 9700 (Security BCP), RFC 7636 (PKCE), RFC 8707 (resource indicators), RFC 9207 (`iss`), RFC 9728 and RFC 8414 (metadata), RFC 7591 (dynamic client registration), the MCP authorization spec, token cryptography (sealed, self-contained tokens), header handling and logging, and a check of the documentation claims against the code.
- **Threat model, in short:** the proxy is internet-facing and stateless. Registration is open, and the proxy holds no stored credentials. The attackers considered are an unauthenticated client, a registered client with attacker-chosen metadata (open registration), a holder of a stolen access or refresh token, and, on deployments without an allow-list, a user with their own valid upstream credentials. The assets are the users' upstream (Tradernet) credentials, which travel only inside sealed tokens, and the operator's availability and IP reputation. The upstream, the TLS terminator in front, and the operator's host are trusted.

## The audits

| Audit | Baseline commit | Date | Report | Outcome |
|---|---|---|---|---|
| First | `3eeecc2` | 2026-10-10 | [audit-2026-10-3eeecc2.md](audit-2026-10-3eeecc2.md) | 0 Critical, 0 High, 2 Medium, 5 Low, 7 Info |
| Second | `7ac37ab` | 2026-10-10 | [audit-2026-10-7ac37ab.md](audit-2026-10-7ac37ab.md) | 0 Critical, 0 High, 0 Medium, 2 Low, 5 Info (new findings) |

The second audit re-verified every finding of the first one against the fixed code. It also reviewed the code added in between. Its addendum records the status at `1255d35`: nothing above Info is open. N-09 and N-10 were fixed afterwards in #38; only N-05 remains, documented by design.

Line numbers in the `file:line` evidence refer to the baseline commit of each report. The proof-of-concept tests used during the audits were run privately and are not published; regression tests for the fixes live in the repository.

## Where the fixes landed

First audit:

| Finding | Fixed in |
|---|---|
| F-01 | #26 (credential validation on authorize), #33 (proxy rate and concurrency limits) |
| F-02 | #27 |
| F-03 | #25 |
| F-04 | #28 |
| F-05, F-06, F-07 | #29 |
| I-01 to I-07 | #31 |

Related hardening that followed (not direct fixes): #30 (re-authorization on upstream tool errors), #32 (credential allow-list, `allowed_values`), #34 (open-relay warning in the docs).

Second audit:

| Finding | Fixed in |
|---|---|
| N-01 | #37 |
| N-05 | documented in #37 (by design) |
| N-03 | #35 |
| N-04, N-06, N-07 | #36 |
| N-08 (documentation drift) | #36, #37, #38 |
| N-09, N-10 | #38 |

N-02 was a hypothesis that was ruled out.

## Reporting a vulnerability

Open a private security advisory on GitHub (Security, then Report a vulnerability). Please do not open a public issue for a suspected vulnerability.

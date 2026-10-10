# Releasing

Releases are cut manually from `main` by a GitHub Actions workflow; GoReleaser builds and publishes the artifacts.

## Triggering a release

1. GitHub -> Actions -> **Release** -> **Run workflow**.
2. Select branch `main` (other refs are rejected).
3. Enter `version`, e.g. `v1.2.3`, and run.

## Versioning

- Semver with a mandatory `v` prefix: `vMAJOR.MINOR.PATCH`, optionally `-prerelease` (`v1.2.3-rc.1`).
- Pre-release versions are published as GitHub pre-releases automatically.
- The tag must not exist yet; the workflow fails early otherwise. Tags are never overwritten.

## What the workflow does

1. Validates the ref, the version format and tag uniqueness.
2. `test` job: `go vet`, `go test -race ./...`, golangci-lint (pinned version).
3. `release` job (the only one with `contents: write`): creates an annotated tag on the checked-out commit as `github-actions[bot]`, pushes it, then runs `goreleaser release --clean` with `GITHUB_TOKEN`.
4. GoReleaser publishes the GitHub Release with GitHub-generated release notes.

Only one release runs at a time (`concurrency: release`). Releases are published non-draft, so failures need manual cleanup (see below).

## Recovering from a failed release

If the `release` job fails after the tag was pushed, the workflow prints these commands; run them before re-running with the same version:

```sh
gh release delete <version> --yes        # only if the GitHub Release was created
git push origin :refs/tags/<version>     # delete the remote tag
```

Note: the workflow cannot stop someone from pushing or deleting `v*` tags by hand. Real enforcement needs a tag ruleset on `v*` (restrict creation, updates and deletion) or a protected environment with required reviewers.

## Artifacts

Per release, for `linux` and `darwin` on `amd64` and `arm64`:

- `tn-mcp-proxy_<version>_<os>_<arch>.tar.gz`, extracting into a wrapping directory of the same name (without `.tar.gz`) that contains:
  - `tn-mcp-proxy` (static binary, `CGO_ENABLED=0`, `-trimpath`, version injected via `-X main.version`, reported as `v1.2.3`)
  - `docs/*.md`, `deploy/` (recursive: example config, and deployment files when present), plus `README*` and `LICENSE*` if they exist
- `checksums.txt` (sha256)

`<version>` in file names has no `v` prefix (`1.2.3`).

## Verifying checksums

```sh
sha256sum --ignore-missing -c checksums.txt     # Linux
shasum -a 256 --ignore-missing -c checksums.txt # macOS
```

## Building locally

```sh
make build                                        # host binary in bin/
goreleaser release --snapshot --clean --skip=publish   # all archives in dist/
```

## Possible follow-ups

Artifact signing (cosign), SBOM generation, container images.

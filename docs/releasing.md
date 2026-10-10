# Releasing

Releases are cut manually from `main` by a GitHub Actions workflow; GoReleaser builds and publishes the artifacts.

## Triggering a release

1. GitHub -> Actions -> **Release** -> **Run workflow**.
2. Select branch `main` (other refs are rejected).
3. Choose `bump`: `patch`, `minor` or `major`.
4. Leave `prerelease` empty for a final release, or set an id such as `rc` for a pre-release.
5. Run. The version is computed by the workflow; nothing is typed by hand. The job summary shows the computed version, the previous tag and the commits (first-parent subjects) since it.

## How the version is computed

The logic lives in `scripts/next-version.sh` (tested by `scripts/next-version_test.sh`, or `make test-scripts`; CI runs the test too). It reads the tags from the remote (`git ls-remote --tags`), which are the source of truth.

- **Base** = the highest *stable* `vX.Y.Z` tag by semver order (so `v0.10.0` > `v0.9.0`; creation date is irrelevant). Pre-release tags, non-semver tags, tags with leading zeros and tags with a numeric component longer than 9 digits are ignored.
- **Bump**: `patch` -> `X.Y.Z+1`; `minor` -> `X.Y+1.0`; `major` -> `X+1.0.0`.
- **First release**: when there is no stable tag yet, the result is `v0.1.0` for every bump (including `major`: the simplest rule, and 1.0.0 should be a deliberate step; once `v0.1.0` exists, `major` gives `v1.0.0`). With a pre-release id and no stable tags the target is still `0.1.0`, e.g. `v0.1.0-rc.1`.
- **Pre-release**: `vX.Y.Z-<id>.N`, where `X.Y.Z` is the bumped target and `N` = 1 + the highest existing `N` for that exact target and id (`rc.1`, `rc.2`, ...). The id must start with a letter, followed by `[0-9A-Za-z-]*` (so `rc`, `beta`, `rc-x` are fine; `1a` and `-` are rejected). Other ids (`beta`) count separately.
- **Final after rc**: running the same bump with an empty `prerelease` yields plain `vX.Y.Z`; the rc tags do not move the base.

Examples (latest stable tag `v1.2.3`):

| bump  | prerelease | result        |
|-------|------------|---------------|
| patch |            | `v1.2.4`      |
| minor | rc         | `v1.3.0-rc.1` |
| minor | rc         | `v1.3.0-rc.2` (after the previous run) |
| minor |            | `v1.3.0` (final; base is then `v1.3.0`) |

Typical rc flow: run `minor` + `rc` (repeat for `rc.2`, ...), verify the pre-release artifacts, then run `minor` with empty `prerelease` for the final. Do not change the bump between rc runs and the final: a different bump targets a different version.

Run locally to preview: `scripts/next-version.sh minor rc` (uses local tags; run `git fetch --tags` first).

## Versioning

- Semver with a mandatory `v` prefix: `vMAJOR.MINOR.PATCH`, optionally `-prerelease` (`v1.2.3-rc.1`).
- Pre-release versions are published as GitHub pre-releases automatically.
- The computed tag must not exist yet; the workflow fails early otherwise (checked fail-closed against the remote). Tags are never overwritten.

## What the workflow does

1. `test` job: checks the ref is `main`, runs the script tests, computes the version from remote tags, validates it (semver format, valid ref name, tag free on the remote), writes the job summary, then runs `go vet`, `go test -race ./...` and golangci-lint (pinned version). The version is exported as a job output.
2. `release` job (the only one with `contents: write`): uses the version from the `test` job output, creates an annotated tag on the checked-out commit as `github-actions[bot]`, pushes it, then runs `goreleaser release --clean` with `GITHUB_TOKEN`.
3. GoReleaser publishes the GitHub Release with GitHub-generated release notes.

Only one release runs at a time (`concurrency: release`). Releases are published non-draft, so failures need manual cleanup (see below). Because the version is computed before the gates run and the tag is pushed afterwards, a tag created by someone else in between makes the push fail; just re-run.

## Recovering from a failed release

If the `release` job fails after the tag was pushed, the workflow prints these commands; run them before re-running. The re-run recomputes the version from the remote tags: with the tag deleted it yields the same version again; if the tag is left in place it counts as taken and the next number is used.

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

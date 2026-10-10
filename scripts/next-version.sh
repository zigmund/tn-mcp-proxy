#!/usr/bin/env bash
# Compute the next release version from existing git tags.
#
# Usage:
#   scripts/next-version.sh [--tags-stdin] [--base] <patch|minor|major> [prerelease-id]
#
#   --tags-stdin  read the tag list (one per line) from stdin instead of `git tag`
#   --base        print the base tag (highest stable vX.Y.Z, empty if none)
#                 instead of the next version
#
# Rules:
#   * Base = highest STABLE vX.Y.Z tag by semver order. Pre-release tags and
#     non-semver tags never act as a base.
#   * No stable tag at all -> the first release is v0.1.0 regardless of bump.
#   * Otherwise bump the base (major resets minor/patch, minor resets patch).
#   * With a prerelease id (e.g. rc): vX.Y.Z-<id>.N, where X.Y.Z is the bumped
#     target and N = 1 + highest existing N for that exact target+id.
#   * The prerelease id must start with a letter, then [0-9A-Za-z-]*.
#   * Numeric components above 9 digits are ignored.
#   * Empty prerelease id = final release vX.Y.Z.
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }

from_stdin=0
print_base=0
while [[ "${1:-}" == --* ]]; do
  case "$1" in
    --tags-stdin) from_stdin=1 ;;
    --base) print_base=1 ;;
    *) die "unknown option $1" ;;
  esac
  shift
done

bump="${1:-}"
pre="${2:-}"
[[ $# -le 2 ]] || die "too many arguments"

case "$bump" in
  patch|minor|major) ;;
  *) die "bump must be patch, minor or major (got '$bump')" ;;
esac

if [[ -n "$pre" ]]; then
  [[ "$pre" =~ ^[A-Za-z][0-9A-Za-z-]*$ ]] || die "prerelease id must start with a letter and match [0-9A-Za-z-]* (got '$pre')"
fi

if [[ $from_stdin -eq 1 ]]; then
  tags="$(cat)"
else
  tags="$(git tag --list)"
fi
tags="${tags//$'\r'/}"

# Numeric components are capped at 9 digits so bash integer math cannot
# overflow; tags exceeding the cap are ignored (never used as a base).
num='(0|[1-9][0-9]{0,8})'
stable_re="^v${num}\\.${num}\\.${num}\$"

# Highest stable tag by numeric semver order (not lexical, not by date).
base=""
stable="$(
  while IFS= read -r t; do
    if [[ "$t" =~ $stable_re ]]; then echo "${t#v}"; fi
  done <<<"$tags" | sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1
)"
[[ -z "$stable" ]] || base="v$stable"

if [[ $print_base -eq 1 ]]; then
  echo "$base"
  exit 0
fi

if [[ -z "$base" ]]; then
  target="0.1.0"
else
  IFS=. read -r maj min pat <<<"$stable"
  case "$bump" in
    major) maj=$((maj + 1)); min=0; pat=0 ;;
    minor) min=$((min + 1)); pat=0 ;;
    patch) pat=$((pat + 1)) ;;
  esac
  target="$maj.$min.$pat"
fi

if [[ -z "$pre" ]]; then
  echo "v$target"
  exit 0
fi

# Next pre-release counter for this exact target+id.
prefix="v${target}-${pre}."
max=0
while IFS= read -r t; do
  [[ "$t" == "$prefix"* ]] || continue
  n="${t#"$prefix"}"
  [[ "$n" =~ ^(0|[1-9][0-9]{0,8})$ ]] || continue
  if (( n > max )); then max=$n; fi
done <<<"$tags"
echo "${prefix}$((max + 1))"

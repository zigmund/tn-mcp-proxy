#!/usr/bin/env bash
# Plain-bash tests for next-version.sh (no external test framework).
set -uo pipefail
cd "$(dirname "$0")"

fail=0
# check <name> <expected> <tags (newline separated)> <args...>
check() {
  local name="$1" want="$2" tags="$3"; shift 3
  local got
  got="$(printf '%s' "$tags" | ./next-version.sh --tags-stdin "$@" 2>&1)"
  if [[ "$got" == "$want" ]]; then echo "ok   $name"; else echo "FAIL $name: want '$want' got '$got'"; fail=1; fi
}
# check_err <name> <tags> <args...>: must exit non-zero
check_err() {
  local name="$1" tags="$2"; shift 2
  if printf '%s' "$tags" | ./next-version.sh --tags-stdin "$@" >/dev/null 2>&1; then
    echo "FAIL $name: expected failure"; fail=1; else echo "ok   $name"; fi
}

check "no tags patch"  v0.1.0 "" patch
check "no tags minor"  v0.1.0 "" minor
check "no tags major"  v0.1.0 "" major
check "no tags rc"     v0.1.0-rc.1 "" major rc
check "only non-semver" v0.1.0 $'latest\nrelease-1\nv1\nv1.2\n1.2.3' patch

T=$'v0.1.0\nv0.1.1'
check "stable patch" v0.1.2 "$T" patch
check "stable minor" v0.2.0 "$T" minor
check "stable major" v1.0.0 "$T" major

T=$'v0.9.0\nv0.10.0\nv0.2.0'
check "non-lexical order patch" v0.10.1 "$T" patch
check "non-lexical order minor" v0.11.0 "$T" minor
check "non-lexical base" v0.10.0 "$T" --base patch

T=$'v1.2.3\nv1.3.0-rc.1\nv1.3.0-rc.2\nv1.3.0-beta.1\nv1.4.0-rc.7'
check "first rc for target" v1.2.4-rc.1 "$T" patch rc
check "rc increments"       v1.3.0-rc.3 "$T" minor rc
check "other id independent" v1.3.0-beta.2 "$T" minor beta
check "new id"              v1.3.0-alpha.1 "$T" minor alpha
check "other target rc not counted" v2.0.0-rc.1 "$T" major rc

T=$'v1.2.3\nv1.3.0-rc.1\nv1.3.0-rc.2\nv1.3.0'
check "rc then final: base is final" v1.3.1 "$T" patch
T=$'v1.2.3\nv1.3.0-rc.1\nv1.3.0-rc.2'
check "final after rc tags" v1.3.0 "$T" minor
check "rc ignored as base" v1.2.4 $'v1.2.3\nv9.9.9-rc.1' patch
check "rc.10 beats rc.9" v1.3.0-rc.11 $'v1.2.3\nv1.3.0-rc.9\nv1.3.0-rc.10' minor rc
check "garbage rc suffix ignored" v1.3.0-rc.1 $'v1.2.3\nv1.3.0-rc.x\nv1.3.0-rc.01' minor rc

check "base empty without tags" "" "" --base patch
check "base prints stable" v1.2.3 $'v1.2.3\nv1.3.0-rc.1' --base patch

check_err "invalid bump"       "" bogus
check_err "empty bump"         "" ""
check_err "numeric prerelease" "" patch 1
check_err "bad prerelease chars" "" patch 'rc.1'
check_err "bad prerelease space" "" patch 'r c'
check_err "bad prerelease slash" "" patch 'rc/1'

# Regression tests (review round)
check "leading-zero tags ignored" v0.1.0 $'v01.2.3\nv1.02.3\nv1.2.03' patch
check "rc.0 counts" v1.3.0-rc.1 $'v1.2.3\nv1.3.0-rc.0' minor rc
check "rc for already-final target" v1.0.2-rc.1 $'v1.0.0\nv1.0.1-rc.1\nv1.0.1' patch rc
check "CRLF tag list" v1.2.4 $'v1.2.3\r\nv1.2.2\r\n' patch
check "rc-x does not collide with rc" v1.3.0-rc-x.1 $'v1.2.3\nv1.3.0-rc.4' minor rc-x
check "rc ignores rc-x tags" v1.3.0-rc.1 $'v1.2.3\nv1.3.0-rc-x.4' minor rc
check "over-cap component ignored" v1.2.4 $'v1.2.3\nv1234567890.0.0' patch
check_err "id dash only" "" patch -
check_err "id 1a" "" patch 1a
check_err "id with newline" "" patch $'rc\nx'

exit $fail

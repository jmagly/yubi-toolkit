#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/yubi-transaction-test.XXXXXX")
trap 'rm -rf "$TEST_DIR"' EXIT HUP INT TERM
export PATH="$ROOT_DIR/tests/bin:/opt/homebrew/opt/openssl@3/bin:/usr/local/opt/openssl@3/bin:$PATH"
export YUBI_TEST_YKMAN_VERSION=5.9.2
export YUBI_TEST_YKMAN_FIXTURE="$ROOT_DIR/tests/fixtures/ykman-5.9.2-info.out"
export YUBI_PROGRAMMER="$ROOT_DIR/tests/bin/programmer-mock"
export YUBI_TEST_KEEP_PATH=true
canary=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

fail() { printf 'not ok - %s\n' "$1" >&2; exit 1; }

run_fault() {
    local phase="$1" expected="$2" input state
    input="$TEST_DIR/$phase.pool"
    state="$TEST_DIR/$phase.state"
    printf '%s\n' "$canary" "$canary" "$canary" "$canary" "$canary" > "$input"
    set +e
    printf 'YES\n' | YUBI_FAULT_AFTER_PHASE="$phase" "$ROOT_DIR/configure-yubi.sh" mixed 12345678 "$input" \
        --derivation-profile v2 --state-file "$state" --with-fido-pin >/dev/null 2>&1
    result=$?
    set -e
    [[ "$result" -eq 90 ]] || fail "fault after $phase returned $result"
    grep -q "\"status\":\"$expected\"" "$state" || fail "fault after $phase state"
    [[ $(grep -c . "$input") -eq 5 ]] || fail "fault after $phase consumed seeds"
    if grep -q "$canary" "$state"; then fail "state disclosed seed material"; fi
}

run_fault preflight failed
run_fault piv partial
run_fault otp partial
run_fault fido2 partial
printf 'ok - every post-adapter fault preserves seeds and accurate redacted state\n'

input="$TEST_DIR/success.pool"
state="$TEST_DIR/success.state"
printf '%s\n' "$canary" "$canary" "$canary" "$canary" "$canary" > "$input"
printf 'YES\n' | "$ROOT_DIR/configure-yubi.sh" mixed 12345678 "$input" \
    --derivation-profile v2 --state-file "$state" >/dev/null
grep -q '"status":"complete"' "$state" || fail "success state is not complete"
grep -q '"scope":\["piv","otp"\]' "$state" || fail "optional FIDO scope inaccurate"
[[ ! -e "$input" ]] || fail "successful transaction did not consume seeds"
printf 'ok - completion commits seeds only after requested postconditions\n'

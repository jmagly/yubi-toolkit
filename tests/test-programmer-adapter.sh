#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fail() { printf 'not ok - %s\n' "$1" >&2; exit 1; }
ok() { printf 'ok - %s\n' "$1"; }

TEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/yubi-adapter-test.XXXXXX")
trap 'jobs -pr | xargs -r kill 2>/dev/null || true; rm -rf "$TEST_DIR"' EXIT HUP INT TERM
canary="YUBI_CANARY_7f92a8d13c"
descriptor="$TEST_DIR/descriptor.json"
printf '{"serial":12345678,"management_algorithm":"AES256","management_key":"%064d","pin":"12345678","puk":"Ab12Cd34","slot1":{"kind":"static","password":"%s"},"slot2":{"kind":"yubiotp","aes_key":"%032d","private_id":"%012d"},"fido_pin":"87654321","derivation_profile":"v2","scope":["piv","otp","fido2"]}\n' \
    0 "$canary" 0 0 > "$descriptor"
chmod 600 "$descriptor"

success_out=$(python3 "$ROOT_DIR/yubikey-programmer.py" --validate-only < "$descriptor" 2>&1)
[[ "$success_out" == *'"ok": true'* ]] || fail "valid descriptor rejected"
[[ "$success_out" != *"$canary"* ]] || fail "success output disclosed canary"
ok "successful validation output is non-sensitive"

printf '{"serial":12345678,"unexpected":"%s"}\n' "$canary" > "$descriptor"
if failure_out=$(python3 "$ROOT_DIR/yubikey-programmer.py" --validate-only < "$descriptor" 2>&1); then
    fail "invalid descriptor accepted"
fi
[[ "$failure_out" != *"$canary"* ]] || fail "failure output disclosed canary"
ok "failure output is non-sensitive"

if [[ -r /proc/self/environ ]]; then
    fifo="$TEST_DIR/input.fifo"
    mkfifo "$fifo"
    { printf '{"canary":"%s"' "$canary"; sleep 5; } > "$fifo" &
    writer_pid=$!
    python3 "$ROOT_DIR/yubikey-programmer.py" --validate-only < "$fifo" > "$TEST_DIR/out" 2> "$TEST_DIR/err" &
    adapter_pid=$!
    sleep 1
    tr '\0' ' ' < "/proc/$adapter_pid/cmdline" | grep -q "$canary" && fail "canary found in argv"
    tr '\0' '\n' < "/proc/$adapter_pid/environ" | grep -q "$canary" && fail "canary found in environment"
    grep -q "$canary" "$TEST_DIR/out" "$TEST_DIR/err" && fail "canary found in output"
    kill "$adapter_pid" "$writer_pid" 2>/dev/null || true
    wait "$adapter_pid" "$writer_pid" 2>/dev/null || true
    ok "process arguments, environment, and output exclude canary"
else
    ok "process surface inspection (skipped: procfs unavailable)"
fi

if grep -En 'ykman .*--(key|pin|puk|management-key|new-pin|new-puk|new-management-key)' "$ROOT_DIR/configure-yubi.sh"; then
    fail "credential-bearing ykman CLI call remains"
fi
ok "no credential-bearing ykman CLI mutation"

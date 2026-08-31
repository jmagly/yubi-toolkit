#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT_DIR/yubi-lib.sh"

fail() { printf 'not ok - %s\n' "$1" >&2; exit 1; }
ok() { printf 'ok - %s\n' "$1"; }

validate_mode otp
validate_mode static
validate_mode mixed
if (validate_mode invalid >/dev/null 2>&1); then
    fail "invalid mode accepted"
fi
ok "mode validation"

validate_serial 12345678
if (validate_serial '12;34' >/dev/null 2>&1); then
    fail "invalid serial accepted"
fi
ok "serial validation"

mock_version=$(YUBI_TEST_YKMAN_VERSION=5.9.2 PATH="$ROOT_DIR/tests/bin:$PATH" ykman --version)
[[ "$mock_version" == *5.9.2 ]] || fail "ykman mock version fixture failed"
mock_info=$(YUBI_TEST_YKMAN_FIXTURE="$ROOT_DIR/tests/fixtures/ykman-5.9.2-info.out" PATH="$ROOT_DIR/tests/bin:$PATH" ykman -d 12345678 info)
[[ "$mock_info" == *'Firmware version: 5.8.1'* ]] || fail "ykman mock info fixture failed"
ok "ykman fixtures"

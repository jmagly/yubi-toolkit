#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT_DIR/yubi-lib.sh"
seed=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
serial=12345678
alpha=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789

fail() { printf 'not ok - %s\n' "$1" >&2; exit 1; }
check() { [[ "$1" == "$2" ]] || fail "$3"; }

check "$(credential_v2_charset "$seed" "$serial" piv/pin 8 0123456789)" 89107495 "PIV PIN vector"
check "$(credential_v2_charset "$seed" "$serial" piv/puk 8 "$alpha")" auWhoXiF "PIV PUK vector"
check "$(credential_v2_hkdf_hex "$seed" "$serial" piv/management-key/AES256 0 32)" \
    81cb50288d677db3e1a9b1765de23f16a04d18c431dcaa9493b42017e2e4f704 "management key vector"
check "$(credential_v2_charset "$seed" "$serial" fido2/pin 8 0123456789)" 29757679 "FIDO PIN vector"
check "$(credential_v2_hkdf_hex "$seed" "$serial" otp/slot1/aes-key 0 16)" 405a296683b99bd7bee431a49d4a88c7 "slot 1 AES vector"
check "$(credential_v2_hkdf_hex "$seed" "$serial" otp/slot1/private-id 0 6)" b113b1bbcf13 "slot 1 private ID vector"
check "$(credential_v2_charset "$seed" "$serial" otp/slot1/static-password 38 "$alpha")" StbQ6pRq0RpwqupbtXxuXNCB0KZzeK7J0hgHhV "slot 1 static vector"
check "$(credential_v2_hkdf_hex "$seed" "$serial" otp/slot2/aes-key 0 16)" b411d90422958508219f8c8fabd8d310 "slot 2 AES vector"
check "$(credential_v2_hkdf_hex "$seed" "$serial" otp/slot2/private-id 0 6)" f315a7e09a78 "slot 2 private ID vector"
check "$(credential_v2_charset "$seed" "$serial" otp/slot2/static-password 38 "$alpha")" v5zTS3WNmVsBa3vvkliIb1M8jtzWgLcLlkFEeP "slot 2 static vector"
[[ "$(credential_v2_charset "$seed" "$serial" piv/pin 8 0123456789)" != "$(credential_v2_charset "$seed" "$serial" fido2/pin 8 0123456789)" ]] || fail "application labels collided"
printf 'ok - known-answer vectors for every credential artifact\n'

check "$(credential_v2_map_block f9fa00 0123456789 3)" 90 "numeric rejection boundary"
check "$(credential_v2_map_block f7f800 "$alpha" 3)" 9a "alphanumeric rejection boundary"
printf 'ok - deterministic rejection boundaries\n'

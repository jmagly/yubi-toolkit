#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT_DIR/yubi-lib.sh"
export PATH="$ROOT_DIR/tests/bin:$PATH"
export YUBI_TEST_YKMAN_VERSION=5.9.2

fail() { printf 'not ok - %s\n' "$1" >&2; exit 1; }
ok() { printf 'ok - %s\n' "$1"; }

openssl_hkdf_kat || fail "HKDF known-answer test"
ok "OpenSSL HKDF provider known-answer test"

for version in 5.4 5.5 5.6 5.7 5.8; do
    export YUBI_TEST_YKMAN_FIXTURE="$ROOT_DIR/tests/fixtures/ykman-firmware-${version}.out"
    yubikey_capability_preflight 12345678 >/dev/null || fail "firmware $version rejected"
done
export YUBI_TEST_YKMAN_FIXTURE="$ROOT_DIR/tests/fixtures/ykman-fips.out"
yubikey_capability_preflight 12345678 >/dev/null || fail "YubiKey 5 FIPS rejected"
ok "supported firmware and FIPS inventory"

for fixture in ykman-bio.out ykman-security-key.out ykman-malformed.out ykman-unknown-major.out ykman-disabled-piv.out; do
    export YUBI_TEST_YKMAN_FIXTURE="$ROOT_DIR/tests/fixtures/$fixture"
    if yubikey_capability_preflight 12345678 >/dev/null 2>&1; then
        fail "$fixture accepted"
    fi
done
ok "unsupported and malformed inventory fails closed"

export YUBI_TEST_YKMAN_FIXTURE="$ROOT_DIR/tests/fixtures/ykman-5.9.2-info.out"
report=$("$ROOT_DIR/yubi-doctor.sh" --json 12345678)
[[ "$report" == *'"overall":"ok"'* ]] || fail "doctor JSON overall"
[[ "$report" == *'"hkdf_kat":true'* ]] || fail "doctor JSON HKDF result"
[[ "$report" == *'"device":{"serial":"12345678","status":"supported"}'* ]] || fail "doctor JSON device result"
ok "machine-readable doctor"

export YUBI_TEST_YKMAN_VERSION=6.0.0
if ykman_supported_version; then fail "unknown ykman major accepted"; fi
ok "unknown ykman major fails closed"

#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT_DIR/yubi-lib.sh"

fail() { printf 'not ok - %s\n' "$1" >&2; exit 1; }
ok() { printf 'ok - %s\n' "$1"; }

command -v age >/dev/null 2>&1 || { printf 'ok - seed pool tests (skipped: age unavailable)\n'; exit 0; }
command -v age-keygen >/dev/null 2>&1 || fail "age-keygen unavailable"

TEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/yubi-pool-test.XXXXXX")
trap 'rm -rf "$TEST_DIR"' EXIT HUP INT TERM
SEED_DIR="$TEST_DIR/pools"
mkdir -m 700 "$SEED_DIR"
YUBI_SEED_IDENTITY="$TEST_DIR/identity"
age-keygen -o "$YUBI_SEED_IDENTITY" >/dev/null 2>&1
chmod 600 "$YUBI_SEED_IDENTITY"
YUBI_SEED_RECIPIENT=$(age-keygen -y "$YUBI_SEED_IDENTITY")
export YUBI_SEED_IDENTITY YUBI_SEED_RECIPIENT

plain="$TEST_DIR/plain"
printf 'alpha\nbeta\ngamma\n' > "$plain"
pool="$SEED_DIR/test.age"
seed_pool_encrypt_atomic "$plain" "$pool"
[[ $(file_perms "$pool") == 600 ]] || fail "ciphertext permissions"
out="$TEST_DIR/out"
seed_pool_decrypt "$pool" "$out"
cmp -s "$plain" "$out" || fail "round trip"
ok "authenticated encrypted round trip and permissions"

: > "$plain"
empty_pool="$SEED_DIR/empty.age"
seed_pool_encrypt_atomic "$plain" "$empty_pool"
seed_pool_decrypt "$empty_pool" "$out"
[[ ! -s "$out" ]] || fail "empty pool changed during round trip"
ok "empty pool round trip"

cp "$pool" "$TEST_DIR/good.age"
printf 'tamper' >> "$pool"
if seed_pool_decrypt "$pool" "$out" >/dev/null 2>&1; then
    fail "tampered ciphertext accepted"
fi
ok "authentication failure is closed"
mv "$TEST_DIR/good.age" "$pool"

ln -s "$pool" "$SEED_DIR/link.age"
if seed_pool_decrypt "$SEED_DIR/link.age" "$out" >/dev/null 2>&1; then
    fail "symlink accepted"
fi
ok "symlink rejected"

chmod 644 "$pool"
if seed_pool_decrypt "$pool" "$out" >/dev/null 2>&1; then
    fail "weak permissions accepted"
fi
chmod 600 "$pool"
ok "weak permissions rejected"

before=$(openssl dgst -sha256 "$pool")
bad_bin="$TEST_DIR/bin"
mkdir "$bad_bin"
printf '#!/usr/bin/env bash\nexit 9\n' > "$bad_bin/age"
chmod +x "$bad_bin/age"
if PATH="$bad_bin:$PATH" seed_pool_encrypt_atomic "$plain" "$pool" >/dev/null 2>&1; then
    fail "failed encryption reported success"
fi
after=$(openssl dgst -sha256 "$pool")
[[ "$before" == "$after" ]] || fail "failed update replaced active pool"
ok "interrupted update preserves prior ciphertext"

seed_pool_lock "$pool"
if (SEED_POOL_LOCK_DIR=""; seed_pool_lock "$pool") >/dev/null 2>&1; then
    fail "concurrent lock accepted"
fi
seed_pool_unlock
ok "concurrent pool update rejected"

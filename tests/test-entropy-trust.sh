#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT_DIR/yubi-lib.sh"
TEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/yubi-entropy-trust.XXXXXX")
trap 'rm -rf "$TEST_DIR"' EXIT HUP INT TERM

fail() { printf 'not ok - %s\n' "$1" >&2; exit 1; }

require_csprng || fail "working CSPRNG rejected"
if YUBI_CSPRNG_COMMAND=/bin/false require_csprng >/dev/null 2>&1; then
    fail "CSPRNG failure was not fatal"
fi
printf 'ok - mandatory CSPRNG success and fatal failure\n'

YUBI_TEST_X11_STATUS=available x11_available || fail "working X11 path rejected"
if YUBI_TEST_X11_STATUS=unavailable x11_available; then fail "unavailable X11 accepted"; fi
printf 'ok - working and unavailable X11 paths\n'

marker="$TEST_DIR/network-called"
mkdir "$TEST_DIR/bin"
printf '#!/usr/bin/env bash\nprintf called > "%s"\n' "$marker" > "$TEST_DIR/bin/curl"
chmod +x "$TEST_DIR/bin/curl"
for rejected_case in invalid-signature malformed oversized replay timeout; do
    if PATH="$TEST_DIR/bin:$PATH" call_external "$rejected_case" "https://example.invalid/$rejected_case" >/dev/null 2>&1; then
        fail "$rejected_case beacon input accepted"
    fi
done
[[ ! -e "$marker" ]] || fail "removed beacon path attempted network access"
printf 'ok - invalid, malformed, oversized, replay, and timeout beacon paths are removed\n'

legacy="$TEST_DIR/legacy.bin"
printf 'unverified-public-data\n' > "$legacy"
chmod 600 "$legacy"
if get_external_entropy --entropy-file "$legacy" >/dev/null 2>&1; then
    fail "legacy unverified beacon file accepted"
fi
printf 'ok - unverified external files fail closed\n'

provenance="$TEST_DIR/provenance.json"
write_entropy_provenance "$provenance"
grep -q '"secret_root":"platform-csprng"' "$provenance" || fail "CSPRNG provenance missing"
grep -q '"public_diversification":"disabled-unverified-beacons-removed"' "$provenance" || fail "beacon provenance missing"
[[ $(file_perms "$provenance") == 600 ]] || fail "provenance permissions"
printf 'ok - non-sensitive provenance is separate and permission restricted\n'

#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT_DIR/yubi-lib.sh"

fail() { printf 'not ok - %s\n' "$1" >&2; exit 1; }
ok() { printf 'ok - %s\n' "$1"; }

found_unsupported=false
for script in "$ROOT_DIR"/*.sh "$ROOT_DIR"/tests/*.sh; do
    [[ "$script" == "$ROOT_DIR/tests/test-bash32-compat.sh" ]] && continue
    if grep -En '(^|[[:space:]])(local|declare)[[:space:]]+-n|declare[[:space:]]+-A|mapfile|readarray|\$\{[^}]+,,|\$\{[^}]+\^\^' "$script"; then
        found_unsupported=true
    fi
done
if [[ "$found_unsupported" == true ]]; then
    fail "Bash 4+ construct found"
fi
ok "no known Bash 4+ constructs"

input=(alpha beta gamma delta)
shuffle_values "${input[@]}"
[[ ${#SHUFFLED_VALUES[@]} -eq ${#input[@]} ]] || fail "shuffle changed element count"
for expected in "${input[@]}"; do
    found=false
    for actual in "${SHUFFLED_VALUES[@]}"; do
        [[ "$actual" == "$expected" ]] && found=true
    done
    [[ "$found" == true ]] || fail "shuffle lost $expected"
done
ok "Bash 3.2-compatible shuffle runtime"

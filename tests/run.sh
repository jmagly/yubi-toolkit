#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

printf '==> Bash syntax\n'
for script in ./*.sh tests/*.sh tests/bin/*; do
    [[ -f "$script" ]] || continue
    bash -n "$script"
done

printf '==> ShellCheck error gate\n'
if ! command -v shellcheck >/dev/null 2>&1; then
    printf 'shellcheck is required\n' >&2
    exit 1
fi
shellcheck -x -S error ./*.sh tests/*.sh tests/bin/*

printf '==> Unit and integration tests\n'
for test_script in tests/test-*.sh; do
    printf '%s\n' "--- $test_script"
    bash "$test_script"
done

printf 'All non-hardware tests passed.\n'

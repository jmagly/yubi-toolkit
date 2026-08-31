#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT_DIR/yubi-lib.sh"

fail() { printf 'not ok - %s\n' "$1" >&2; exit 1; }
ok() { printf 'ok - %s\n' "$1"; }

test_parent_state_and_cleanup() {
    local allow_disk=false
    [[ "$_IS_MACOS" == "true" ]] && allow_disk=true
    secure_tmpfs_create "yubi-test-parent" 1 "$allow_disk"
    local created="$SECURE_TMPFS_DIR"
    [[ -n "$created" && -d "$created" ]] || fail "allocator did not set parent state"
    if [[ "$allow_disk" == "false" ]]; then
        [[ "$SECURE_TMPFS_KIND" == *tmpfs ]] || fail "allocator did not verify tmpfs"
    fi
    secure_tmpfs_cleanup
    [[ ! -e "$created" ]] || fail "cleanup left workspace behind"
    [[ -z "$SECURE_TMPFS_DIR" ]] || fail "cleanup did not reset state"
    secure_tmpfs_cleanup
    ok "parent state and idempotent cleanup"
}

test_signal_cleanup() {
    local signal_name="$1"
    local state_file child created
    state_file=$(mktemp)
    (
        source "$ROOT_DIR/yubi-lib.sh"
        cleanup_child() {
            child_status=$?
            trap - EXIT
            secure_tmpfs_cleanup || true
            exit "$child_status"
        }
        trap cleanup_child EXIT
        trap 'exit 129' HUP
        trap 'exit 130' INT
        trap 'exit 143' TERM
        secure_tmpfs_create "yubi-test-signal" 1 "${ALLOW_DISK:-false}"
        printf '%s\n' "$SECURE_TMPFS_DIR" > "$state_file"
        while :; do sleep 1; done
    ) &
    child=$!
    for _attempt in 1 2 3 4 5; do
        [[ -s "$state_file" ]] && break
        sleep 1
    done
    [[ -s "$state_file" ]] || fail "signal child did not allocate workspace"
    created=$(sed -n '1p' "$state_file")
    kill -"$signal_name" "$child"
    wait "$child" 2>/dev/null || true
    rm -f "$state_file"
    [[ ! -e "$created" ]] || fail "$signal_name left workspace behind"
    ok "$signal_name cleanup"
}

test_interrupt_cleanup() {
    local state_file created
    state_file=$(mktemp)
    if ! command -v timeout >/dev/null 2>&1; then
        ok "INT cleanup (skipped: timeout unavailable)"
        rm -f "$state_file"
        return
    fi
    ROOT_DIR="$ROOT_DIR" STATE_FILE="$state_file" ALLOW_DISK="${ALLOW_DISK:-false}" timeout --signal=INT 1 bash -c '
        set -euo pipefail
        source "$ROOT_DIR/yubi-lib.sh"
        cleanup_child() {
            child_status=$?
            trap - EXIT
            secure_tmpfs_cleanup || true
            exit "$child_status"
        }
        trap cleanup_child EXIT
        trap "exit 130" INT
        secure_tmpfs_create "yubi-test-int" 1 "$ALLOW_DISK"
        printf "%s\n" "$SECURE_TMPFS_DIR" > "$STATE_FILE"
        sleep 30
    ' >/dev/null 2>&1 || true
    [[ -s "$state_file" ]] || fail "INT child did not allocate workspace"
    created=$(sed -n '1p' "$state_file")
    rm -f "$state_file"
    [[ ! -e "$created" ]] || fail "INT left workspace behind"
    ok "INT cleanup"
}

test_persistent_fallback_is_explicit() {
    local saved_is_macos="$_IS_MACOS"
    _IS_MACOS=true
    if secure_tmpfs_create "yubi-test-refuse" 1 false 2>/dev/null; then
        fail "allocator accepted implicit persistent fallback"
    fi
    secure_tmpfs_create "yubi-test-override" 1 true >/dev/null 2>&1
    [[ "$SECURE_TMPFS_KIND" == "persistent-override" ]] || fail "explicit override was not recorded"
    secure_tmpfs_cleanup >/dev/null
    _IS_MACOS="$saved_is_macos"
    ok "persistent fallback requires opt-in"
}

if [[ "$_IS_MACOS" == "true" ]]; then
    ALLOW_DISK=true
    export ALLOW_DISK
fi

test_parent_state_and_cleanup
test_signal_cleanup HUP
test_interrupt_cleanup
test_signal_cleanup TERM
test_persistent_fallback_is_explicit

#!/usr/bin/env bash
# yubi-lib.sh — Shared library for YubiKey entropy toolkit
#
# Source this file from other scripts:
#   source "$(dirname "${BASH_SOURCE[0]}")/yubi-lib.sh"

# =============================================================================
# Logging
# =============================================================================

RED='\033[0;31m'
YLW='\033[0;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
DIM='\033[2m'
RST='\033[0m'

log_info()  { printf "${CYN}[INFO]${RST}  %s\n" "$*"; }
log_ok()    { printf "${GRN}[OK]${RST}    %s\n" "$*"; }
log_warn()  { printf "${YLW}[WARN]${RST}  %s\n" "$*"; }
log_err()   { printf "${RED}[ERR]${RST}   %s\n" "$*" >&2; }

# =============================================================================
# Process hardening
# =============================================================================

# Call at script entry to prevent secret leaks via core dumps
harden_process() {
    umask 077       # New files owner-only (no group/world read)
    ulimit -c 0     # Disable core dumps (prevents secret material on disk)
}

# =============================================================================
# OpenSSL version check
# =============================================================================

require_openssl3() {
    if ! command -v openssl &>/dev/null; then
        log_err "openssl not found"
        exit 1
    fi
    local ver
    ver=$(openssl version | awk '{print $2}')
    local major="${ver%%.*}"
    if [[ "$major" -lt 3 ]]; then
        log_err "OpenSSL 3.0+ required (found: $ver) — 'openssl kdf' unavailable on 1.x"
        exit 1
    fi
}

# =============================================================================
# Serial number validation
# =============================================================================

validate_serial() {
    local serial="$1"
    if ! [[ "$serial" =~ ^[0-9]+$ ]]; then
        log_err "Invalid serial number: $serial (must be numeric)"
        exit 1
    fi
}

# =============================================================================
# Mode validation
# =============================================================================

validate_mode() {
    local mode="$1"
    if [[ "$mode" != "otp" && "$mode" != "static" && "$mode" != "mixed" ]]; then
        log_err "Invalid mode: $mode (must be 'otp', 'static', or 'mixed')"
        exit 1
    fi
}

# =============================================================================
# Secure file deletion
# =============================================================================
#
# SSD + journaled filesystem (ext4, btrfs) means shred alone is insufficient:
#   - SSD FTL retains old block copies (wear leveling)
#   - ext4 journal may hold data copies
#   - LVM snapshots can preserve old data
#
# Strategy (defense in depth):
#   1. Overwrite file content 3x with random data (defeats casual recovery)
#   2. Overwrite once with zeros (clean slate)
#   3. fsync to push to controller
#   4. Unlink the file
#   5. If root: fstrim the mount to TRIM freed SSD blocks
#
# For truly sensitive operations, use secure_tmpfs_create() which puts
# files in RAM (tmpfs) so they never touch persistent storage.

secure_delete() {
    local file="$1"
    local verbose="${2:-false}"

    if [[ ! -f "$file" ]]; then
        return 0
    fi

    local filesize
    filesize=$(stat -c%s "$file" 2>/dev/null || echo "0")

    # Pass 1-3: overwrite with random data
    for pass in 1 2 3; do
        dd if=/dev/urandom of="$file" bs=4096 count=$(( (filesize / 4096) + 1 )) \
            conv=notrunc 2>/dev/null
    done

    # Pass 4: zero fill
    dd if=/dev/zero of="$file" bs=4096 count=$(( (filesize / 4096) + 1 )) \
        conv=notrunc 2>/dev/null

    # Sync to push through caches to controller
    sync "$file" 2>/dev/null

    # Resolve mount point BEFORE deleting (df fails on deleted paths)
    local mount_point=""
    if [[ $EUID -eq 0 ]]; then
        mount_point=$(df --output=target "$file" 2>/dev/null | tail -1)
    fi

    # Remove
    rm -f "$file"

    # If we can fstrim (root), TRIM freed SSD blocks
    if [[ $EUID -eq 0 && -n "$mount_point" ]]; then
        fstrim "$mount_point" 2>/dev/null || true
    fi

    [[ "$verbose" == "true" ]] && log_ok "Secure deleted: $(basename "$file")"
    return 0
}

# Securely delete all files in a directory, then remove the directory
secure_delete_dir() {
    local dir="$1"
    local verbose="${2:-false}"

    if [[ ! -d "$dir" ]]; then
        return 0
    fi

    find "$dir" -type f | while IFS= read -r f; do
        secure_delete "$f" "$verbose"
    done

    rm -rf "$dir"
}

# =============================================================================
# Secure tmpfs workspace (RAM-backed, never hits disk)
# =============================================================================
#
# Creates a tmpfs mount for sensitive working files.
# Falls back to regular tmpdir if not root (can't mount).
# Either way, secure_delete is used on cleanup.

SECURE_TMPFS_DIR=""
SECURE_TMPFS_MOUNTED=false

secure_tmpfs_create() {
    local label="${1:-yubi-work}"
    local size_mb="${2:-16}"

    SECURE_TMPFS_DIR=$(mktemp -d "/tmp/${label}.XXXXXX")
    chmod 700 "$SECURE_TMPFS_DIR"

    if [[ $EUID -eq 0 ]]; then
        if mount -t tmpfs -o size=${size_mb}m,mode=700 tmpfs "$SECURE_TMPFS_DIR" 2>/dev/null; then
            SECURE_TMPFS_MOUNTED=true
            log_ok "Secure workspace: tmpfs (RAM-backed, ${size_mb}MB)" >&2
        fi
    fi

    if [[ "$SECURE_TMPFS_MOUNTED" == "false" ]]; then
        log_info "Secure workspace: $SECURE_TMPFS_DIR (disk-backed, will secure-delete)" >&2
    fi

    echo "$SECURE_TMPFS_DIR"
}

secure_tmpfs_cleanup() {
    if [[ -z "$SECURE_TMPFS_DIR" || ! -d "$SECURE_TMPFS_DIR" ]]; then
        return 0
    fi

    if [[ "$SECURE_TMPFS_MOUNTED" == "true" ]]; then
        # tmpfs: just unmount — RAM is gone
        umount "$SECURE_TMPFS_DIR" 2>/dev/null
        rmdir "$SECURE_TMPFS_DIR" 2>/dev/null
        log_ok "Secure workspace unmounted (RAM released)"
    else
        # Disk-backed: secure delete everything
        secure_delete_dir "$SECURE_TMPFS_DIR" false
        log_ok "Secure workspace wiped and removed"
    fi

    SECURE_TMPFS_DIR=""
    SECURE_TMPFS_MOUNTED=false
}

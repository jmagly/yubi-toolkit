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

# =============================================================================
# External entropy: shared fetch with retry+degrade
# =============================================================================
#
# Consolidated from bootstrap-entropy.sh, entropy-mix.sh, and init-yubi.sh.
# All three scripts previously had identical call_external() implementations.

ENTROPY_RETRY_MAX=3
ENTROPY_RETRY_DELAY=2

# Fetch from an external URL with retry and graceful degradation.
# Usage: call_external <name> <curl_args...>
# Returns: response on stdout, exit 0 on success, exit 1 on failure
call_external() {
    local name="$1"; shift
    local attempt=0
    local response=""
    while (( attempt < ENTROPY_RETRY_MAX )); do
        attempt=$(( attempt + 1 ))
        response=$(curl -sf --max-time 10 "$@" 2>/dev/null) && break
        log_warn "$name: attempt $attempt/$ENTROPY_RETRY_MAX failed"
        sleep "$ENTROPY_RETRY_DELAY"
        response=""
    done
    if [[ -z "$response" ]]; then
        log_warn "$name: ALL RETRIES FAILED — degrading"
        echo ""; return 1
    fi
    echo "$response"; return 0
}

# Fetch all three external entropy sources. Sets EXT_RANDOM_ORG, EXT_NIST,
# EXT_DRAND variables and EXT_SOURCES_OK count.
# Usage: fetch_all_external_entropy
fetch_all_external_entropy() {
    EXT_RANDOM_ORG=""
    EXT_NIST=""
    EXT_DRAND=""
    EXT_SOURCES_OK=0

    log_info "Fetching random.org..."
    if EXT_RANDOM_ORG=$(call_external "random.org" \
        "https://www.random.org/integers/?num=10&min=0&max=1000000000&col=1&base=10&format=plain&rnd=new"); then
        log_ok "random.org"
        EXT_SOURCES_OK=$(( EXT_SOURCES_OK + 1 ))
    fi

    log_info "Fetching NIST Beacon..."
    if EXT_NIST=$(call_external "NIST Beacon" \
        "https://beacon.nist.gov/beacon/2.0/pulse/last"); then
        log_ok "NIST Beacon"
        EXT_SOURCES_OK=$(( EXT_SOURCES_OK + 1 ))
    fi

    log_info "Fetching drand..."
    if EXT_DRAND=$(call_external "drand" \
        "https://drand.cloudflare.com/public/latest"); then
        log_ok "drand"
        EXT_SOURCES_OK=$(( EXT_SOURCES_OK + 1 ))
    fi

    log_info "External sources: $EXT_SOURCES_OK/3"
}

# =============================================================================
# Entropy file format: portable external entropy for air-gapped workflows
# =============================================================================
#
# File format (text-based, inspectable with cat/grep/head):
#
#   YUBI-ENTROPY-V1
#   SOURCE:<source_id>
#   TIME:<iso8601_timestamp>
#   HASH:<sha256_hex>
#   SIZE:<byte_count>
#   DATA:<base64_encoded_data>
#   END
#   SOURCE:<source_id>
#   ...
#
# Source IDs: random.org, nist, drand

ENTROPY_FILE_MAGIC="YUBI-ENTROPY-V1"

# Write a single entropy block to an entropy file.
# Usage: write_entropy_block <file> <source_id> <raw_data>
write_entropy_block() {
    local file="$1"
    local source_id="$2"
    local raw_data="$3"

    if [[ -z "$raw_data" ]]; then
        return 1
    fi

    local timestamp
    timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    local b64_data
    b64_data=$(printf '%s' "$raw_data" | openssl base64 -A)
    local byte_count=${#raw_data}
    local hash
    hash=$(printf '%s' "$raw_data" | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}')

    {
        printf 'SOURCE:%s\n' "$source_id"
        printf 'TIME:%s\n' "$timestamp"
        printf 'HASH:%s\n' "$hash"
        printf 'SIZE:%d\n' "$byte_count"
        printf 'DATA:%s\n' "$b64_data"
        printf 'END\n'
    } >> "$file"
}

# Initialize a new entropy file with magic header.
# Usage: init_entropy_file <file>
init_entropy_file() {
    local file="$1"
    printf '%s\n' "$ENTROPY_FILE_MAGIC" > "$file"
    chmod 600 "$file"
}

# Validate an entropy file's structure and integrity.
# Usage: validate_entropy_file <file>
# Returns: 0 if valid, 1 if invalid. Prints diagnostics to stderr.
validate_entropy_file() {
    local file="$1"

    if [[ ! -f "$file" ]]; then
        log_err "Entropy file not found: $file"
        return 1
    fi

    # Check magic header
    local header
    header=$(head -1 "$file")
    if [[ "$header" != "$ENTROPY_FILE_MAGIC" ]]; then
        log_err "Invalid entropy file: bad magic header (expected $ENTROPY_FILE_MAGIC)"
        return 1
    fi

    # Check file permissions
    local perms
    perms=$(stat -c '%a' "$file" 2>/dev/null)
    if [[ "$perms" != "600" ]]; then
        log_warn "Entropy file permissions are $perms (recommended: 600)"
    fi

    # Parse and validate blocks
    local block_count=0
    local corrupt=0
    local in_block=false
    local cur_source="" cur_hash="" cur_data="" cur_size=""

    while IFS= read -r line; do
        case "$line" in
            SOURCE:*)
                in_block=true
                cur_source="${line#SOURCE:}"
                cur_hash="" cur_data="" cur_size=""
                ;;
            HASH:*)
                cur_hash="${line#HASH:}"
                ;;
            SIZE:*)
                cur_size="${line#SIZE:}"
                ;;
            DATA:*)
                cur_data="${line#DATA:}"
                ;;
            END)
                if [[ "$in_block" == "true" && -n "$cur_data" && -n "$cur_hash" ]]; then
                    # Verify hash
                    local decoded
                    decoded=$(printf '%s' "$cur_data" | openssl base64 -d -A 2>/dev/null)
                    local computed_hash
                    computed_hash=$(printf '%s' "$decoded" | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}')
                    if [[ "$computed_hash" == "$cur_hash" ]]; then
                        block_count=$(( block_count + 1 ))
                    else
                        log_err "Block $cur_source: hash mismatch (expected $cur_hash, got $computed_hash)"
                        corrupt=$(( corrupt + 1 ))
                    fi
                fi
                in_block=false
                ;;
        esac
    done < "$file"

    if [[ $block_count -eq 0 ]]; then
        log_err "Entropy file contains no valid blocks"
        return 1
    fi

    if [[ $corrupt -gt 0 ]]; then
        log_err "$corrupt block(s) failed integrity check"
        return 1
    fi

    return 0
}

# Extract entropy for a specific source from an entropy file.
# Concatenates all blocks for that source (multiple collections = more entropy).
# Usage: extract_source_entropy <file> <source_id>
# Returns: raw concatenated data on stdout
extract_source_entropy() {
    local file="$1"
    local source_id="$2"
    local result=""
    local in_target=false

    while IFS= read -r line; do
        case "$line" in
            SOURCE:${source_id})
                in_target=true
                ;;
            SOURCE:*)
                in_target=false
                ;;
            DATA:*)
                if [[ "$in_target" == "true" ]]; then
                    local decoded
                    decoded=$(printf '%s' "${line#DATA:}" | openssl base64 -d -A 2>/dev/null)
                    result+="$decoded"
                fi
                ;;
            END)
                in_target=false
                ;;
        esac
    done < "$file"

    printf '%s' "$result"
}

# Load external entropy from a pre-collected file into EXT_RANDOM_ORG,
# EXT_NIST, EXT_DRAND variables (same interface as fetch_all_external_entropy).
# Usage: load_external_entropy <file>
load_external_entropy() {
    local file="$1"
    EXT_RANDOM_ORG=""
    EXT_NIST=""
    EXT_DRAND=""
    EXT_SOURCES_OK=0

    if ! validate_entropy_file "$file"; then
        return 1
    fi

    EXT_RANDOM_ORG=$(extract_source_entropy "$file" "random.org")
    if [[ -n "$EXT_RANDOM_ORG" ]]; then
        log_ok "Loaded random.org entropy from file"
        EXT_SOURCES_OK=$(( EXT_SOURCES_OK + 1 ))
    fi

    EXT_NIST=$(extract_source_entropy "$file" "nist")
    if [[ -n "$EXT_NIST" ]]; then
        log_ok "Loaded NIST Beacon entropy from file"
        EXT_SOURCES_OK=$(( EXT_SOURCES_OK + 1 ))
    fi

    EXT_DRAND=$(extract_source_entropy "$file" "drand")
    if [[ -n "$EXT_DRAND" ]]; then
        log_ok "Loaded drand entropy from file"
        EXT_SOURCES_OK=$(( EXT_SOURCES_OK + 1 ))
    fi

    log_info "Loaded $EXT_SOURCES_OK/3 sources from entropy file"
}

# Dispatcher: get external entropy from the appropriate source.
# Usage: get_external_entropy [--no-external] [--entropy-file <path>]
#   Sets EXT_RANDOM_ORG, EXT_NIST, EXT_DRAND, EXT_SOURCES_OK
get_external_entropy() {
    local no_external=false
    local entropy_file=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --no-external) no_external=true; shift ;;
            --entropy-file) entropy_file="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    if [[ "$no_external" == "true" ]]; then
        EXT_RANDOM_ORG=""
        EXT_NIST=""
        EXT_DRAND=""
        EXT_SOURCES_OK=0
        log_info "External entropy: disabled (--no-external)"
        return 0
    fi

    if [[ -n "$entropy_file" ]]; then
        log_info "Loading external entropy from file: $entropy_file"
        load_external_entropy "$entropy_file"
        return 0
    fi

    # Default: live API fetch
    fetch_all_external_entropy
    return 0
}

# Report entropy file contents (for entropy-verify).
# Usage: report_entropy_file <file>
report_entropy_file() {
    local file="$1"
    local block_count=0
    local sources=()
    local earliest="" latest=""
    local total_size=0

    while IFS= read -r line; do
        case "$line" in
            SOURCE:*)
                local src="${line#SOURCE:}"
                # Track unique sources
                local found=false
                for s in "${sources[@]+"${sources[@]}"}"; do
                    [[ "$s" == "$src" ]] && found=true
                done
                [[ "$found" == "false" ]] && sources+=("$src")
                ;;
            TIME:*)
                local ts="${line#TIME:}"
                if [[ -z "$earliest" || "$ts" < "$earliest" ]]; then
                    earliest="$ts"
                fi
                if [[ -z "$latest" || "$ts" > "$latest" ]]; then
                    latest="$ts"
                fi
                ;;
            SIZE:*)
                total_size=$(( total_size + ${line#SIZE:} ))
                ;;
            END)
                block_count=$(( block_count + 1 ))
                ;;
        esac
    done < "$file"

    echo ""
    log_info "Entropy file: $(basename "$file")"
    log_info "Blocks:       $block_count"
    log_info "Sources:      ${sources[*]+"${sources[*]}"}"
    log_info "Total size:   $total_size bytes"
    log_info "Time range:   ${earliest:-n/a} — ${latest:-n/a}"

    # Staleness check
    if [[ -n "$latest" ]]; then
        local latest_epoch
        latest_epoch=$(date -d "$latest" +%s 2>/dev/null || echo 0)
        local now_epoch
        now_epoch=$(date +%s)
        local age_days=$(( (now_epoch - latest_epoch) / 86400 ))
        if [[ $age_days -gt 30 ]]; then
            log_warn "All blocks are >30 days old — consider collecting fresh entropy"
        fi
    fi
}

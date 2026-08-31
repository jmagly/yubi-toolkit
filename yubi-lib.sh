#!/usr/bin/env bash
# yubi-lib.sh — Shared library for YubiKey entropy toolkit
#
# Source this file from other scripts:
#   source "$(dirname "${BASH_SOURCE[0]}")/yubi-lib.sh"

# =============================================================================
# Platform detection and PATH bootstrap
# =============================================================================
#
# Linux: GNU coreutils, OpenSSL 3.x at /usr/bin/openssl, /sys/class/thermal,
#        lm-sensors, fstrim — all expected on PATH.
# macOS: BSD coreutils (no `stat -c`, no `date +%s%N`, no `date -d`),
#        /usr/bin/openssl is LibreSSL (no `openssl kdf`), no /sys/class/thermal,
#        no lm-sensors, no fstrim. brew openssl@3 + ykman expected via Homebrew.
#
# We prepend Homebrew prefixes to PATH so `openssl` resolves to OpenSSL 3.x and
# `ykman` is found, then provide portable wrappers for stat/date/thermal.

case "$(uname -s 2>/dev/null)" in
    Darwin) _IS_MACOS=true ;;
    *)      _IS_MACOS=false ;;
esac

if [[ "$_IS_MACOS" == "true" ]]; then
    # Prefer brew openssl@3 over LibreSSL at /usr/bin/openssl
    for _brew_prefix in /opt/homebrew/opt/openssl@3/bin /usr/local/opt/openssl@3/bin \
                        /opt/homebrew/bin /usr/local/bin; do
        if [[ -d "$_brew_prefix" ]]; then
            case ":$PATH:" in
                *":$_brew_prefix:"*) ;;
                *) PATH="$_brew_prefix:$PATH" ;;
            esac
        fi
    done
    unset _brew_prefix
    export PATH
fi

# =============================================================================
# Portable wrappers (GNU vs BSD coreutils)
# =============================================================================

# Nanosecond-resolution timestamp. macOS `date` lacks %N; fall back to python3.
now_ns() {
    if [[ "$_IS_MACOS" == "true" ]]; then
        python3 -c 'import time; print(time.time_ns())'
    else
        date +%s%N
    fi
}

# File size in bytes.
file_size() {
    if [[ "$_IS_MACOS" == "true" ]]; then
        stat -f%z "$1" 2>/dev/null || echo 0
    else
        stat -c%s "$1" 2>/dev/null || echo 0
    fi
}

# File permissions as octal (e.g. 600).
file_perms() {
    if [[ "$_IS_MACOS" == "true" ]]; then
        stat -f%A "$1" 2>/dev/null
    else
        stat -c%a "$1" 2>/dev/null
    fi
}

# File modification time as "YYYY-MM-DD HH:MM:SS".
file_mtime() {
    if [[ "$_IS_MACOS" == "true" ]]; then
        stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "$1" 2>/dev/null
    else
        stat -c '%y' "$1" 2>/dev/null | cut -d. -f1
    fi
}

# Mount point hosting <path>.
df_target() {
    if [[ "$_IS_MACOS" == "true" ]]; then
        df "$1" 2>/dev/null | awk 'NR==2 {print $NF}'
    else
        df --output=target "$1" 2>/dev/null | tail -1
    fi
}

# Convert ISO8601 timestamp (YYYY-MM-DDTHH:MM:SSZ) to epoch seconds.
iso_to_epoch() {
    local iso="$1"
    if [[ "$_IS_MACOS" == "true" ]]; then
        date -j -u -f '%Y-%m-%dT%H:%M:%SZ' "$iso" +%s 2>/dev/null || echo 0
    else
        date -d "$iso" +%s 2>/dev/null || echo 0
    fi
}

# OS-appropriate "thermal/system" entropy snapshot. Output is a hash-friendly
# blob of changing kernel/system data — used as a salt component, not as
# primary entropy. On Linux: thermal zones + lm-sensors. On macOS: sysctl
# state + vm_stat + ioreg power/thermal nodes (all change frequently).
system_thermal_entropy() {
    if [[ "$_IS_MACOS" == "true" ]]; then
        {
            sysctl -a 2>/dev/null | grep -E '(machdep\.cpu|hw\.|kern\.boottime|vm\.loadavg|hw\.cpufrequency)' || true
            vm_stat 2>/dev/null || true
            ioreg -l -w0 -c IOPMrootDomain 2>/dev/null | head -200 || true
            ioreg -l -w0 -c AppleSmartBattery 2>/dev/null | head -100 || true
        } | tr -d ' \n'
    else
        {
            for tz in /sys/class/thermal/thermal_zone*/temp; do
                [[ -f "$tz" ]] && cat "$tz"
            done
            sensors -u 2>/dev/null || true
        } | tr -d ' \n'
    fi
}

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
    local raw ver major flavor
    raw=$(openssl version)
    flavor=$(echo "$raw" | awk '{print $1}')
    ver=$(echo "$raw" | awk '{print $2}')
    major="${ver%%.*}"

    # LibreSSL (Apple's /usr/bin/openssl) lacks the `kdf` subcommand entirely.
    if [[ "$flavor" == "LibreSSL" ]]; then
        log_err "LibreSSL detected ($raw) — 'openssl kdf' is unavailable."
        if [[ "$_IS_MACOS" == "true" ]]; then
            log_err "Install OpenSSL 3.x via Homebrew: brew install openssl@3"
            log_err "(yubi-lib.sh prepends Homebrew paths automatically)"
        fi
        exit 1
    fi

    if [[ "$major" -lt 3 ]]; then
        log_err "OpenSSL 3.0+ required (found: $ver) — 'openssl kdf' unavailable on 1.x"
        exit 1
    fi
}

openssl_hkdf_kat() {
    local output expected
    expected="8a343ebf7af154aef74eb9befa06127aefc81ce04df181d10ceca10853eda9ec0255f649fa8f7f6e9e66"
    output=$(openssl kdf -keylen 42 \
        -kdfopt digest:SHA256 \
        -kdfopt hexkey:0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b \
        -kdfopt hexsalt:000102030405060708090a0b0c \
        -kdfopt hexinfo:f0f1f2f3f4f5f6f7f8f9 HKDF 2>/dev/null \
        | tr -d ':' | tr '[:upper:]' '[:lower:]') || return 1
    [[ "$output" == "$expected" ]]
}

# YUBI-CRED-V2 derivation. Text framing is ASCII decimal-length-prefixed so
# field boundaries are unambiguous and portable across OpenSSL providers.
credential_v2_hkdf_hex() {
    local seed_b64="$1" serial="$2" purpose="$3" counter="$4" length="$5"
    local suite="YUBI-CRED-V2" salt info ikm_hex salt_hex info_hex
    salt="${#suite}:$suite|serial:${#serial}:$serial"
    info="suite:${#suite}:$suite|purpose:${#purpose}:$purpose|counter:8:$(printf '%08x' "$counter")"
    ikm_hex=$(printf '%s' "$seed_b64" | openssl base64 -d -A | xxd -p | tr -d '\n')
    salt_hex=$(printf '%s' "$salt" | xxd -p | tr -d '\n')
    info_hex=$(printf '%s' "$info" | xxd -p | tr -d '\n')
    openssl kdf -keylen "$length" -kdfopt digest:SHA256 \
        -kdfopt "hexkey:$ikm_hex" -kdfopt "hexsalt:$salt_hex" \
        -kdfopt "hexinfo:$info_hex" HKDF 2>/dev/null \
        | tr -d ':' | tr '[:upper:]' '[:lower:]'
}

credential_v2_charset() {
    local seed_b64="$1" serial="$2" purpose="$3" length="$4" alphabet="$5"
    local counter=0 output="" block mapped remaining
    while [[ ${#output} -lt $length ]]; do
        block=$(credential_v2_hkdf_hex "$seed_b64" "$serial" "$purpose" "$counter" 64) || return 1
        counter=$(( counter + 1 ))
        remaining=$(( length - ${#output} ))
        mapped=$(credential_v2_map_block "$block" "$alphabet" "$remaining")
        output+="$mapped"
    done
    printf '%s' "$output"
}

credential_v2_map_block() {
    local block="$1" alphabet="$2" max_length="$3" output=""
    local alphabet_len=${#alphabet} threshold byte_hex byte_dec index
    threshold=$(( (256 / alphabet_len) * alphabet_len ))
    while [[ -n "$block" && ${#output} -lt $max_length ]]; do
        byte_hex="${block:0:2}"
        block="${block:2}"
        byte_dec=$((16#$byte_hex))
        if [[ "$byte_dec" -lt "$threshold" ]]; then
            index=$(( byte_dec % alphabet_len ))
            output+="${alphabet:$index:1}"
        fi
    done
    printf '%s' "$output"
}

version_triplet() {
    local value="$1"
    [[ "$value" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || return 1
    VERSION_MAJOR="${BASH_REMATCH[1]}"
    VERSION_MINOR="${BASH_REMATCH[2]}"
    VERSION_PATCH="${BASH_REMATCH[3]}"
}

ykman_supported_version() {
    local raw version
    raw=$(ykman --version 2>/dev/null) || return 1
    version=$(printf '%s\n' "$raw" | sed -n 's/.*version: \([0-9][0-9.]*\).*/\1/p')
    version_triplet "$version" || return 1
    [[ "$VERSION_MAJOR" -eq 5 && "$VERSION_MINOR" -ge 5 && "$VERSION_MINOR" -le 9 ]]
}

# Inventory a target without mutating it. Exports DEVICE_* fields on success.
yubikey_capability_preflight() {
    local serial="$1" info
    validate_serial "$serial"
    ykman_supported_version || { log_err "Supported ykman range is 5.5.x through 5.9.x"; return 1; }
    info=$(ykman -d "$serial" info 2>/dev/null) || { log_err "Unable to inventory YubiKey $serial"; return 1; }
    DEVICE_TYPE=$(printf '%s\n' "$info" | sed -n 's/^Device type: //p')
    DEVICE_FIRMWARE=$(printf '%s\n' "$info" | sed -n 's/^Firmware version: //p')
    DEVICE_INTERFACES=$(printf '%s\n' "$info" | sed -n 's/^Enabled USB interfaces: //p')
    [[ -n "$DEVICE_TYPE" && -n "$DEVICE_FIRMWARE" && -n "$DEVICE_INTERFACES" ]] || {
        log_err "Malformed or incomplete ykman device inventory"; return 1;
    }
    case "$DEVICE_TYPE" in
        "YubiKey 5"*) ;;
        *) log_err "Unsupported or ambiguous product: $DEVICE_TYPE"; return 1 ;;
    esac
    version_triplet "$DEVICE_FIRMWARE" || { log_err "Malformed firmware version: $DEVICE_FIRMWARE"; return 1; }
    [[ "$VERSION_MAJOR" -eq 5 && "$VERSION_MINOR" -ge 4 && "$VERSION_MINOR" -le 8 ]] || {
        log_err "Supported firmware range is YubiKey 5.4.x through 5.8.x"; return 1;
    }
    DEVICE_FW_MAJOR="$VERSION_MAJOR"
    DEVICE_FW_MINOR="$VERSION_MINOR"
    DEVICE_FW_PATCH="$VERSION_PATCH"
    case ",$DEVICE_INTERFACES," in
        *,OTP,*CCID,*|*,CCID,*OTP,*) ;;
        *) log_err "Required OTP and CCID interfaces are not enabled"; return 1 ;;
    esac
    for application in "Yubico OTP" PIV FIDO2; do
        printf '%s\n' "$info" | grep -Eq "^${application}[[:space:]]+Enabled$" || {
            log_err "Required application is absent or disabled: $application"; return 1;
        }
    done
    export DEVICE_TYPE DEVICE_FIRMWARE DEVICE_INTERFACES DEVICE_FW_MAJOR DEVICE_FW_MINOR DEVICE_FW_PATCH
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

# Shuffle positional values without namerefs (which require Bash 4.3+).
# Results are returned in a global indexed array for Apple's Bash 3.2.
shuffle_values() {
    SHUFFLED_VALUES=("$@")
    local n=${#SHUFFLED_VALUES[@]}
    local i j tmp random_word
    for (( i=n-1; i>0; i-- )); do
        random_word=$(od -An -tu4 -N4 /dev/urandom | tr -d ' ')
        j=$(( random_word % (i + 1) ))
        tmp="${SHUFFLED_VALUES[$i]}"
        SHUFFLED_VALUES[$i]="${SHUFFLED_VALUES[$j]}"
        SHUFFLED_VALUES[$j]="$tmp"
    done
}

# =============================================================================
# File removal
# =============================================================================
#
# SSD + journaled filesystem (ext4, btrfs) means shred alone is insufficient:
#   - SSD FTL retains old block copies (wear leveling)
#   - ext4 journal may hold data copies
#   - LVM snapshots can preserve old data
#
# Overwriting cannot guarantee sanitization on modern storage. Sensitive
# plaintext belongs in a verified volatile workspace; this helper provides
# best-effort removal only.

secure_delete() {
    local file="$1"
    local verbose="${2:-false}"

    if [[ ! -f "$file" ]]; then
        return 0
    fi

    rm -f "$file"

    [[ "$verbose" == "true" ]] && log_ok "Removed: $(basename "$file") (sanitization is not guaranteed)"
    return 0
}

# =============================================================================
# Authenticated persistent seed pools (age)
# =============================================================================

seed_pool_validate_file() {
    local pool="$1"
    [[ ! -L "$pool" ]] || { log_err "Refusing symlinked seed pool: $pool"; return 1; }
    [[ -f "$pool" ]] || { log_err "Seed pool is not a regular file: $pool"; return 1; }
    local perms
    perms=$(file_perms "$pool")
    [[ "$perms" == "600" ]] || { log_err "Seed pool permissions must be 600 (found $perms): $pool"; return 1; }
}

seed_pool_require_age() {
    command -v age >/dev/null 2>&1 || {
        log_err "age is required for persistent seed pools (https://age-encryption.org/)"
        return 1
    }
}

seed_pool_recipient() {
    local recipient_file="${YUBI_SEED_RECIPIENT_FILE:-$SEED_DIR/recipient}"
    if [[ -n "${YUBI_SEED_RECIPIENT:-}" ]]; then
        printf '%s' "$YUBI_SEED_RECIPIENT"
    elif [[ -f "$recipient_file" && ! -L "$recipient_file" ]]; then
        IFS= read -r recipient < "$recipient_file"
        printf '%s' "$recipient"
    else
        log_err "Set YUBI_SEED_RECIPIENT or create $recipient_file with one age recipient"
        return 1
    fi
}

seed_pool_identity() {
    local identity="${YUBI_SEED_IDENTITY:-}"
    [[ -n "$identity" ]] || {
        log_err "Set YUBI_SEED_IDENTITY to an age identity file or plugin identity"
        return 1
    }
    [[ ! -L "$identity" && -f "$identity" ]] || {
        log_err "Age identity must be a regular, non-symlink file: $identity"
        return 1
    }
    printf '%s' "$identity"
}

seed_pool_encrypt_atomic() {
    local plaintext="$1" pool="$2"
    seed_pool_require_age || return 1
    [[ ! -L "$pool" ]] || { log_err "Refusing symlinked seed pool: $pool"; return 1; }
    local recipient tmp
    recipient=$(seed_pool_recipient) || return 1
    tmp=$(mktemp "$(dirname "$pool")/.seed-pool.XXXXXX") || return 1
    chmod 600 "$tmp"
    if ! age -r "$recipient" < "$plaintext" > "$tmp"; then
        rm -f "$tmp"
        log_err "Seed-pool encryption failed"
        return 1
    fi
    chmod 600 "$tmp"
    mv -f "$tmp" "$pool"
}

seed_pool_decrypt() {
    local pool="$1" plaintext="$2" identity
    seed_pool_require_age || return 1
    seed_pool_validate_file "$pool" || return 1
    identity=$(seed_pool_identity) || return 1
    if ! age -d -i "$identity" < "$pool" > "$plaintext"; then
        : > "$plaintext"
        log_err "Seed-pool authentication or decryption failed"
        return 1
    fi
    chmod 600 "$plaintext"
}

SEED_POOL_LOCK_DIR=""
seed_pool_lock() {
    local pool="$1"
    SEED_POOL_LOCK_DIR="${pool}.lock"
    if ! mkdir -m 700 "$SEED_POOL_LOCK_DIR" 2>/dev/null; then
        log_err "Seed pool is locked by another operation: $pool"
        SEED_POOL_LOCK_DIR=""
        return 1
    fi
    printf '%s\n' "$$" > "$SEED_POOL_LOCK_DIR/pid"
}

seed_pool_unlock() {
    if [[ -n "$SEED_POOL_LOCK_DIR" && -d "$SEED_POOL_LOCK_DIR" ]]; then
        rm -f "$SEED_POOL_LOCK_DIR/pid"
        rmdir "$SEED_POOL_LOCK_DIR"
    fi
    SEED_POOL_LOCK_DIR=""
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
# Secure volatile workspace
# =============================================================================
#
# Uses an existing Linux tmpfs when available, or mounts a private tmpfs when
# running as root. A persistent fallback is forbidden unless the caller passes
# an explicit opt-in. tmpfs pages can be swapped; operators that require a
# no-write-to-disk guarantee must also disable or encrypt swap.

SECURE_TMPFS_DIR=""
SECURE_TMPFS_MOUNTED=false
SECURE_TMPFS_KIND=""

path_filesystem_type() {
    local path="$1"
    if [[ "$_IS_MACOS" == "true" ]]; then
        stat -f '%T' "$path" 2>/dev/null
    elif command -v findmnt >/dev/null 2>&1; then
        findmnt -n -o FSTYPE --target "$path" 2>/dev/null
    else
        stat -f -c '%T' "$path" 2>/dev/null
    fi
}

path_is_tmpfs() {
    [[ "$(path_filesystem_type "$1")" == "tmpfs" ]]
}

secure_tmpfs_create() {
    local label="${1:-yubi-work}"
    local size_mb="${2:-16}"
    local allow_disk="${3:-false}"
    local candidate=""

    SECURE_TMPFS_DIR=""
    SECURE_TMPFS_MOUNTED=false
    SECURE_TMPFS_KIND=""

    if [[ "$_IS_MACOS" == "false" ]]; then
        for candidate in "${XDG_RUNTIME_DIR:-}" /dev/shm /tmp; do
            [[ -n "$candidate" && -d "$candidate" && -w "$candidate" ]] || continue
            if path_is_tmpfs "$candidate"; then
                SECURE_TMPFS_DIR=$(mktemp -d "${candidate%/}/${label}.XXXXXX") || return 1
                chmod 700 "$SECURE_TMPFS_DIR"
                SECURE_TMPFS_KIND="existing-tmpfs"
                break
            fi
        done
    fi

    if [[ -z "$SECURE_TMPFS_DIR" && $EUID -eq 0 && "$_IS_MACOS" == "false" ]]; then
        SECURE_TMPFS_DIR=$(mktemp -d "/tmp/${label}.XXXXXX") || return 1
        chmod 700 "$SECURE_TMPFS_DIR"
        if mount -t tmpfs -o "size=${size_mb}m,mode=700" tmpfs "$SECURE_TMPFS_DIR" 2>/dev/null && \
           path_is_tmpfs "$SECURE_TMPFS_DIR"; then
            SECURE_TMPFS_MOUNTED=true
            SECURE_TMPFS_KIND="private-tmpfs"
        else
            umount "$SECURE_TMPFS_DIR" 2>/dev/null || true
            rmdir "$SECURE_TMPFS_DIR" 2>/dev/null || true
            SECURE_TMPFS_DIR=""
        fi
    fi

    if [[ -z "$SECURE_TMPFS_DIR" ]]; then
        if [[ "$allow_disk" != "true" ]]; then
            log_err "No verified tmpfs is available; refusing persistent secret workspace"
            log_err "Use --allow-disk-workspace only after reviewing the storage risk"
            return 1
        fi
        SECURE_TMPFS_DIR=$(mktemp -d "/tmp/${label}.XXXXXX") || return 1
        chmod 700 "$SECURE_TMPFS_DIR"
        SECURE_TMPFS_KIND="persistent-override"
        log_warn "Persistent workspace override enabled: $SECURE_TMPFS_DIR" >&2
        log_warn "Deletion cannot guarantee sanitization of flash, journals, or snapshots" >&2
    else
        log_ok "Secure workspace: verified tmpfs ($SECURE_TMPFS_KIND, ${size_mb}MB limit when privately mounted)" >&2
    fi

    : > "$SECURE_TMPFS_DIR/.yubi-secure-workspace"
    chmod 600 "$SECURE_TMPFS_DIR/.yubi-secure-workspace"
    return 0
}

secure_tmpfs_cleanup() {
    if [[ -z "$SECURE_TMPFS_DIR" || ! -d "$SECURE_TMPFS_DIR" ]]; then
        SECURE_TMPFS_DIR=""
        SECURE_TMPFS_MOUNTED=false
        SECURE_TMPFS_KIND=""
        return 0
    fi

    if [[ ! -f "$SECURE_TMPFS_DIR/.yubi-secure-workspace" ]]; then
        log_err "Refusing to clean unmarked workspace: $SECURE_TMPFS_DIR"
        return 1
    fi

    if [[ "$SECURE_TMPFS_MOUNTED" == "true" ]]; then
        # tmpfs: just unmount — RAM is gone
        rm -f "$SECURE_TMPFS_DIR/.yubi-secure-workspace"
        umount "$SECURE_TMPFS_DIR" 2>/dev/null || return 1
        rmdir "$SECURE_TMPFS_DIR" 2>/dev/null || return 1
        log_ok "Secure workspace unmounted (RAM released)"
    else
        # Existing tmpfs needs only removal. Persistent override gets the
        # legacy best-effort clear until encrypted pools replace it.
        secure_delete_dir "$SECURE_TMPFS_DIR" false
        log_ok "Secure workspace cleared and removed"
    fi

    SECURE_TMPFS_DIR=""
    SECURE_TMPFS_MOUNTED=false
    SECURE_TMPFS_KIND=""
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
    perms=$(file_perms "$file")
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
        latest_epoch=$(iso_to_epoch "$latest")
        local now_epoch
        now_epoch=$(date +%s)
        local age_days=$(( (now_epoch - latest_epoch) / 86400 ))
        if [[ $age_days -gt 30 ]]; then
            log_warn "All blocks are >30 days old — consider collecting fresh entropy"
        fi
    fi
}

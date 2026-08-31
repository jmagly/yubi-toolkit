#!/usr/bin/env bash
# entropy-mix.sh — Mix YubiKey RNG passwords with multiple entropy sources
# Uses HKDF-SHA512 to combine: YubiKey + CPU RNG + thermal sensors +
# mandatory CSPRNG output plus unassessed local supplements
#
# Usage: ./entropy-mix.sh <input_file> [output_file]
#   input_file:  text file with one YubiKey password per line
#   output_file: defaults to <input_file>.mixed

set -euo pipefail
umask 077       # New files owner-only
ulimit -c 0     # Disable core dumps

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/yubi-lib.sh"

# --- Configuration ---
API_BATCH_SIZE=10  # how many random values per API call
HKDF_KEYLEN=32     # 32 bytes = 44 char base64

# --- Argument handling ---
if [[ $# -lt 1 ]]; then
    cat <<'USAGE'
Usage: entropy-mix.sh <input_file> [output_file] [options]

  input_file:  text file with one YubiKey password per line
  output_file: defaults to <input_file>.mixed

Options:
  --no-external         Compatibility no-op; networking is disabled
  --entropy-file PATH   Rejected legacy unverified input
USAGE
    exit 1
fi

# Parse arguments
INPUT_FILE=""
OUTPUT_FILE=""
NO_EXTERNAL=false
ENTROPY_FILE_PATH=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-external)
            NO_EXTERNAL=true
            shift
            ;;
        --entropy-file)
            ENTROPY_FILE_PATH="$2"
            shift 2
            ;;
        -*)
            log_err "Unknown option: $1"
            exit 1
            ;;
        *)
            if [[ -z "$INPUT_FILE" ]]; then
                INPUT_FILE="$1"
            elif [[ -z "$OUTPUT_FILE" ]]; then
                OUTPUT_FILE="$1"
            fi
            shift
            ;;
    esac
done

if [[ -z "$OUTPUT_FILE" ]]; then
    OUTPUT_FILE="${INPUT_FILE}.mixed"
fi

if [[ ! -f "$INPUT_FILE" ]]; then
    log_err "Input file not found: $INPUT_FILE"
    exit 1
fi

LINE_COUNT=$(wc -l < "$INPUT_FILE")
if [[ $LINE_COUNT -eq 0 ]]; then
    log_err "Input file is empty"
    exit 1
fi

log_info "Input: $INPUT_FILE ($LINE_COUNT passwords)"
log_info "Output: $OUTPUT_FILE"

# --- Prerequisite checks ---
for cmd in openssl; do
    if ! command -v "$cmd" &>/dev/null; then
        log_err "Required command not found: $cmd"
        exit 1
    fi
done

# lm-sensors is Linux-only; system_thermal_entropy() handles both platforms.
require_openssl3
require_csprng
if [[ -n "$ENTROPY_FILE_PATH" ]]; then
    log_err "Legacy external entropy files cannot be mixed; verified beacon support was removed"
    exit 1
fi
NO_EXTERNAL=true

# --- Entropy collection functions ---

collect_cpu_random() {
    csprng_hex 32
}

collect_thermal_base() {
    # Collect sensor snapshot once (expensive), store as base entropy.
    # system_thermal_entropy() picks the right source per platform.
    printf '%s' "$(system_thermal_entropy)" \
        | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}'
}

collect_thermal_perline() {
    # Fast per-line: cheap sysfs/sysctl read + nanosecond timestamp + base.
    local base="$1"
    local data="$base"
    if [[ "$_IS_MACOS" == "true" ]]; then
        data+="$(sysctl -n vm.loadavg kern.boottime 2>/dev/null)"
    else
        for tz in /sys/class/thermal/thermal_zone*/temp; do
            [[ -f "$tz" ]] && data+="$(cat "$tz")"
        done
    fi
    data+="$(now_ns)"
    printf '%s' "$data" | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}'
}

collect_disk_jitter_base() {
    # Collect timing jitter once (8 samples), store as base entropy
    local data=""
    for i in {1..8}; do
        local t_start t_end
        t_start=$(now_ns)
        dd if=/dev/urandom bs=512 count=1 of=/dev/null 2>/dev/null
        t_end=$(now_ns)
        data+="$((t_end - t_start))"
    done
    printf '%s' "$data" | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}'
}

collect_jitter_perline() {
    # Fast per-line: 2 quick timing samples + nanosecond timestamp + base
    local base="$1"
    local t_start t_end
    t_start=$(now_ns)
    dd if=/dev/urandom bs=64 count=1 of=/dev/null 2>/dev/null
    t_end=$(now_ns)
    printf '%s:%s:%s' "$base" "$((t_end - t_start))" "$(now_ns)" \
        | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}'
}

# External API functions are provided by yubi-lib.sh (call_external,
# get_external_entropy). The batch collection functions below use the
# shared call_external() with retry+degrade.

# Live public-beacon collectors were removed. Public inputs are not mixed
# without signature, chain, freshness, replay, schema, and size verification.
# --- Per-line entropy distributor ---
# Given a raw data blob from an API batch, pick a portion for this line index
# using CPU random to select which chunk maps to which line
pick_entropy_for_line() {
    local raw_data="$1"
    local line_idx="$2"
    local total_lines="$3"

    if [[ -z "$raw_data" ]]; then
        echo ""
        return
    fi

    # Hash the raw data with the line index for unique per-line contribution
    printf '%s:%s:%s' "$raw_data" "$line_idx" "$(openssl rand -hex 8)" \
        | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}'
}

# --- HKDF mixing function ---
# Combines all entropy sources into one derived key for a password line
hkdf_mix() {
    local yubikey_pw="$1"
    local cpu_entropy="$2"
    local thermal_entropy="$3"
    local jitter_entropy="$4"
    local ext1_entropy="$5"  # random.org
    local ext2_entropy="$6"  # ANU QRNG
    local ext3_entropy="$7"  # drand

    # Build salt from all non-YubiKey entropy (hex concatenation)
    local salt_hex="${thermal_entropy}${jitter_entropy}"
    salt_hex+="${ext1_entropy}${ext2_entropy}${ext3_entropy}"

    # The CSPRNG is mandatory secret IKM; the password is a supplement.
    local ikm_hex
    ikm_hex=$(printf '%s:%s' "$cpu_entropy" "$yubikey_pw" | xxd -p | tr -d '\n')

    # Info field identifies this derivation context
    local info_hex
    info_hex=$(printf '%s' "entropy-mix-v1" | xxd -p | tr -d '\n')

    # HKDF-SHA512 derive
    openssl kdf -keylen "$HKDF_KEYLEN" \
        -kdfopt digest:SHA512 \
        -kdfopt "hexkey:${ikm_hex}" \
        -kdfopt "hexsalt:${salt_hex}" \
        -kdfopt "hexinfo:${info_hex}" \
        HKDF 2>/dev/null \
        | tr -d ':' | xxd -r -p | openssl base64 -A
}

# --- Main execution ---
# Public diversification is disabled. These empty values preserve the v1
# function framing without treating public data as secret input.
RANDOM_ORG_RAW=""
NIST_BEACON_RAW=""
DRAND_RAW=""
ext_sources_ok=0
log_info "Public diversification: disabled (unverified beacon paths removed)"
log_info "=== Collecting local sensor baselines ==="
THERMAL_BASE=$(collect_thermal_base)
log_ok "Thermal baseline collected"
JITTER_BASE=$(collect_disk_jitter_base)
log_ok "Disk jitter baseline collected"

log_info "=== Mixing $LINE_COUNT passwords ==="

# Process each line
line_idx=0
declare -a output_lines=()

while IFS= read -r yubikey_pw || [[ -n "$yubikey_pw" ]]; do
    line_idx=$(( line_idx + 1 ))

    # Skip empty lines
    if [[ -z "$yubikey_pw" ]]; then
        continue
    fi

    # Fresh local entropy per line (fast variants using cached base)
    cpu_ent=$(collect_cpu_random) || { log_err "CSPRNG failed during mixing"; exit 1; }
    thermal_ent=$(collect_thermal_perline "$THERMAL_BASE")
    jitter_ent=$(collect_jitter_perline "$JITTER_BASE")

    # Per-line external entropy (randomly distributed from batch)
    ext1_ent=$(pick_entropy_for_line "$RANDOM_ORG_RAW" "$line_idx" "$LINE_COUNT")
    ext2_ent=$(pick_entropy_for_line "$NIST_BEACON_RAW" "$line_idx" "$LINE_COUNT")
    ext3_ent=$(pick_entropy_for_line "$DRAND_RAW" "$line_idx" "$LINE_COUNT")

    # Mix via HKDF
    mixed=$(hkdf_mix "$yubikey_pw" "$cpu_ent" "$thermal_ent" "$jitter_ent" \
        "$ext1_ent" "$ext2_ent" "$ext3_ent")

    output_lines+=("$mixed")
    printf "\r${CYN}[INFO]${RST}  Processing: %d/%d" "$line_idx" "$LINE_COUNT"
done < "$INPUT_FILE"
printf "\n"

# --- Write output ---
printf '%s\n' "${output_lines[@]}" > "$OUTPUT_FILE"
chmod 600 "$OUTPUT_FILE"

# --- Verification ---
log_info "=== Verification ==="

out_count=$(wc -l < "$OUTPUT_FILE")
log_info "Output lines: $out_count"

# Check for duplicates
dup_count=$(sort "$OUTPUT_FILE" | uniq -d | wc -l)
if [[ $dup_count -gt 0 ]]; then
    log_err "DUPLICATE PASSWORDS DETECTED ($dup_count) — this should not happen"
    exit 1
fi
log_ok "No duplicates"

# Check output length consistency
first_len=$(head -1 "$OUTPUT_FILE" | wc -c)
log_info "Password length: $((first_len - 1)) chars (base64 of ${HKDF_KEYLEN} bytes)"

# Entropy source summary
log_info "=== Entropy Source Report ==="
log_ok "Platform CSPRNG: ✓ (mandatory fresh secret root per line)"
log_info "Thermal/timing: unassessed supplements (no min-entropy claim)"
log_info "Public beacons: disabled (unverified paths removed)"

log_ok "Output written to: $OUTPUT_FILE (mode 600)"
log_info "Done."

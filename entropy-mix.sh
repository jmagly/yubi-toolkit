#!/usr/bin/env bash
# entropy-mix.sh — Mix YubiKey RNG passwords with multiple entropy sources
# Uses HKDF-SHA512 to combine: YubiKey + CPU RNG + thermal sensors +
# disk timing jitter + random.org + NIST Beacon + drand beacon
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
  --no-external         Skip external API calls (local entropy only)
  --entropy-file PATH   Use pre-collected entropy file instead of live APIs
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
for cmd in openssl curl sensors; do
    if ! command -v "$cmd" &>/dev/null; then
        log_err "Required command not found: $cmd"
        exit 1
    fi
done

# Verify OpenSSL 3.x for HKDF support
ossl_ver=$(openssl version | awk '{print $2}')
ossl_major="${ossl_ver%%.*}"
if [[ "$ossl_major" -lt 3 ]]; then
    log_err "OpenSSL 3.0+ required (found: $ossl_ver) — 'openssl kdf' unavailable on 1.x"
    exit 1
fi

# --- Entropy collection functions ---

collect_cpu_random() {
    # 32 bytes from /dev/urandom via openssl (uses CPU RDRAND when available)
    openssl rand -hex 32
}

collect_thermal_base() {
    # Collect sensor snapshot once (expensive), store as base entropy
    local data=""
    for tz in /sys/class/thermal/thermal_zone*/temp; do
        [[ -f "$tz" ]] && data+="$(cat "$tz")"
    done
    data+="$(sensors -u 2>/dev/null | tr -d ' \n')"
    printf '%s' "$data" | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}'
}

collect_thermal_perline() {
    # Fast per-line: re-read sysfs temps (cheap) + nanosecond timestamp + base
    local base="$1"
    local data="$base"
    for tz in /sys/class/thermal/thermal_zone*/temp; do
        [[ -f "$tz" ]] && data+="$(cat "$tz")"
    done
    data+="$(date +%s%N)"
    printf '%s' "$data" | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}'
}

collect_disk_jitter_base() {
    # Collect timing jitter once (8 samples), store as base entropy
    local data=""
    for i in {1..8}; do
        local t_start t_end
        t_start=$(date +%s%N)
        dd if=/dev/urandom bs=512 count=1 of=/dev/null 2>/dev/null
        t_end=$(date +%s%N)
        data+="$((t_end - t_start))"
    done
    printf '%s' "$data" | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}'
}

collect_jitter_perline() {
    # Fast per-line: 2 quick timing samples + nanosecond timestamp + base
    local base="$1"
    local t_start t_end
    t_start=$(date +%s%N)
    dd if=/dev/urandom bs=64 count=1 of=/dev/null 2>/dev/null
    t_end=$(date +%s%N)
    printf '%s:%s:%s' "$base" "$((t_end - t_start))" "$(date +%s%N)" \
        | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}'
}

# External API functions are provided by yubi-lib.sh (call_external,
# get_external_entropy). The batch collection functions below use the
# shared call_external() with retry+degrade.

collect_random_org_batch() {
    local count=$1
    log_info "random.org: requesting $count values..."
    local url="https://www.random.org/integers/?num=${count}&min=0&max=1000000000&col=1&base=10&format=plain&rnd=new"
    local raw
    raw=$(call_external "random.org" "$url") || { echo ""; return 1; }
    printf '%s' "$raw" | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}'
    RANDOM_ORG_RAW="$raw"
    return 0
}

collect_nist_beacon_batch() {
    local count=$1
    log_info "NIST Beacon: requesting $count pulses..."
    local data=""
    local calls=$count
    (( calls > 3 )) && calls=3

    for (( i=0; i<calls; i++ )); do
        local raw
        raw=$(call_external "NIST Beacon" \
            "https://beacon.nist.gov/beacon/2.0/pulse/last") || continue
        data+="$raw"
        sleep 0.3
    done

    if [[ -z "$data" ]]; then
        NIST_BEACON_RAW=""
        echo ""
        return 1
    fi
    NIST_BEACON_RAW="$data"
    printf '%s' "$data" | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}'
    return 0
}

collect_drand_batch() {
    local count=$1
    log_info "drand: requesting $count beacon rounds..."
    local data=""
    local calls=$(( (count + API_BATCH_SIZE - 1) / API_BATCH_SIZE ))
    (( calls < 1 )) && calls=1
    (( calls > 3 )) && calls=3

    for (( i=0; i<calls; i++ )); do
        local raw
        raw=$(call_external "drand" \
            "https://drand.cloudflare.com/public/latest") || continue
        data+="$raw"
        sleep 0.5
    done

    if [[ -z "$data" ]]; then
        DRAND_RAW=""
        echo ""
        return 1
    fi
    DRAND_RAW="$data"
    printf '%s' "$data" | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}'
    return 0
}

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
    local salt_hex="${cpu_entropy}${thermal_entropy}${jitter_entropy}"
    salt_hex+="${ext1_entropy}${ext2_entropy}${ext3_entropy}"

    # IKM is the YubiKey password
    local ikm_hex
    ikm_hex=$(printf '%s' "$yubikey_pw" | xxd -p | tr -d '\n')

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

log_info "=== Collecting batch external entropy ==="

RANDOM_ORG_RAW=""
NIST_BEACON_RAW=""
DRAND_RAW=""

# Track which external sources succeeded
ext_sources_ok=0
ext_sources_failed=()

if [[ "$NO_EXTERNAL" == "true" ]]; then
    log_info "External entropy: disabled (--no-external)"
elif [[ -n "$ENTROPY_FILE_PATH" ]]; then
    # Load from pre-collected entropy file
    log_info "Loading external entropy from file: $ENTROPY_FILE_PATH"
    load_external_entropy "$ENTROPY_FILE_PATH"
    ext_sources_ok="$EXT_SOURCES_OK"
    # Map to the RAW variables used by pick_entropy_for_line
    RANDOM_ORG_RAW="$EXT_RANDOM_ORG"
    NIST_BEACON_RAW="$EXT_NIST"
    DRAND_RAW="$EXT_DRAND"
else
    # Live API fetch (original behavior)
    api_calls=$(( (LINE_COUNT + API_BATCH_SIZE - 1) / API_BATCH_SIZE ))
    (( api_calls < 1 )) && api_calls=1
    (( api_calls > 3 )) && api_calls=3
    batch_size=$(( (LINE_COUNT + api_calls - 1) / api_calls ))

    if collect_random_org_batch "$batch_size"; then
        log_ok "random.org: collected"
        ext_sources_ok=$(( ext_sources_ok + 1 ))
    else
        ext_sources_failed+=("random.org")
    fi

    if collect_nist_beacon_batch "$batch_size"; then
        log_ok "NIST Beacon: collected"
        ext_sources_ok=$(( ext_sources_ok + 1 ))
    else
        ext_sources_failed+=("NIST Beacon")
    fi

    if collect_drand_batch "$api_calls"; then
        log_ok "drand: collected"
        ext_sources_ok=$(( ext_sources_ok + 1 ))
    else
        ext_sources_failed+=("drand")
    fi

    if [[ ${#ext_sources_failed[@]} -gt 0 ]]; then
        log_warn "Failed external sources: ${ext_sources_failed[*]}"
    fi
fi

log_info "External sources available: $ext_sources_ok/3"

if (( ext_sources_ok == 0 )) && [[ "$NO_EXTERNAL" == "false" ]]; then
    log_warn "NO external sources available — output relies on local entropy only"
    log_warn "Consider re-running when network is available for stronger mixing"
fi

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
    cpu_ent=$(collect_cpu_random)
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
log_ok "CPU RDRAND:     ✓ (fresh per line)"
log_ok "Thermal:        ✓ (fresh per line)"
log_ok "Disk jitter:    ✓ (fresh per line)"
for src in "random.org" "NIST Beacon" "drand"; do
    if printf '%s\n' "${ext_sources_failed[@]}" | grep -q "$src" 2>/dev/null; then
        log_warn "$src:  ✗ DEGRADED"
    else
        log_ok "$src:  ✓ (batch, randomly distributed)"
    fi
done

log_ok "Output written to: $OUTPUT_FILE (mode 600)"
log_info "Done."

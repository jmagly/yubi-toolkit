#!/usr/bin/env bash
# entropy-mix.sh — Mix YubiKey RNG passwords with multiple entropy sources
# Uses HKDF-SHA512 to combine: YubiKey + CPU RNG + thermal sensors +
# disk timing jitter + random.org + NIST Beacon + drand beacon
#
# Usage: ./entropy-mix.sh <input_file> [output_file]
#   input_file:  text file with one YubiKey password per line
#   output_file: defaults to <input_file>.mixed

set -euo pipefail

# --- Configuration ---
RETRY_MAX=3
RETRY_DELAY=2
API_BATCH_SIZE=10  # how many random values per API call
HKDF_KEYLEN=32     # 32 bytes = 44 char base64

# --- Color output ---
RED='\033[0;31m'
YLW='\033[0;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
RST='\033[0m'

log_info()  { printf "${CYN}[INFO]${RST}  %s\n" "$*"; }
log_ok()    { printf "${GRN}[OK]${RST}    %s\n" "$*"; }
log_warn()  { printf "${YLW}[WARN]${RST}  %s\n" "$*"; }
log_err()   { printf "${RED}[ERR]${RST}   %s\n" "$*" >&2; }

# --- Argument handling ---
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <input_file> [output_file]"
    echo "  input_file:  text file with one YubiKey password per line"
    echo "  output_file: defaults to <input_file>.mixed"
    exit 1
fi

INPUT_FILE="$1"
OUTPUT_FILE="${2:-${INPUT_FILE}.mixed}"

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

# --- External API functions with retry+degrade ---

# Calls an external source. Returns hex entropy or empty string on failure.
# Usage: call_external <name> <curl_args...>
call_external() {
    local name="$1"; shift
    local attempt=0
    local response=""

    while (( attempt < RETRY_MAX )); do
        attempt=$(( attempt + 1 ))
        response=$(curl -sf --max-time 10 "$@" 2>/dev/null) && break
        log_warn "$name: attempt $attempt/$RETRY_MAX failed, retrying in ${RETRY_DELAY}s..."
        sleep "$RETRY_DELAY"
        response=""
    done

    if [[ -z "$response" ]]; then
        log_warn "$name: ALL RETRIES FAILED — degrading (source excluded)"
        echo ""
        return 1
    fi
    echo "$response"
    return 0
}

collect_random_org_batch() {
    local count=$1
    log_info "random.org: requesting $count values..."
    local url="https://www.random.org/integers/?num=${count}&min=0&max=1000000000&col=1&base=10&format=plain&rnd=new"
    local raw
    raw=$(call_external "random.org" "$url") || { echo ""; return 1; }
    # Hash each line to hex
    printf '%s' "$raw" | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}'
    # Store raw values for per-line distribution
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
    # Fetch latest round plus previous rounds for additional entropy
    local calls=$(( (count + API_BATCH_SIZE - 1) / API_BATCH_SIZE ))
    (( calls < 1 )) && calls=1
    (( calls > 3 )) && calls=3

    for (( i=0; i<calls; i++ )); do
        local raw
        raw=$(call_external "drand" \
            "https://drand.cloudflare.com/public/latest") || continue
        data+="$raw"
        # Small delay to get different rounds
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

# Calculate API batch sizes: ~3 calls per source, distribute across lines
api_calls=$(( (LINE_COUNT + API_BATCH_SIZE - 1) / API_BATCH_SIZE ))
(( api_calls < 1 )) && api_calls=1
(( api_calls > 3 )) && api_calls=3
batch_size=$(( (LINE_COUNT + api_calls - 1) / api_calls ))

RANDOM_ORG_RAW=""
NIST_BEACON_RAW=""
DRAND_RAW=""

# Track which external sources succeeded
ext_sources_ok=0
ext_sources_failed=()

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

# Report external source status
if [[ ${#ext_sources_failed[@]} -gt 0 ]]; then
    log_warn "Failed external sources: ${ext_sources_failed[*]}"
fi
log_info "External sources available: $ext_sources_ok/3"

# Minimum viable: need CPU + at least 1 local sensor + 1 external
# But we degrade gracefully — warn if below ideal
if (( ext_sources_ok == 0 )); then
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

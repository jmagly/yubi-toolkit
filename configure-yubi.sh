#!/usr/bin/env bash
# configure-yubi.sh — Full YubiKey initialization from entropy-mixed source material
#
# Replaces ALL factory-programmed secrets with user-controlled entropy:
#   - PIV PIN        (8 numeric digits, derived via HKDF)
#   - PIV PUK        (8 alphanumeric chars, derived via HKDF)
#   - PIV Management Key (AES256 on 5.4.2+, TDES on older firmware)
#   - OTP Slot 1     (Yubico OTP or static password)
#   - OTP Slot 2     (Yubico OTP or static password)
#
# Consumes 5 lines from input data file (randomly selected, never reused).
# Outputs the derived PIN on success — record it securely.
#
# Usage: ./configure-yubi.sh <MODE> <SERIAL> <INPUTDATA>
#   MODE:      "otp"    = both OTP slots get Yubico OTP credentials
#              "static" = both OTP slots get static passwords
#              "mixed"  = slot 1 Yubico OTP, slot 2 static password
#   SERIAL:    YubiKey serial number (run 'ykman list --serials')
#   INPUTDATA: text file with one base64 key per line (from entropy-mix.sh)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/yubi-lib.sh"
harden_process
require_openssl3

# =============================================================================
# Configuration
# =============================================================================

MAX_STATIC_LEN=38    # YubiKey static password slot limit
OTP_AES_KEY_LEN=16   # Yubico OTP AES key: 16 bytes
OTP_PRIVATE_ID_LEN=6 # Yubico OTP private ID: 6 bytes
PIV_PIN_LEN=8        # PIV PIN: 8 numeric digits
PIV_PUK_LEN=8        # PIV PUK: 8 alphanumeric chars
LINES_REQUIRED=5     # Total entropy lines consumed per key
# PIV_MGMT_KEY_LEN and MGMT_KEY_ALGO set after firmware detection

# Factory defaults (used to authenticate before changing)
FACTORY_PIN="123456"
FACTORY_PUK="12345678"
FACTORY_MGMT_KEY="010203040506070801020304050607080102030405060708"

# =============================================================================
# Arguments
# =============================================================================

if [[ $# -lt 3 ]]; then
    echo "Usage: $0 <MODE> <SERIAL> <INPUTDATA>"
    echo ""
    echo "  MODE:      'otp'    = both OTP slots Yubico OTP (replace factory seed)"
    echo "             'static' = both OTP slots static password"
    echo "             'mixed'  = slot 1 OTP + slot 2 static password"
    echo "  SERIAL:    YubiKey serial number (run 'ykman list --serials' to find it)"
    echo "  INPUTDATA: text file with one base64 key per line (from entropy-mix.sh)"
    echo ""
    echo "Consumes $LINES_REQUIRED lines: 2 for OTP slots + PIN + PUK + management key."
    echo "Outputs the derived PIN on success."
    exit 1
fi

MODE="$1"
SERIAL="$2"
INPUT_FILE="$3"

validate_mode "$MODE"
validate_serial "$SERIAL"

if [[ ! -f "$INPUT_FILE" ]]; then
    log_err "Input data file not found: $INPUT_FILE"
    exit 1
fi

# =============================================================================
# Prerequisites
# =============================================================================

if ! command -v ykman &>/dev/null; then
    log_err "ykman not found — install with: sudo apt install yubikey-manager"
    exit 1
fi

# =============================================================================
# YubiKey detection
# =============================================================================

log_info "Looking for YubiKey serial: $SERIAL"

connected_serials=$(ykman list --serials 2>/dev/null)
if [[ -z "$connected_serials" ]]; then
    log_err "No YubiKeys detected — insert a key and try again"
    exit 1
fi

if ! echo "$connected_serials" | grep -qx "$SERIAL"; then
    log_err "YubiKey $SERIAL not found. Connected keys:"
    echo "$connected_serials" | while read -r s; do echo "  - $s"; done
    exit 1
fi
log_ok "YubiKey $SERIAL detected"

# --- Tmpfile cleanup trap ---
CONFIGURE_TMPFILE=""
cleanup_configure() {
    if [[ -n "$CONFIGURE_TMPFILE" && -f "$CONFIGURE_TMPFILE" ]]; then
        secure_delete "$CONFIGURE_TMPFILE" false
    fi
}
trap cleanup_configure EXIT

# --- Detect firmware version for AES256 management key support ---
fw_version=$(ykman -d "$SERIAL" info 2>/dev/null | grep 'Firmware version:' | awk '{print $NF}')
fw_major=$(echo "$fw_version" | cut -d. -f1)
fw_minor=$(echo "$fw_version" | cut -d. -f2)
fw_patch=$(echo "$fw_version" | cut -d. -f3)

if [[ "$fw_major" -gt 5 ]] || \
   [[ "$fw_major" -eq 5 && "$fw_minor" -gt 4 ]] || \
   [[ "$fw_major" -eq 5 && "$fw_minor" -eq 4 && "$fw_patch" -ge 2 ]]; then
    MGMT_KEY_ALGO="AES256"
    PIV_MGMT_KEY_LEN=32   # AES256: 32 bytes
    log_ok "Firmware $fw_version — using AES256 management key"
else
    MGMT_KEY_ALGO="TDES"
    PIV_MGMT_KEY_LEN=24   # TDES: 24 bytes
    log_warn "Firmware $fw_version — using TDES management key (AES256 requires 5.4.2+)"
fi

log_info "Current OTP state:"
ykman -d "$SERIAL" otp info
log_info "Current PIV state:"
ykman -d "$SERIAL" piv info

# =============================================================================
# Entropy pool — randomly select 5 lines
# =============================================================================

declare -a pool_lines=()
declare -a pool_linenos=()
line_num=0
while IFS= read -r line; do
    line_num=$(( line_num + 1 ))
    [[ -z "$line" ]] && continue
    pool_lines+=("$line")
    pool_linenos+=("$line_num")
done < "$INPUT_FILE"

pool_size=${#pool_lines[@]}
if [[ "$pool_size" -lt "$LINES_REQUIRED" ]]; then
    log_err "Need $LINES_REQUIRED lines but input file only has $pool_size"
    log_err "Generate more with entropy-mix.sh first"
    exit 1
fi

log_info "Input file has $pool_size keys available, selecting $LINES_REQUIRED"

# Pick N random distinct indices using Fisher-Yates partial shuffle
declare -a selected_indices=()
declare -a available_indices=()
for (( i=0; i<pool_size; i++ )); do
    available_indices+=("$i")
done

for (( pick=0; pick<LINES_REQUIRED; pick++ )); do
    remaining=$(( pool_size - pick ))
    rand_pos=$(( $(od -An -tu4 -N4 /dev/urandom | tr -d ' ') % remaining ))
    selected_indices+=("${available_indices[$rand_pos]}")
    # Swap selected with last available
    available_indices[$rand_pos]="${available_indices[$(( remaining - 1 ))]}"
done

# Assign purpose to each selected line
raw_slot1="${pool_lines[${selected_indices[0]}]}"
raw_slot2="${pool_lines[${selected_indices[1]}]}"
raw_pin="${pool_lines[${selected_indices[2]}]}"
raw_puk="${pool_lines[${selected_indices[3]}]}"
raw_mgmt="${pool_lines[${selected_indices[4]}]}"

line_numbers_consumed=()
for idx in "${selected_indices[@]}"; do
    line_numbers_consumed+=("${pool_linenos[$idx]}")
done

log_info "Selected lines: ${line_numbers_consumed[*]}"
log_info "  Slot 1 entropy:  line ${line_numbers_consumed[0]}"
log_info "  Slot 2 entropy:  line ${line_numbers_consumed[1]}"
log_info "  PIN entropy:     line ${line_numbers_consumed[2]}"
log_info "  PUK entropy:     line ${line_numbers_consumed[3]}"
log_info "  Mgmt key entropy: line ${line_numbers_consumed[4]}"

# =============================================================================
# HKDF derivation helpers
# =============================================================================

# Base64 input -> hex IKM
b64_to_ikm_hex() {
    printf '%s' "$1" | openssl base64 -d -A | xxd -p | tr -d '\n'
}

# HKDF-SHA256 derive arbitrary bytes
# Usage: hkdf_derive <b64_input> <info_label> <byte_length>
# Salt is the YubiKey serial — binds derived credentials to the target device
hkdf_derive_hex() {
    local ikm_hex
    ikm_hex=$(b64_to_ikm_hex "$1")
    local info_hex
    info_hex=$(printf '%s' "$2" | xxd -p | tr -d '\n')
    local salt_hex
    salt_hex=$(printf '%s' "$SERIAL" | xxd -p | tr -d '\n')

    openssl kdf -keylen "$3" \
        -kdfopt digest:SHA256 \
        -kdfopt "hexkey:${ikm_hex}" \
        -kdfopt "hexsalt:${salt_hex}" \
        -kdfopt "hexinfo:${info_hex}" \
        HKDF 2>/dev/null \
        | tr -d ':' | tr '[:upper:]' '[:lower:]'
}

# Derive numeric-only string of given length from hex
# Converts each byte to a decimal digit via modulo
hex_to_numeric() {
    local hex="$1"
    local length="$2"
    local result=""
    for (( i=0; i<length; i++ )); do
        local byte_hex="${hex:$((i*2)):2}"
        local byte_dec=$((16#$byte_hex))
        result+="$(( byte_dec % 10 ))"
    done
    echo "$result"
}

# Derive alphanumeric string of given length from hex
hex_to_alphanum() {
    local hex="$1"
    local length="$2"
    local charset="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local charset_len=${#charset}
    local result=""
    for (( i=0; i<length; i++ )); do
        local byte_hex="${hex:$((i*2)):2}"
        local byte_dec=$((16#$byte_hex))
        local idx=$(( byte_dec % charset_len ))
        result+="${charset:$idx:1}"
    done
    echo "$result"
}

# =============================================================================
# Derive all credentials
# =============================================================================

# --- PIV PIN (8 numeric digits) ---
pin_hex=$(hkdf_derive_hex "$raw_pin" "yubikey-piv-pin" "$PIV_PIN_LEN")
derived_pin=$(hex_to_numeric "$pin_hex" "$PIV_PIN_LEN")

# --- PIV PUK (8 alphanumeric chars) ---
puk_hex=$(hkdf_derive_hex "$raw_puk" "yubikey-piv-puk" "$PIV_PUK_LEN")
derived_puk=$(hex_to_alphanum "$puk_hex" "$PIV_PUK_LEN")

# --- PIV Management Key (AES256 32 bytes or TDES 24 bytes, hex) ---
derived_mgmt=$(hkdf_derive_hex "$raw_mgmt" "yubikey-piv-mgmt-key" "$PIV_MGMT_KEY_LEN")

# --- OTP Slot modes ---
case "$MODE" in
    otp)    slot1_mode="otp";    slot2_mode="otp"    ;;
    static) slot1_mode="static"; slot2_mode="static" ;;
    mixed)  slot1_mode="otp";    slot2_mode="static" ;;
esac

# --- OTP Slot 1 ---
declare -A slot_desc
if [[ "$slot1_mode" == "otp" ]]; then
    s1_aes=$(hkdf_derive_hex "$raw_slot1" "yubiotp-aes-key-slot1" "$OTP_AES_KEY_LEN")
    s1_pid=$(hkdf_derive_hex "$raw_slot1" "yubiotp-private-id-slot1" "$OTP_PRIVATE_ID_LEN")
    slot_desc[1]="Yubico OTP  AES ${s1_aes:0:8}...${s1_aes: -4}  pid ${s1_pid}"
else
    s1_pw="${raw_slot1:0:$MAX_STATIC_LEN}"
    [[ ${#raw_slot1} -gt $MAX_STATIC_LEN ]] && \
        log_warn "Slot 1: truncated from ${#raw_slot1} to $MAX_STATIC_LEN chars"
    slot_desc[1]="static password (US layout, ${#s1_pw} chars)"
fi

# --- OTP Slot 2 ---
if [[ "$slot2_mode" == "otp" ]]; then
    s2_aes=$(hkdf_derive_hex "$raw_slot2" "yubiotp-aes-key-slot2" "$OTP_AES_KEY_LEN")
    s2_pid=$(hkdf_derive_hex "$raw_slot2" "yubiotp-private-id-slot2" "$OTP_PRIVATE_ID_LEN")
    slot_desc[2]="Yubico OTP  AES ${s2_aes:0:8}...${s2_aes: -4}  pid ${s2_pid}"
else
    s2_pw="${raw_slot2:0:$MAX_STATIC_LEN}"
    [[ ${#raw_slot2} -gt $MAX_STATIC_LEN ]] && \
        log_warn "Slot 2: truncated from ${#raw_slot2} to $MAX_STATIC_LEN chars"
    slot_desc[2]="static password (US layout, ${#s2_pw} chars)"
fi

# =============================================================================
# Confirmation gate
# =============================================================================

echo ""
log_info "=== CONFIGURATION PLAN ==="
log_info "Target:      YubiKey $SERIAL"
log_info "OTP Slot 1:  ${slot_desc[1]}"
log_info "OTP Slot 2:  ${slot_desc[2]}"
log_info "PIV PIN:     ${derived_pin:0:2}******  (8 numeric digits)"
log_info "PIV PUK:     ${derived_puk:0:2}******  (8 alphanumeric chars)"
log_info "PIV Mgmt:    ${derived_mgmt:0:8}...${derived_mgmt: -4}  (${PIV_MGMT_KEY_LEN}-byte $MGMT_KEY_ALGO)"
log_info "Input:       $INPUT_FILE (consuming ${LINES_REQUIRED} lines)"
echo ""
if [[ "$slot1_mode" == "otp" || "$slot2_mode" == "otp" ]]; then
    printf "${YLW}OTP slots will REPLACE factory seed — will not validate against YubiCloud.${RST}\n"
fi
printf "${YLW}PIV PIN, PUK, and management key will REPLACE factory defaults.${RST}\n"
printf "${YLW}This is a full key initialization. All factory secrets will be overwritten.${RST}\n"
printf "Type YES to proceed: "
read -r confirm
if [[ "$confirm" != "YES" ]]; then
    log_info "Aborted."
    exit 0
fi

# =============================================================================
# Phase 1: PIV initialization (PIN, PUK, Management Key)
# =============================================================================

echo ""
log_info "=== Phase 1: PIV credentials ==="

# Order matters: change management key first (needs factory mgmt key),
# then PUK (needs factory PUK), then PIN (needs factory PIN).

# Try with factory defaults first; if that fails, offer PIV reset
piv_reset_and_retry() {
    log_warn "PIV credentials don't match factory defaults — key was previously initialized"
    echo ""
    printf "${YLW}Reset PIV to factory defaults and re-initialize? (YES/no): ${RST}"
    read -r reset_confirm
    if [[ "$reset_confirm" != "YES" ]]; then
        log_info "Aborted. Reset manually with: ykman -d $SERIAL piv reset"
        exit 1
    fi
    log_info "Resetting PIV application..."
    if ! ykman -d "$SERIAL" piv reset --force; then
        log_err "PIV reset FAILED"
        exit 1
    fi
    log_ok "PIV reset to factory defaults"
    echo ""
}

# Build management key change args (factory key is always TDES)
mgmt_change_args=(
    -d "$SERIAL" piv access change-management-key
    --management-key "$FACTORY_MGMT_KEY"
    --new-management-key "$derived_mgmt"
    --force
)
# Set algorithm for the NEW key (factory auth is auto-detected by ykman)
if [[ "$MGMT_KEY_ALGO" == "AES256" ]]; then
    mgmt_change_args+=(--algorithm AES256)
fi

log_info "Changing management key ($MGMT_KEY_ALGO)..."
if ! ykman "${mgmt_change_args[@]}" 2>/dev/null; then
    piv_reset_and_retry
    # Retry after reset — factory defaults are restored
    log_info "Retrying management key change..."
    if ! ykman "${mgmt_change_args[@]}"; then
        log_err "Management key change FAILED even after reset"
        exit 1
    fi
fi
log_ok "Management key replaced"

log_info "Changing PUK..."
if ! ykman -d "$SERIAL" piv access change-puk \
    --puk "$FACTORY_PUK" \
    --new-puk "$derived_puk"; then
    log_err "PUK change FAILED"
    log_err "WARNING: Management key was already changed. Input file NOT modified."
    exit 1
fi
log_ok "PUK replaced"

log_info "Changing PIN..."
if ! ykman -d "$SERIAL" piv access change-pin \
    --pin "$FACTORY_PIN" \
    --new-pin "$derived_pin"; then
    log_err "PIN change FAILED"
    log_err "WARNING: Management key and PUK were already changed. Input file NOT modified."
    exit 1
fi
log_ok "PIN replaced"

# =============================================================================
# Phase 2: OTP slot programming
# =============================================================================

echo ""
log_info "=== Phase 2: OTP slots ==="

program_otp_slot() {
    local slot_num="$1" aes_key="$2" private_id="$3"
    ykman -d "$SERIAL" otp yubiotp "$slot_num" \
        --key "$aes_key" \
        --private-id "$private_id" \
        --serial-public-id \
        --force
}

program_static_slot() {
    local slot_num="$1" password="$2"
    ykman -d "$SERIAL" otp static "$slot_num" "$password" \
        --keyboard-layout US --no-enter --force
}

log_info "Programming slot 1 ($slot1_mode)..."
if [[ "$slot1_mode" == "otp" ]]; then
    if ! program_otp_slot 1 "$s1_aes" "$s1_pid"; then
        log_err "Slot 1 programming FAILED — PIV was already changed. Input file NOT modified."
        exit 1
    fi
else
    if ! program_static_slot 1 "$s1_pw"; then
        log_err "Slot 1 programming FAILED — PIV was already changed. Input file NOT modified."
        exit 1
    fi
fi
log_ok "Slot 1 programmed ($slot1_mode)"

log_info "Programming slot 2 ($slot2_mode)..."
if [[ "$slot2_mode" == "otp" ]]; then
    if ! program_otp_slot 2 "$s2_aes" "$s2_pid"; then
        log_err "Slot 2 programming FAILED — PIV + slot 1 already changed. Input file NOT modified."
        exit 1
    fi
else
    if ! program_static_slot 2 "$s2_pw"; then
        log_err "Slot 2 programming FAILED — PIV + slot 1 already changed. Input file NOT modified."
        exit 1
    fi
fi
log_ok "Slot 2 programmed ($slot2_mode)"

# =============================================================================
# Phase 2B: FIDO2 PIN initialization
# =============================================================================

echo ""
log_info "=== Phase 2B: FIDO2 PIN ==="

# Reuse PIV PIN for FIDO2 — separate applications, operationally simpler
log_info "Setting FIDO2 PIN (same as PIV PIN for operational simplicity)..."
if ykman -d "$SERIAL" fido access change-pin --new-pin "$derived_pin" 2>/dev/null; then
    log_ok "FIDO2 PIN set"
elif ykman -d "$SERIAL" fido access change-pin \
    --pin "$derived_pin" --new-pin "$derived_pin" 2>/dev/null; then
    # Already has this PIN set — no-op
    log_ok "FIDO2 PIN already matches"
else
    # FIDO2 PIN may already be set to something else, or FIDO2 may be unavailable
    log_warn "FIDO2 PIN not set — may require manual reset: ykman -d $SERIAL fido reset"
fi

# =============================================================================
# Phase 3: Consume entropy lines from input file
# =============================================================================

echo ""
log_info "=== Phase 3: Cleanup ==="
log_info "Removing $LINES_REQUIRED consumed lines from input file..."

CONFIGURE_TMPFILE=$(mktemp "${INPUT_FILE}.tmp.XXXXXX")
tmpfile="$CONFIGURE_TMPFILE"
{
    line_num=0
    while IFS= read -r line; do
        line_num=$(( line_num + 1 ))
        skip=false
        for consumed in "${line_numbers_consumed[@]}"; do
            if [[ "$line_num" -eq "$consumed" ]]; then
                skip=true
                break
            fi
        done
        if [[ "$skip" == "false" ]]; then
            printf '%s\n' "$line"
        fi
    done < "$INPUT_FILE"
} > "$tmpfile"

mv "$tmpfile" "$INPUT_FILE"
CONFIGURE_TMPFILE=""  # Successfully moved — no cleanup needed
chmod 600 "$INPUT_FILE"
log_ok "Input file updated — $LINES_REQUIRED lines consumed"

# If file is now empty, securely remove it
remaining_check=$(grep -c '.' "$INPUT_FILE" 2>/dev/null || true)
if [[ "$remaining_check" -eq 0 ]]; then
    secure_delete "$INPUT_FILE" true
fi

# =============================================================================
# Verification and output
# =============================================================================

echo ""
log_info "=== Verification ==="
ykman -d "$SERIAL" otp info
ykman -d "$SERIAL" piv info
if [[ -f "$INPUT_FILE" ]]; then
    remaining=$(grep -c '.' "$INPUT_FILE" || true)
    log_info "Keys remaining in $INPUT_FILE: $remaining"
else
    log_info "Seed file was fully consumed and securely deleted"
fi

echo ""
log_ok "============================================"
log_ok " YubiKey $SERIAL — fully initialized"
log_ok "============================================"
log_ok "OTP Slot 1:  ${slot_desc[1]}"
log_ok "OTP Slot 2:  ${slot_desc[2]}"
log_ok "PIV Mgmt:    $derived_mgmt  ($MGMT_KEY_ALGO)"
log_ok "PIV PUK:     $derived_puk"
log_ok "FIDO2 PIN:   (same as PIV PIN)"
echo ""
printf "${GRN}${GRN}[PIN]${RST}  ${GRN}%s${RST}\n" "$derived_pin"
echo ""
log_warn "Record the PIN, PUK, and management key securely NOW."
log_warn "They cannot be recovered — only reset to factory defaults."
log_warn "Clear terminal scrollback after recording (secrets are visible above)."
if [[ "$slot1_mode" == "otp" || "$slot2_mode" == "otp" ]]; then
    log_warn "OTP slot(s) will NOT validate against YubiCloud (factory trust removed)."
fi
log_info "Done."

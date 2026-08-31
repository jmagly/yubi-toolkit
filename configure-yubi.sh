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
# Generated credential values are never printed; recovery output is opt-in.
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
    echo "Requires --derivation-profile v2 or legacy-v1. Generated values are not printed."
    exit 1
fi

MODE="$1"
SERIAL="$2"
INPUT_FILE="$3"
shift 3
RECOVERY_FILE=""
RECOVERY_RECIPIENT=""
DERIVATION_PROFILE=""
WITH_FIDO_PIN=false
STATE_FILE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --recovery-file) RECOVERY_FILE="$2"; shift 2 ;;
        --recovery-recipient) RECOVERY_RECIPIENT="$2"; shift 2 ;;
        --derivation-profile) DERIVATION_PROFILE="$2"; shift 2 ;;
        --with-fido-pin) WITH_FIDO_PIN=true; shift ;;
        --state-file) STATE_FILE="$2"; shift 2 ;;
        *) log_err "Unknown option: $1"; exit 1 ;;
    esac
done
if [[ -n "$RECOVERY_FILE" || -n "$RECOVERY_RECIPIENT" ]]; then
    [[ -n "$RECOVERY_FILE" && -n "$RECOVERY_RECIPIENT" ]] || {
        log_err "Recovery output requires both --recovery-file and --recovery-recipient"
        exit 1
    }
fi
case "$DERIVATION_PROFILE" in
    v2|legacy-v1) ;;
    *)
        log_err "Choose --derivation-profile v2 or legacy-v1; implicit migration is forbidden"
        exit 1
        ;;
esac
[[ -n "$STATE_FILE" && ! -L "$STATE_FILE" ]] || {
    log_err "A non-symlink --state-file is required for durable recovery state"
    exit 1
}

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
    if [[ "$_IS_MACOS" == "true" ]]; then
        log_err "ykman not found — install with: brew install ykman"
    else
        log_err "ykman not found — install with: sudo apt install yubikey-manager"
    fi
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

# Inventory product, firmware, interfaces, and applications before mutation.
yubikey_capability_preflight "$SERIAL"
fw_version="$DEVICE_FIRMWARE"
fw_major="$DEVICE_FW_MAJOR"
fw_minor="$DEVICE_FW_MINOR"
fw_patch="$DEVICE_FW_PATCH"

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

case "$MODE" in
    otp)    slot1_mode="otp";    slot2_mode="otp"    ;;
    static) slot1_mode="static"; slot2_mode="static" ;;
    mixed)  slot1_mode="otp";    slot2_mode="static" ;;
esac

slot1_desc=""
slot2_desc=""
if [[ "$DERIVATION_PROFILE" == "v2" ]]; then
    derived_pin=$(credential_v2_charset "$raw_pin" "$SERIAL" "piv/pin" "$PIV_PIN_LEN" "0123456789")
    derived_puk=$(credential_v2_charset "$raw_puk" "$SERIAL" "piv/puk" "$PIV_PUK_LEN" "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    derived_mgmt=$(credential_v2_hkdf_hex "$raw_mgmt" "$SERIAL" "piv/management-key/$MGMT_KEY_ALGO" 0 "$PIV_MGMT_KEY_LEN")
    derived_fido_pin=$(credential_v2_charset "$raw_pin" "$SERIAL" "fido2/pin" 8 "0123456789")
    if [[ "$slot1_mode" == "otp" ]]; then
        s1_aes=$(credential_v2_hkdf_hex "$raw_slot1" "$SERIAL" "otp/slot1/aes-key" 0 "$OTP_AES_KEY_LEN")
        s1_pid=$(credential_v2_hkdf_hex "$raw_slot1" "$SERIAL" "otp/slot1/private-id" 0 "$OTP_PRIVATE_ID_LEN")
        slot1_desc="Yubico OTP credential"
    else
        s1_pw=$(credential_v2_charset "$raw_slot1" "$SERIAL" "otp/slot1/static-password" "$MAX_STATIC_LEN" "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        slot1_desc="static password (US layout, ${#s1_pw} chars)"
    fi
    if [[ "$slot2_mode" == "otp" ]]; then
        s2_aes=$(credential_v2_hkdf_hex "$raw_slot2" "$SERIAL" "otp/slot2/aes-key" 0 "$OTP_AES_KEY_LEN")
        s2_pid=$(credential_v2_hkdf_hex "$raw_slot2" "$SERIAL" "otp/slot2/private-id" 0 "$OTP_PRIVATE_ID_LEN")
        slot2_desc="Yubico OTP credential"
    else
        s2_pw=$(credential_v2_charset "$raw_slot2" "$SERIAL" "otp/slot2/static-password" "$MAX_STATIC_LEN" "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        slot2_desc="static password (US layout, ${#s2_pw} chars)"
    fi
else
    pin_hex=$(hkdf_derive_hex "$raw_pin" "yubikey-piv-pin" "$PIV_PIN_LEN")
    derived_pin=$(hex_to_numeric "$pin_hex" "$PIV_PIN_LEN")
    puk_hex=$(hkdf_derive_hex "$raw_puk" "yubikey-piv-puk" "$PIV_PUK_LEN")
    derived_puk=$(hex_to_alphanum "$puk_hex" "$PIV_PUK_LEN")
    derived_mgmt=$(hkdf_derive_hex "$raw_mgmt" "yubikey-piv-mgmt-key" "$PIV_MGMT_KEY_LEN")
    derived_fido_pin="$derived_pin"
    if [[ "$slot1_mode" == "otp" ]]; then
        s1_aes=$(hkdf_derive_hex "$raw_slot1" "yubiotp-aes-key-slot1" "$OTP_AES_KEY_LEN")
        s1_pid=$(hkdf_derive_hex "$raw_slot1" "yubiotp-private-id-slot1" "$OTP_PRIVATE_ID_LEN")
        slot1_desc="Yubico OTP credential"
    else
        s1_pw=$(hex_to_alphanum "$(hkdf_derive_hex "$raw_slot1" "static-password-slot1" "$MAX_STATIC_LEN")" "$MAX_STATIC_LEN")
        slot1_desc="static password (US layout, ${#s1_pw} chars)"
    fi
    if [[ "$slot2_mode" == "otp" ]]; then
        s2_aes=$(hkdf_derive_hex "$raw_slot2" "yubiotp-aes-key-slot2" "$OTP_AES_KEY_LEN")
        s2_pid=$(hkdf_derive_hex "$raw_slot2" "yubiotp-private-id-slot2" "$OTP_PRIVATE_ID_LEN")
        slot2_desc="Yubico OTP credential"
    else
        s2_pw=$(hex_to_alphanum "$(hkdf_derive_hex "$raw_slot2" "static-password-slot2" "$MAX_STATIC_LEN")" "$MAX_STATIC_LEN")
        slot2_desc="static password (US layout, ${#s2_pw} chars)"
    fi
fi

# =============================================================================
# Secret-safe programming adapter
# =============================================================================

echo ""
log_info "=== CONFIGURATION PLAN ==="
log_info "Target:      YubiKey $SERIAL"
log_info "OTP Slot 1:  ${slot1_desc}"
log_info "OTP Slot 2:  ${slot2_desc}"
log_info "PIV:         unique PIN, PUK, and ${MGMT_KEY_ALGO} management key"
if [[ "$WITH_FIDO_PIN" == true ]]; then
    log_info "FIDO2:       set an independent PIN"
else
    log_info "FIDO2:       outside requested scope"
fi
log_info "Derivation:  $DERIVATION_PROFILE"
log_info "Recovery:    ${RECOVERY_FILE:-disabled}"
echo ""
printf "${YLW}This operation replaces the configured PIV and OTP credentials.${RST}\n"
printf "Type YES to proceed: "
read -r confirm
if [[ "$confirm" != "YES" ]]; then
    log_info "Aborted."
    exit 0
fi

CONFIGURE_TMPFILE=$(mktemp "$(dirname "$INPUT_FILE")/.program-descriptor.XXXXXX")
descriptor="$CONFIGURE_TMPFILE"
chmod 600 "$descriptor"
if [[ "$slot1_mode" == "otp" ]]; then
    slot1_json=$(printf '{"kind":"yubiotp","aes_key":"%s","private_id":"%s"}' "$s1_aes" "$s1_pid")
else
    slot1_json=$(printf '{"kind":"static","password":"%s"}' "$s1_pw")
fi
if [[ "$slot2_mode" == "otp" ]]; then
    slot2_json=$(printf '{"kind":"yubiotp","aes_key":"%s","private_id":"%s"}' "$s2_aes" "$s2_pid")
else
    slot2_json=$(printf '{"kind":"static","password":"%s"}' "$s2_pw")
fi
scope_json='["piv","otp"]'
[[ "$WITH_FIDO_PIN" == true ]] && scope_json='["piv","otp","fido2"]'
printf '{"serial":%s,"management_algorithm":"%s","management_key":"%s","pin":"%s","puk":"%s","slot1":%s,"slot2":%s,"fido_pin":"%s","derivation_profile":"%s","scope":%s}\n' \
    "$SERIAL" "$MGMT_KEY_ALGO" "$derived_mgmt" "$derived_pin" "$derived_puk" \
    "$slot1_json" "$slot2_json" "$derived_fido_pin" "$DERIVATION_PROFILE" "$scope_json" > "$descriptor"

state_update() {
    local status="$1" phase="$2" completed="$3" guidance="$4" tmp
    tmp=$(mktemp "$(dirname "$STATE_FILE")/.$(basename "$STATE_FILE").XXXXXX")
    chmod 600 "$tmp"
    printf '{"version":1,"serial":%s,"scope":%s,"status":"%s","phase":"%s","completed":%s,"guidance":"%s"}\n' \
        "$SERIAL" "$scope_json" "$status" "$phase" "$completed" "$guidance" > "$tmp"
    mv -f "$tmp" "$STATE_FILE"
}

adapter_phase() {
    local phase="$1" completed="$2" failure_status="$3" result result_status=0
    if [[ -n "${YUBI_PROGRAMMER:-}" ]]; then
        result=$("$YUBI_PROGRAMMER" "--phase=$phase" < "$descriptor") || result_status=$?
    else
        result=$(python3 "$SCRIPT_DIR/yubikey-programmer.py" "--phase=$phase" < "$descriptor") || result_status=$?
    fi
    if [[ "${result_status:-0}" -ne 0 ]]; then
        state_update "$failure_status" "$phase" "$completed" "Inspect this redacted state and the encrypted recovery record; do not reuse the pending pool."
        log_err "$phase phase failed; durable recovery state was written"
        exit 1
    fi
    [[ "$result" == *'"ok": true'* ]] || {
        state_update "$failure_status" "$phase" "$completed" "Adapter response was invalid; do not reuse the pending pool."
        exit 1
    }
}

state_update "in-progress" "preflight" '[]' "Preflight is running; no device mutation has occurred."
adapter_phase preflight '[]' failed
state_update "in-progress" "preflight-complete" '[]' "Preflight passed; no device mutation has occurred."
if [[ "${YUBI_FAULT_AFTER_PHASE:-}" == "preflight" ]]; then
    state_update failed "fault-after-preflight" '[]' "Injected failure after preflight; no device mutation occurred."
    exit 90
fi

if [[ -n "$RECOVERY_FILE" ]]; then
    command -v age >/dev/null 2>&1 || { state_update failed recovery '[]' "age is unavailable; no device mutation occurred."; exit 1; }
    recovery_tmp="${RECOVERY_FILE}.tmp.$$"
    umask 077
    if ! age -r "$RECOVERY_RECIPIENT" < "$descriptor" > "$recovery_tmp"; then
        rm -f "$recovery_tmp"
        state_update failed recovery '[]' "Recovery encryption failed; no device mutation occurred."
        exit 1
    fi
    chmod 600 "$recovery_tmp"
    mv -f "$recovery_tmp" "$RECOVERY_FILE"
    log_ok "Encrypted recovery record written"
fi

adapter_phase piv '[]' partial
state_update in-progress piv-complete '["piv"]' "PIV postconditions passed; continue with OTP using the same recovery record."
if [[ "${YUBI_FAULT_AFTER_PHASE:-}" == "piv" ]]; then
    state_update partial fault-after-piv '["piv"]' "PIV completed; OTP and FIDO2 were not attempted."
    exit 90
fi

adapter_phase otp '["piv"]' partial
state_update in-progress otp-complete '["piv","otp"]' "PIV and OTP postconditions passed."
if [[ "${YUBI_FAULT_AFTER_PHASE:-}" == "otp" ]]; then
    state_update partial fault-after-otp '["piv","otp"]' "PIV and OTP completed; optional FIDO2 was not attempted."
    exit 90
fi

completed='["piv","otp"]'
if [[ "$WITH_FIDO_PIN" == true ]]; then
    adapter_phase fido2 "$completed" partial
    completed='["piv","otp","fido2"]'
    state_update in-progress fido2-complete "$completed" "All requested application postconditions passed."
    if [[ "${YUBI_FAULT_AFTER_PHASE:-}" == "fido2" ]]; then
        state_update partial fault-after-fido2 "$completed" "All mutations passed, but final commit did not run; reconcile before consuming seeds."
        exit 90
    fi
fi
state_update complete complete "$completed" "All requested application postconditions passed; seed consumption may commit."
: > "$descriptor"
rm -f "$descriptor"
CONFIGURE_TMPFILE=""
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

# If the volatile file is now empty, remove it.
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
    log_info "Seed file was fully consumed and removed"
fi

echo ""
log_ok "============================================"
log_ok " YubiKey $SERIAL — requested application scope complete"
log_ok "============================================"
log_ok "OTP Slot 1:  ${slot1_desc}"
log_ok "OTP Slot 2:  ${slot2_desc}"
log_ok "PIV credentials: programmed (values not displayed)"
if [[ "$WITH_FIDO_PIN" == true ]]; then
    log_ok "FIDO2 PIN:       programmed (value not displayed)"
else
    log_info "FIDO2 PIN:       unchanged (outside requested scope)"
fi
if [[ -n "$RECOVERY_FILE" ]]; then
    log_ok "Recovery record: encrypted operator-selected sink"
else
    log_warn "Recovery output was disabled; generated credentials were not retained"
fi
if [[ "$slot1_mode" == "otp" || "$slot2_mode" == "otp" ]]; then
    log_warn "OTP slot(s) will NOT validate against YubiCloud (factory trust removed)."
fi
log_info "Done."

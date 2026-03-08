#!/usr/bin/env bash
# yubi-mux.sh — Collect passwords from 2 YubiKeys and randomly pair them
#
# Collects N passwords from device 1, then N from device 2.
# Randomly pairs one from each side (Fisher-Yates shuffle).
# Random which side comes first in each compound password.
# Output: one compound password per line.
#
# Usage: ./yubi-mux.sh <output_file>

set -euo pipefail

# --- Logging ---
RED='\033[0;31m'
YLW='\033[0;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
RST='\033[0m'

log_info()  { printf "${CYN}[INFO]${RST}  %s\n" "$*"; }
log_ok()    { printf "${GRN}[OK]${RST}    %s\n" "$*"; }
log_warn()  { printf "${YLW}[WARN]${RST}  %s\n" "$*"; }
log_err()   { printf "${RED}[ERR]${RST}   %s\n" "$*" >&2; }

# --- Arguments ---
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <output_file>"
    echo ""
    echo "Collects passwords from 2 YubiKeys, randomly pairs them."
    echo "Tap each YubiKey to enter passwords, one per line."
    echo "Press Enter on an empty line when done with each device."
    exit 1
fi

OUTPUT_FILE="$1"

# Show masked preview: first 5 + "..." + last 5 chars
mask_pw() {
    local pw="$1"
    local len=${#pw}
    if [[ "$len" -le 10 ]]; then
        printf '%s' "${pw:0:2}..${pw: -2}"
    else
        printf '%s' "${pw:0:5}...${pw: -5}"
    fi
}

# --- Collect from device 1 ---
echo ""
log_info "=== Device 1 ==="
log_info "Tap YubiKey 1 to enter passwords. Empty line when done."
echo ""

declare -a dev1=()
while true; do
    printf "  [D1 #%d] " "$(( ${#dev1[@]} + 1 ))"
    IFS= read -rs line
    [[ -z "$line" ]] && printf "\n" && break
    dev1+=("$line")
    printf "%s\n" "$(mask_pw "$line")"
done

if [[ ${#dev1[@]} -eq 0 ]]; then
    log_err "No passwords entered for device 1"
    exit 1
fi
log_ok "Device 1: ${#dev1[@]} passwords collected"

# --- Collect from device 2 ---
echo ""
log_info "=== Device 2 ==="
log_info "Tap YubiKey 2 to enter passwords. Empty line when done."
echo ""

declare -a dev2=()
while true; do
    printf "  [D2 #%d] " "$(( ${#dev2[@]} + 1 ))"
    IFS= read -rs line
    [[ -z "$line" ]] && printf "\n" && break
    dev2+=("$line")
    printf "%s\n" "$(mask_pw "$line")"
done

if [[ ${#dev2[@]} -eq 0 ]]; then
    log_err "No passwords entered for device 2"
    exit 1
fi
log_ok "Device 2: ${#dev2[@]} passwords collected"

# --- Determine pair count ---
count1=${#dev1[@]}
count2=${#dev2[@]}
pair_count=$(( count1 < count2 ? count1 : count2 ))

if [[ "$count1" -ne "$count2" ]]; then
    log_warn "Unequal counts: D1=$count1, D2=$count2 — using $pair_count pairs"
    log_warn "$(( (count1 > count2 ? count1 : count2) - pair_count )) password(s) will be discarded"
fi

log_info "Creating $pair_count compound passwords"

# --- Fisher-Yates shuffle both arrays independently ---
shuffle_array() {
    local -n arr=$1
    local n=${#arr[@]}
    for (( i=n-1; i>0; i-- )); do
        local j=$(( $(od -An -tu4 -N4 /dev/urandom | tr -d ' ') % (i + 1) ))
        local tmp="${arr[$i]}"
        arr[$i]="${arr[$j]}"
        arr[$j]="$tmp"
    done
}

shuffle_array dev1
shuffle_array dev2

# --- Pair and randomize concatenation order ---
declare -a output=()
for (( i=0; i<pair_count; i++ )); do
    # Random bit: 0 = D1 first, 1 = D2 first
    order_bit=$(( $(od -An -tu1 -N1 /dev/urandom | tr -d ' ') % 2 ))
    if [[ "$order_bit" -eq 0 ]]; then
        output+=("${dev1[$i]}${dev2[$i]}")
    else
        output+=("${dev2[$i]}${dev1[$i]}")
    fi
done

# --- Write output ---
printf '%s\n' "${output[@]}" > "$OUTPUT_FILE"
chmod 600 "$OUTPUT_FILE"

log_ok "$pair_count compound passwords written to $OUTPUT_FILE (mode 600)"
log_info "Next: ./configure-yubi.sh <MODE> <SERIAL> $OUTPUT_FILE"

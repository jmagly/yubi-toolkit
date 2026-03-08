#!/usr/bin/env bash
# init-yubi.sh — End-to-end YubiKey initialization from 2 source devices
#
# Pipeline:
#   1. Collect passwords from 2 existing YubiKeys (tap to enter)
#   2. Randomly pair into compound passwords (yubi-mux.sh)
#   3. Select 5 random lines for the target key
#   4. Enrich those 5 with local + external entropy (entropy-mix.sh logic)
#   5. Program the target YubiKey (configure-yubi.sh)
#
# External APIs are only called at step 4 — when committing to specific seeds.
#
# Usage: ./init-yubi.sh <MODE> <SERIAL>
#   MODE:   "otp", "static", or "mixed"
#   SERIAL: target YubiKey serial number
#
# Requires: ykman, openssl, curl, sensors

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Shared library ---
source "$SCRIPT_DIR/yubi-lib.sh"

# --- Arguments ---
if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <MODE> <SERIAL>"
    echo ""
    echo "  MODE:   'otp'    = both OTP slots Yubico OTP"
    echo "          'static' = both OTP slots static password"
    echo "          'mixed'  = slot 1 OTP + slot 2 static"
    echo "  SERIAL: target YubiKey serial (run 'ykman list --serials')"
    echo ""
    echo "You will be prompted to tap 2 source YubiKeys for entropy input."
    exit 1
fi

MODE="$1"
SERIAL="$2"
LINES_REQUIRED=5

# --- Verify scripts exist ---
for script in yubi-mux.sh entropy-mix.sh configure-yubi.sh; do
    if [[ ! -x "$SCRIPT_DIR/$script" ]]; then
        log_err "Required script not found: $SCRIPT_DIR/$script"
        exit 1
    fi
done

# --- Secure working directory ---
WORKDIR=$(secure_tmpfs_create "init-yubi")
trap secure_tmpfs_cleanup EXIT

MUX_FILE="$WORKDIR/muxed.txt"
ENRICHED_FILE="$WORKDIR/enriched.txt"

# =============================================================================
# Step 1: Collect passwords from 2 source YubiKeys
# =============================================================================

echo ""
log_info "============================================"
log_info " Step 1: Collect entropy from source keys"
log_info "============================================"
echo ""
log_info "You need 2 source YubiKeys with static passwords."
log_info "Tap each key to enter passwords. At least $LINES_REQUIRED from each."
log_info "Empty line when done with each device."

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

# --- Device 1 ---
echo ""
log_info "=== Source Device 1 ==="
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
log_ok "Device 1: ${#dev1[@]} passwords"

# --- Device 2 ---
echo ""
log_info "=== Source Device 2 ==="
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
log_ok "Device 2: ${#dev2[@]} passwords"

# --- Determine pair count ---
count1=${#dev1[@]}
count2=${#dev2[@]}
pair_count=$(( count1 < count2 ? count1 : count2 ))

if [[ "$pair_count" -lt "$LINES_REQUIRED" ]]; then
    log_err "Need at least $LINES_REQUIRED pairs but can only make $pair_count"
    log_err "Provide at least $LINES_REQUIRED passwords from each device"
    exit 1
fi

if [[ "$count1" -ne "$count2" ]]; then
    log_warn "Unequal counts: D1=$count1, D2=$count2 — using $pair_count pairs"
fi

# =============================================================================
# Step 1B: Interactive entropy (keyboard timing + mouse movement)
# =============================================================================

echo ""
log_info "============================================"
log_info " Step 1B: Interactive entropy collection"
log_info "============================================"
echo ""

KEYS_PER_ROUND=50
MOUSE_SAMPLES=80
MOUSE_INTERVAL_MS=50

# --- Keyboard timing ---
KEY_ENTROPY=""

collect_keyboard_round() {
    local round_num="$1"
    local chars_needed="$KEYS_PER_ROUND"

    printf "${CYN}[Round %d]${RST} Type %d random characters, then press Enter:\n" \
        "$round_num" "$chars_needed"
    printf "  ${DIM}>"

    local result
    result=$(python3 -c "
import sys, time, tty, termios

fd = sys.stdin.fileno()
old = termios.tcgetattr(fd)
try:
    tty.setraw(fd)
    timings = []
    chars = []
    prev = time.time_ns()
    count = 0
    while count < $chars_needed:
        ch = sys.stdin.read(1)
        now = time.time_ns()
        if ord(ch) == 13 or ord(ch) == 10:
            if count > 0:
                break
            continue
        if ord(ch) == 3:
            break
        timings.append(str(now - prev))
        chars.append(str(ord(ch)))
        prev = now
        count += 1
        sys.stderr.write('.')
        sys.stderr.flush()
    print('|'.join([','.join(timings), ','.join(chars)]))
finally:
    termios.tcsetattr(fd, termios.TCSADRAIN, old)
" 2>&1)

    local data_line
    data_line=$(echo "$result" | tail -1)
    printf "${RST}\n"

    if [[ -z "$data_line" || "$data_line" != *"|"* ]]; then
        log_warn "Round $round_num: incomplete capture, using what we got"
        printf '%s:%s' "$result" "$(date +%s%N)" \
            | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}'
        return
    fi

    local timings="${data_line%%|*}"
    local chars="${data_line##*|}"

    local timing_hash
    timing_hash=$(printf '%s' "$timings" \
        | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}')
    local char_hash
    char_hash=$(printf '%s' "$chars" \
        | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}')

    printf '%s:%s:%s' "$timing_hash" "$char_hash" "$(date +%s%N)" \
        | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}'
}

log_info "Type random characters — the TIMING between keystrokes is the entropy."
echo ""

for round in 1 2; do
    round_entropy=$(collect_keyboard_round "$round")
    KEY_ENTROPY+="$round_entropy"
    log_ok "Round $round captured"
    echo ""
done

log_ok "Keyboard entropy: ${#KEY_ENTROPY} hex chars collected"

# --- Mouse movement ---
MOUSE_ENTROPY=""
MOUSE_AVAILABLE=false

if python3 -c "
import ctypes, ctypes.util
x11 = ctypes.cdll.LoadLibrary(ctypes.util.find_library('X11'))
d = x11.XOpenDisplay(None)
if d: x11.XCloseDisplay(d); exit(0)
else: exit(1)
" 2>/dev/null; then
    MOUSE_AVAILABLE=true
fi

if [[ "$MOUSE_AVAILABLE" == "true" ]]; then
    echo ""
    log_info "Move your mouse around randomly for about 5 seconds."
    printf "${DIM}Press Enter when ready, then start moving...${RST}"
    read -r
    printf "${CYN}[Sampling]${RST} Move the mouse now"

    MOUSE_ENTROPY=$(python3 -c "
import ctypes, ctypes.util, time, hashlib, sys

x11 = ctypes.cdll.LoadLibrary(ctypes.util.find_library('X11'))
display = x11.XOpenDisplay(None)
root = x11.XDefaultRootWindow(display)

root_ret = ctypes.c_ulong()
child_ret = ctypes.c_ulong()
rx, ry, wx, wy = ctypes.c_int(), ctypes.c_int(), ctypes.c_int(), ctypes.c_int()
mask = ctypes.c_uint()

samples = []
for i in range($MOUSE_SAMPLES):
    x11.XQueryPointer(display, root,
        ctypes.byref(root_ret), ctypes.byref(child_ret),
        ctypes.byref(rx), ctypes.byref(ry),
        ctypes.byref(wx), ctypes.byref(wy),
        ctypes.byref(mask))
    t = time.time_ns()
    samples.append(f'{rx.value},{ry.value},{t}')
    if i % 10 == 0:
        sys.stderr.write('.')
        sys.stderr.flush()
    time.sleep($MOUSE_INTERVAL_MS / 1000.0)

x11.XCloseDisplay(display)
raw = ':'.join(samples)
h = hashlib.sha512(raw.encode()).hexdigest()
print(h)
" 2>&1)

    mouse_hash=$(echo "$MOUSE_ENTROPY" | tail -1)
    MOUSE_ENTROPY="$mouse_hash"
    printf "\n"
    log_ok "Mouse entropy: ${#MOUSE_ENTROPY} hex chars collected"
else
    log_info "No X11 display — collecting extra keyboard entropy instead"
    echo ""
    extra_round=$(collect_keyboard_round 3)
    MOUSE_ENTROPY="$extra_round"
    log_ok "Extra keyboard round captured"
fi

# =============================================================================
# Step 2: Mux — randomly pair with random concatenation order
# =============================================================================

echo ""
log_info "============================================"
log_info " Step 2: Mux source passwords"
log_info "============================================"

# Fisher-Yates shuffle both arrays independently
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

# Pair with random order
declare -a muxed=()
for (( i=0; i<pair_count; i++ )); do
    order_bit=$(( $(od -An -tu1 -N1 /dev/urandom | tr -d ' ') % 2 ))
    if [[ "$order_bit" -eq 0 ]]; then
        muxed+=("${dev1[$i]}${dev2[$i]}")
    else
        muxed+=("${dev2[$i]}${dev1[$i]}")
    fi
done

printf '%s\n' "${muxed[@]}" > "$MUX_FILE"
chmod 600 "$MUX_FILE"
log_ok "$pair_count compound passwords created"

# =============================================================================
# Step 3: Select 5 random lines for this target key
# =============================================================================

echo ""
log_info "============================================"
log_info " Step 3: Select $LINES_REQUIRED seeds for target key"
log_info "============================================"

# Fisher-Yates partial shuffle to pick 5
declare -a pick_indices=()
declare -a avail=()
for (( i=0; i<pair_count; i++ )); do avail+=("$i"); done

for (( p=0; p<LINES_REQUIRED; p++ )); do
    rem=$(( pair_count - p ))
    r=$(( $(od -An -tu4 -N4 /dev/urandom | tr -d ' ') % rem ))
    pick_indices+=("${avail[$r]}")
    avail[$r]="${avail[$(( rem - 1 ))]}"
done

declare -a selected_raw=()
for idx in "${pick_indices[@]}"; do
    selected_raw+=("${muxed[$idx]}")
done

log_ok "Selected indices: ${pick_indices[*]}"
log_info "  Slot 1 seed:     index ${pick_indices[0]}"
log_info "  Slot 2 seed:     index ${pick_indices[1]}"
log_info "  PIN seed:        index ${pick_indices[2]}"
log_info "  PUK seed:        index ${pick_indices[3]}"
log_info "  Mgmt key seed:   index ${pick_indices[4]}"

# =============================================================================
# Step 4: Enrich selected seeds with local + external entropy
# =============================================================================

echo ""
log_info "============================================"
log_info " Step 4: Entropy enrichment (API calls now)"
log_info "============================================"

# --- External entropy (batched, retry+degrade) ---
RETRY_MAX=3
RETRY_DELAY=2

call_external() {
    local name="$1"; shift
    local attempt=0
    local response=""
    while (( attempt < RETRY_MAX )); do
        attempt=$(( attempt + 1 ))
        response=$(curl -sf --max-time 10 "$@" 2>/dev/null) && break
        log_warn "$name: attempt $attempt/$RETRY_MAX failed"
        sleep "$RETRY_DELAY"
        response=""
    done
    if [[ -z "$response" ]]; then
        log_warn "$name: ALL RETRIES FAILED — degrading"
        echo ""; return 1
    fi
    echo "$response"; return 0
}

ext_sources_ok=0

log_info "Fetching random.org..."
random_org_raw=""
if random_org_raw=$(call_external "random.org" \
    "https://www.random.org/integers/?num=3&min=0&max=1000000000&col=1&base=10&format=plain&rnd=new"); then
    log_ok "random.org"
    ext_sources_ok=$(( ext_sources_ok + 1 ))
fi

log_info "Fetching NIST Beacon..."
nist_raw=""
if nist_raw=$(call_external "NIST Beacon" \
    "https://beacon.nist.gov/beacon/2.0/pulse/last"); then
    log_ok "NIST Beacon"
    ext_sources_ok=$(( ext_sources_ok + 1 ))
fi

log_info "Fetching drand..."
drand_raw=""
if drand_raw=$(call_external "drand" \
    "https://drand.cloudflare.com/public/latest"); then
    log_ok "drand"
    ext_sources_ok=$(( ext_sources_ok + 1 ))
fi

log_info "External sources: $ext_sources_ok/3"

# --- Local entropy baselines ---
log_info "Collecting local sensor baselines..."

thermal_base=""
for tz in /sys/class/thermal/thermal_zone*/temp; do
    [[ -f "$tz" ]] && thermal_base+="$(cat "$tz")"
done
thermal_base+="$(sensors -u 2>/dev/null | tr -d ' \n')"
thermal_base=$(printf '%s' "$thermal_base" | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}')

jitter_base=""
for j in {1..8}; do
    t_start=$(date +%s%N)
    dd if=/dev/urandom bs=512 count=1 of=/dev/null 2>/dev/null
    t_end=$(date +%s%N)
    jitter_base+="$((t_end - t_start))"
done
jitter_base=$(printf '%s' "$jitter_base" | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}')

log_ok "Local baselines collected"

# --- Enrich each selected seed via HKDF-SHA512 ---
HKDF_KEYLEN=32

enrich_seed() {
    local raw_seed="$1"
    local seed_label="$2"

    # Fresh local entropy
    local cpu_ent
    cpu_ent=$(openssl rand -hex 32)

    # Fresh thermal read + timestamp
    local thermal_ent=""
    for tz in /sys/class/thermal/thermal_zone*/temp; do
        [[ -f "$tz" ]] && thermal_ent+="$(cat "$tz")"
    done
    thermal_ent+="$(date +%s%N)${thermal_base}"
    thermal_ent=$(printf '%s' "$thermal_ent" | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}')

    # Fresh jitter sample + timestamp
    local t_s t_e jitter_ent
    t_s=$(date +%s%N)
    dd if=/dev/urandom bs=64 count=1 of=/dev/null 2>/dev/null
    t_e=$(date +%s%N)
    jitter_ent=$(printf '%s:%s:%s' "$jitter_base" "$((t_e - t_s))" "$(date +%s%N)" \
        | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}')

    # Per-seed external entropy slices
    local ext1 ext2 ext3
    ext1=$(printf '%s:%s:%s' "$random_org_raw" "$seed_label" "$(openssl rand -hex 8)" \
        | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}')
    ext2=$(printf '%s:%s:%s' "$nist_raw" "$seed_label" "$(openssl rand -hex 8)" \
        | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}')
    ext3=$(printf '%s:%s:%s' "$drand_raw" "$seed_label" "$(openssl rand -hex 8)" \
        | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}')

    # Build salt from all non-seed entropy
    local salt_hex="${cpu_ent}${thermal_ent}${jitter_ent}${ext1}${ext2}${ext3}"

    # IKM is compound password + interactive entropy (keyboard timing + mouse)
    local ikm_hex
    ikm_hex=$(printf '%s:%s:%s' "$raw_seed" "$KEY_ENTROPY" "$MOUSE_ENTROPY" \
        | xxd -p | tr -d '\n')

    local info_hex
    info_hex=$(printf '%s' "init-yubi-enrich-v1-${seed_label}" | xxd -p | tr -d '\n')

    # HKDF-SHA512 mix
    openssl kdf -keylen "$HKDF_KEYLEN" \
        -kdfopt digest:SHA512 \
        -kdfopt "hexkey:${ikm_hex}" \
        -kdfopt "hexsalt:${salt_hex}" \
        -kdfopt "hexinfo:${info_hex}" \
        HKDF 2>/dev/null \
        | tr -d ':' | xxd -r -p | openssl base64 -A
}

log_info "Enriching 5 selected seeds..."
declare -a enriched=()
labels=("slot1" "slot2" "pin" "puk" "mgmt")
for (( i=0; i<LINES_REQUIRED; i++ )); do
    enriched+=("$(enrich_seed "${selected_raw[$i]}" "${labels[$i]}")")
    printf "\r${CYN}[INFO]${RST}  Enriched: %d/%d" "$(( i + 1 ))" "$LINES_REQUIRED"
done
printf "\n"
log_ok "All 5 seeds enriched with local + external entropy"

# Write enriched seeds to temp file for configure-yubi.sh
printf '%s\n' "${enriched[@]}" > "$ENRICHED_FILE"
chmod 600 "$ENRICHED_FILE"

# =============================================================================
# Step 5: Configure the target YubiKey
# =============================================================================

echo ""
log_info "============================================"
log_info " Step 5: Program YubiKey $SERIAL"
log_info "============================================"

# configure-yubi.sh will pick randomly from the file, but we only have
# exactly 5 lines so all will be used. Pass through to it.
"$SCRIPT_DIR/configure-yubi.sh" "$MODE" "$SERIAL" "$ENRICHED_FILE"

# =============================================================================
# Step 6: Clean up mux pool (remove used compound passwords)
# =============================================================================

# The enriched tempfile is cleaned by trap. The mux file was ephemeral.
# Nothing persists to disk after this script exits.

echo ""
log_ok "Working files will be securely wiped on exit."
log_info "init-yubi complete."

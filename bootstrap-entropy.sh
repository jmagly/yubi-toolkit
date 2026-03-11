#!/usr/bin/env bash
# bootstrap-entropy.sh — Generate entropy seeds from scratch for new users
#
# For users with no existing source of hardware entropy (no configured YubiKeys).
# Collects entropy from multiple interactive and system sources:
#
#   Interactive (user-driven):
#     - Random keyboard typing with inter-keystroke timing (nanoseconds)
#     - Mouse movement sampling (position + timing via X11)
#
#   Local system:
#     - CPU RDRAND (/dev/urandom)
#     - Thermal sensors (sysfs + lm-sensors)
#     - Disk I/O timing jitter
#
#   External APIs (retry + degrade):
#     - random.org (atmospheric noise)
#     - NIST Beacon (randomness beacon)
#     - drand (distributed randomness beacon)
#
# Each seed is mixed via HKDF-SHA512 from all available sources.
# Output: 10-20 base64 seeds (one per line), ready for configure-yubi.sh.
#
# Usage: ./bootstrap-entropy.sh <output_file> [count]
#   output_file: where to write seeds
#   count:       number of seeds to generate (default: 15, range: 10-20)
#
# Requires: openssl, curl, sensors, python3 (for mouse capture)

set -euo pipefail
umask 077       # New files owner-only
ulimit -c 0     # Disable core dumps

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/yubi-lib.sh"

# =============================================================================
# Configuration
# =============================================================================

HKDF_KEYLEN=32       # 32 bytes = 44 char base64 per seed
MIN_SEEDS=10
MAX_SEEDS=20
DEFAULT_SEEDS=15

# Keyboard collection: characters needed per round
KEYS_PER_ROUND=50
# Mouse collection: samples per round
MOUSE_SAMPLES=80
MOUSE_INTERVAL_MS=50  # milliseconds between samples

log_step()  { printf "\n${BLD}${CYN}>>> %s${RST}\n\n" "$*"; }

# =============================================================================
# Arguments
# =============================================================================

if [[ $# -lt 1 ]]; then
    cat <<'USAGE'
Usage: bootstrap-entropy.sh <output_file> [count] [extra_data_file] [options]

  output_file:      where to write seeds (one base64 per line)
  count:            number of seeds (default: 15, range: 10-20)
  extra_data_file:  optional file with extra entropy (one value per line)

Options:
  --no-external         Skip external API calls (local entropy only)
  --entropy-file PATH   Use pre-collected entropy file instead of live APIs
  --image-dir PATH      Hash image files as additional entropy (SHA-256, one per file)

Generates high-quality entropy seeds from interactive + system + external
sources for users who don't yet have configured YubiKeys.

Output is compatible with configure-yubi.sh and entropy-mix.sh.
USAGE
    exit 1
fi

# Parse positional and flag arguments
OUTPUT_FILE=""
SEED_COUNT="$DEFAULT_SEEDS"
EXTRA_FILE=""
NO_EXTERNAL=false
ENTROPY_FILE_PATH=""
IMAGE_DIR=""

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
        --image-dir)
            IMAGE_DIR="$2"
            shift 2
            ;;
        -*)
            log_err "Unknown option: $1"
            exit 1
            ;;
        *)
            if [[ -z "$OUTPUT_FILE" ]]; then
                OUTPUT_FILE="$1"
            elif [[ "$SEED_COUNT" == "$DEFAULT_SEEDS" && "$1" =~ ^[0-9]+$ ]]; then
                SEED_COUNT="$1"
            elif [[ -z "$EXTRA_FILE" ]]; then
                EXTRA_FILE="$1"
            fi
            shift
            ;;
    esac
done

if [[ "$SEED_COUNT" -lt "$MIN_SEEDS" || "$SEED_COUNT" -gt "$MAX_SEEDS" ]]; then
    log_err "Seed count must be between $MIN_SEEDS and $MAX_SEEDS (got: $SEED_COUNT)"
    exit 1
fi

# --- Load optional extra entropy file ---
declare -a EXTRA_POOL=()
if [[ -n "$EXTRA_FILE" ]]; then
    if [[ ! -f "$EXTRA_FILE" ]]; then
        log_err "Extra data file not found: $EXTRA_FILE"
        exit 1
    fi
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        EXTRA_POOL+=("$line")
    done < "$EXTRA_FILE"
    if [[ ${#EXTRA_POOL[@]} -eq 0 ]]; then
        log_err "Extra data file is empty: $EXTRA_FILE"
        exit 1
    fi
    log_ok "Extra entropy loaded: ${#EXTRA_POOL[@]} lines from $(basename "$EXTRA_FILE")"
fi

# --- Load image directory entropy ---
if [[ -n "$IMAGE_DIR" ]]; then
    if [[ ! -d "$IMAGE_DIR" ]]; then
        log_err "Image directory not found: $IMAGE_DIR"
        exit 1
    fi
    img_count=0
    for img in "$IMAGE_DIR"/*.{jpg,jpeg,png,gif,bmp,tiff,tif,webp,svg,ico,heic,heif,avif,raw,cr2,nef,arw} \
               "$IMAGE_DIR"/*.{JPG,JPEG,PNG,GIF,BMP,TIFF,TIF,WEBP,SVG,ICO,HEIC,HEIF,AVIF,RAW,CR2,NEF,ARW}; do
        [[ -f "$img" ]] || continue
        hash=$(openssl dgst -sha256 -hex "$img" 2>/dev/null | awk '{print $NF}')
        if [[ -n "$hash" ]]; then
            EXTRA_POOL+=("$hash")
            img_count=$(( img_count + 1 ))
        fi
    done
    if [[ $img_count -eq 0 ]]; then
        log_err "No image files found in: $IMAGE_DIR"
        exit 1
    fi
    log_ok "Image entropy loaded: $img_count files hashed (SHA-256) from $(basename "$IMAGE_DIR")"
fi

# =============================================================================
# Prerequisites
# =============================================================================

for cmd in openssl curl sensors python3; do
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

# Check X11 mouse capture availability
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

# =============================================================================
# Welcome
# =============================================================================

clear 2>/dev/null || true
echo ""
printf "${BLD}${CYN}"
cat <<'BANNER'
  ╔═══════════════════════════════════════════════════════╗
  ║         Entropy Bootstrap — Seed Generator           ║
  ║                                                      ║
  ║  This tool creates cryptographic seeds by collecting  ║
  ║  randomness from YOUR actions + system sensors +      ║
  ║  external services. No two runs produce the same      ║
  ║  output, even on the same machine.                    ║
  ╚═══════════════════════════════════════════════════════╝
BANNER
printf "${RST}"
echo ""
log_info "Generating $SEED_COUNT seeds to: $OUTPUT_FILE"
if [[ "$NO_EXTERNAL" == "true" ]]; then
    log_info "Sources: keyboard, mouse, CPU RNG, thermal, jitter (no external APIs)"
elif [[ -n "$ENTROPY_FILE_PATH" ]]; then
    log_info "Sources: keyboard, mouse, CPU RNG, thermal, jitter + entropy file"
elif [[ ${#EXTRA_POOL[@]} -gt 0 && -n "$IMAGE_DIR" ]]; then
    log_info "Sources: keyboard, mouse, CPU RNG, thermal, jitter, APIs + images"
elif [[ ${#EXTRA_POOL[@]} -gt 0 ]]; then
    log_info "Sources: keyboard, mouse, CPU RNG, thermal, jitter, APIs + extra data"
else
    log_info "Sources: keyboard timing, mouse movement, CPU RNG, thermal, jitter, APIs"
fi
echo ""
printf "${DIM}Press Enter to begin...${RST}"
read -r

# =============================================================================
# Phase 1: Interactive entropy collection
# =============================================================================

# --- Accumulated entropy pools ---
KEY_ENTROPY=""
MOUSE_ENTROPY=""

# ---- 1A: Keyboard timing entropy ----

log_step "Phase 1A: Keyboard Entropy"
echo "Type random characters as fast or slow as you want."
echo "Mix it up — vary your speed, use different fingers, mash randomly."
echo "What you type doesn't matter. The TIMING between keystrokes is the entropy."
echo ""
printf "${DIM}We need about %d characters across %d rounds.${RST}\n" \
    "$(( KEYS_PER_ROUND * 2 ))" "2"
echo ""

collect_keyboard_round() {
    local round_num="$1"
    local chars_needed="$KEYS_PER_ROUND"
    local timing_data=""
    local char_data=""
    local count=0

    printf "${CYN}[Round %d]${RST} Type %d random characters, then press Enter:\n" \
        "$round_num" "$chars_needed"
    printf "  ${DIM}>"

    # Use python3 for character-by-character timing (bash read -n1 loses precision)
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
        if ord(ch) == 13 or ord(ch) == 10:  # Enter
            if count > 0:
                break
            continue
        if ord(ch) == 3:  # Ctrl-C
            break
        timings.append(str(now - prev))
        chars.append(str(ord(ch)))
        prev = now
        count += 1
        sys.stderr.write('.')
        sys.stderr.flush()
    # Output: timings|chars
    print('|'.join([','.join(timings), ','.join(chars)]))
finally:
    termios.tcsetattr(fd, termios.TCSADRAIN, old)
" 2>&1)

    # Parse — stderr dots mixed in, stdout has the data on last line
    local data_line
    data_line=$(echo "$result" | tail -1)
    printf "${RST}\n"

    if [[ -z "$data_line" || "$data_line" != *"|"* ]]; then
        log_warn "Round $round_num: incomplete capture, using what we got"
        # Still hash whatever we got
        printf '%s:%s' "$result" "$(date +%s%N)" \
            | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}'
        return
    fi

    local timings="${data_line%%|*}"
    local chars="${data_line##*|}"

    # Hash timing data (this is the real entropy — nanosecond intervals)
    local timing_hash
    timing_hash=$(printf '%s' "$timings" \
        | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}')

    # Hash character data (mild entropy — what keys were pressed)
    local char_hash
    char_hash=$(printf '%s' "$chars" \
        | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}')

    # Combine with timestamp
    printf '%s:%s:%s' "$timing_hash" "$char_hash" "$(date +%s%N)" \
        | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}'
}

# Two rounds of keyboard input
for round in 1 2; do
    round_entropy=$(collect_keyboard_round "$round")
    KEY_ENTROPY+="$round_entropy"
    log_ok "Round $round captured"
    echo ""
done

log_ok "Keyboard entropy: ${#KEY_ENTROPY} hex chars collected"

# ---- 1B: Mouse movement entropy ----

if [[ "$MOUSE_AVAILABLE" == "true" ]]; then
    log_step "Phase 1B: Mouse Entropy"
    echo "Move your mouse around randomly for about 5 seconds."
    echo "Circles, zigzags, random movements — anything goes."
    echo ""
    printf "${DIM}Press Enter when ready, then start moving...${RST}"
    read -r
    echo ""
    printf "${CYN}[Sampling]${RST} Move the mouse now"

    MOUSE_ENTROPY=$(python3 -c "
import ctypes, ctypes.util, time, hashlib

x11 = ctypes.cdll.LoadLibrary(ctypes.util.find_library('X11'))
display = x11.XOpenDisplay(None)
root = x11.XDefaultRootWindow(display)

root_ret = ctypes.c_ulong()
child_ret = ctypes.c_ulong()
rx, ry, wx, wy = ctypes.c_int(), ctypes.c_int(), ctypes.c_int(), ctypes.c_int()
mask = ctypes.c_uint()

samples = []
import sys
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

# Hash all position+timing data
raw = ':'.join(samples)
h = hashlib.sha512(raw.encode()).hexdigest()
print(h)
" 2>&1)

    # Separate stderr dots from stdout hash
    local mouse_hash
    mouse_hash=$(echo "$MOUSE_ENTROPY" | tail -1)
    MOUSE_ENTROPY="$mouse_hash"
    printf "\n"
    log_ok "Mouse entropy: ${#MOUSE_ENTROPY} hex chars collected"
else
    log_step "Phase 1B: Extra Keyboard Entropy (no X11 display)"
    echo "Mouse capture unavailable — collecting extra keyboard entropy instead."
    echo ""
    extra_round=$(collect_keyboard_round 3)
    MOUSE_ENTROPY="$extra_round"
    log_ok "Extra keyboard round captured"
fi

# =============================================================================
# Phase 2: System entropy collection
# =============================================================================

log_step "Phase 2: System Entropy"

log_info "Collecting thermal sensor data..."
THERMAL_ENTROPY=""
for tz in /sys/class/thermal/thermal_zone*/temp; do
    [[ -f "$tz" ]] && THERMAL_ENTROPY+="$(cat "$tz")"
done
THERMAL_ENTROPY+="$(sensors -u 2>/dev/null | tr -d ' \n')"
THERMAL_ENTROPY+="$(date +%s%N)"
THERMAL_ENTROPY=$(printf '%s' "$THERMAL_ENTROPY" \
    | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}')
log_ok "Thermal entropy collected"

log_info "Collecting disk I/O timing jitter..."
JITTER_ENTROPY=""
for j in {1..16}; do
    t_start=$(date +%s%N)
    dd if=/dev/urandom bs=512 count=1 of=/dev/null 2>/dev/null
    t_end=$(date +%s%N)
    JITTER_ENTROPY+="$((t_end - t_start))"
done
JITTER_ENTROPY=$(printf '%s' "$JITTER_ENTROPY" \
    | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}')
log_ok "Jitter entropy collected"

# =============================================================================
# Phase 3: External entropy
# =============================================================================

log_step "Phase 3: External Entropy Sources"

# Use shared dispatcher — handles --no-external, --entropy-file, or live fetch
ext_args=()
[[ "$NO_EXTERNAL" == "true" ]] && ext_args+=(--no-external)
[[ -n "$ENTROPY_FILE_PATH" ]] && ext_args+=(--entropy-file "$ENTROPY_FILE_PATH")

get_external_entropy "${ext_args[@]+"${ext_args[@]}"}"
ext_ok="$EXT_SOURCES_OK"

# =============================================================================
# Phase 4: Generate seeds via HKDF-SHA512 mixing
# =============================================================================

log_step "Phase 4: Generating $SEED_COUNT Seeds"

echo "Each seed mixes: your keyboard timing + mouse movement + CPU RNG"
echo "                 + thermal sensors + disk jitter + external APIs"
if [[ ${#EXTRA_POOL[@]} -gt 0 ]]; then
    echo "                 + extra data file (${#EXTRA_POOL[@]} lines, random selection)"
fi
echo ""

declare -a seeds=()

for (( s=0; s<SEED_COUNT; s++ )); do
    # Fresh CPU entropy per seed
    cpu_ent=$(openssl rand -hex 32)

    # Fresh thermal snapshot (fast — sysfs only)
    fresh_thermal=""
    for tz in /sys/class/thermal/thermal_zone*/temp; do
        [[ -f "$tz" ]] && fresh_thermal+="$(cat "$tz")"
    done
    fresh_thermal+="$(date +%s%N)"
    fresh_thermal=$(printf '%s' "$fresh_thermal" \
        | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}')

    # Fresh jitter sample
    t_s=$(date +%s%N)
    dd if=/dev/urandom bs=64 count=1 of=/dev/null 2>/dev/null
    t_e=$(date +%s%N)
    fresh_jitter=$(printf '%s:%s' "$((t_e - t_s))" "$(date +%s%N)" \
        | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}')

    # Per-seed external entropy slices (unique via seed index + random nonce)
    nonce=$(openssl rand -hex 8)
    ext1=$(printf '%s:%d:%s' "$EXT_RANDOM_ORG" "$s" "$nonce" \
        | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}')
    ext2=$(printf '%s:%d:%s' "$EXT_NIST" "$s" "$nonce" \
        | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}')
    ext3=$(printf '%s:%d:%s' "$EXT_DRAND" "$s" "$nonce" \
        | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}')

    # Build IKM from interactive entropy (the user's unique contribution)
    ikm_raw="${KEY_ENTROPY}:${MOUSE_ENTROPY}:seed${s}:$(date +%s%N)"

    # Mix in a randomly selected line from extra data file (if provided)
    if [[ ${#EXTRA_POOL[@]} -gt 0 ]]; then
        extra_idx=$(( $(od -An -tu4 -N4 /dev/urandom | tr -d ' ') % ${#EXTRA_POOL[@]} ))
        ikm_raw+=":extra:${EXTRA_POOL[$extra_idx]}"
    fi

    ikm_hex=$(printf '%s' "$ikm_raw" | openssl dgst -sha512 -hex 2>/dev/null | awk '{print $NF}')

    # Build salt from all system + external entropy
    salt_hex="${cpu_ent}${THERMAL_ENTROPY}${fresh_thermal}${JITTER_ENTROPY}${fresh_jitter}"
    salt_hex+="${ext1}${ext2}${ext3}"

    # Info field: unique per seed
    info_hex=$(printf '%s' "bootstrap-entropy-v1-seed${s}" | xxd -p | tr -d '\n')

    # HKDF-SHA512 mix
    seed=$(openssl kdf -keylen "$HKDF_KEYLEN" \
        -kdfopt digest:SHA512 \
        -kdfopt "hexkey:${ikm_hex}" \
        -kdfopt "hexsalt:${salt_hex}" \
        -kdfopt "hexinfo:${info_hex}" \
        HKDF 2>/dev/null \
        | tr -d ':' | xxd -r -p | openssl base64 -A)

    seeds+=("$seed")
    printf "\r  Generating: %d/%d" "$(( s + 1 ))" "$SEED_COUNT"
done
printf "\n\n"

# =============================================================================
# Phase 5: Write output and verify
# =============================================================================

log_step "Phase 5: Output"

printf '%s\n' "${seeds[@]}" > "$OUTPUT_FILE"
chmod 600 "$OUTPUT_FILE"

# Verify
dup_count=$(sort "$OUTPUT_FILE" | uniq -d | wc -l)
out_count=$(wc -l < "$OUTPUT_FILE")
first_len=$(head -1 "$OUTPUT_FILE" | wc -c)

if [[ $dup_count -gt 0 ]]; then
    log_err "DUPLICATE SEEDS DETECTED — this should never happen"
    exit 1
fi

echo ""
log_ok "============================================"
log_ok " Bootstrap Complete"
log_ok "============================================"
echo ""
log_ok "Seeds generated: $out_count"
log_ok "Seed length:     $(( first_len - 1 )) chars (base64, 256-bit)"
log_ok "Duplicates:      none"
log_ok "Output file:     $OUTPUT_FILE (mode 600)"
echo ""
log_info "Entropy source summary:"
log_ok "  Keyboard timing:    2 rounds ($KEYS_PER_ROUND chars each)"
if [[ "$MOUSE_AVAILABLE" == "true" ]]; then
    log_ok "  Mouse movement:     $MOUSE_SAMPLES position samples"
else
    log_ok "  Extra keyboard:     1 additional round (no X11)"
fi
log_ok "  CPU RDRAND:         fresh per seed"
log_ok "  Thermal sensors:    baseline + fresh per seed"
log_ok "  Disk I/O jitter:    baseline + fresh per seed"
if [[ $ext_ok -gt 0 ]]; then
    log_ok "  External APIs:      $ext_ok/3 sources"
else
    log_warn "  External APIs:      none (local entropy only)"
fi
if [[ -n "$IMAGE_DIR" ]]; then
    log_ok "  Image hashes:       $img_count files from $(basename "$IMAGE_DIR")"
fi
if [[ -n "$EXTRA_FILE" && ${#EXTRA_POOL[@]} -gt 0 ]]; then
    log_ok "  Extra data:         file lines (random per seed)"
fi
echo ""
log_info "Next steps:"
echo "  # Initialize a YubiKey directly:"
echo "  ./configure-yubi.sh otp <SERIAL> $OUTPUT_FILE"
echo ""
echo "  # Or enrich further with entropy-mix.sh:"
echo "  ./entropy-mix.sh $OUTPUT_FILE ${OUTPUT_FILE%.txt}-enriched.txt"
echo ""
log_warn "Keep this file secure. Delete after use."

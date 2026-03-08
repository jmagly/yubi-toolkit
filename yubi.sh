#!/usr/bin/env bash
# yubi.sh — Unified entry point for YubiKey entropy and provisioning toolkit
#
# Subcommands:
#   bootstrap   [count] [file|--mux] Generate seeds from scratch (no keys needed)
#   mux                              Pair passwords from 2 existing YubiKeys
#   enrich                           Enrich latest seed file with external entropy
#   configure   <mode> [serial]      Program a YubiKey from seed pool
#   init        <mode> [serial]      Full pipeline: 2 keys → mux → enrich → program
#   list                             Show connected YubiKeys
#   info        [serial]             Detailed info for a specific key
#   status                           Show seed pool status
#   purge                            Securely delete empty/exhausted seed files
#
# All files are managed in ~/.yubikey-seeds/ — no file paths to remember.
#
# Usage: ./yubi.sh <command> [args...]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/yubi-lib.sh"

# =============================================================================
# Managed seed directory
# =============================================================================

SEED_DIR="${HOME}/.yubikey-seeds"

ensure_seed_dir() {
    if [[ ! -d "$SEED_DIR" ]]; then
        mkdir -p "$SEED_DIR"
        chmod 700 "$SEED_DIR"
    fi
}

# Generate a timestamped filename: bootstrap-20260308-143022.txt
seed_filename() {
    local prefix="$1"
    printf '%s/%s-%s.txt' "$SEED_DIR" "$prefix" "$(date +%Y%m%d-%H%M%S)"
}

# Find the active seed pool (most recent file with seeds remaining)
find_active_pool() {
    local best=""
    local best_count=0

    for f in "$SEED_DIR"/*.txt; do
        [[ -f "$f" ]] || continue
        local count
        count=$(grep -c '.' "$f" 2>/dev/null || true)
        if [[ "$count" -ge 5 ]]; then
            # Pick the most recently modified file with enough seeds
            best="$f"
            best_count="$count"
        fi
    done

    if [[ -z "$best" ]]; then
        return 1
    fi

    echo "$best"
}

# Detect single connected YubiKey serial, or prompt if multiple
detect_serial() {
    local serials
    serials=$(ykman list --serials 2>/dev/null)
    if [[ -z "$serials" ]]; then
        log_err "No YubiKeys detected — insert a key and try again"
        exit 1
    fi

    local count
    count=$(echo "$serials" | wc -l)

    if [[ "$count" -eq 1 ]]; then
        echo "$serials"
        return
    fi

    # Multiple keys — show them and ask
    log_info "Multiple YubiKeys detected:"
    echo ""
    ykman list 2>/dev/null | while IFS= read -r line; do
        printf "  %s\n" "$line"
    done
    echo ""
    printf "Enter serial number of target key: "
    read -r chosen
    if ! echo "$serials" | grep -qx "$chosen"; then
        log_err "Serial $chosen not found"
        exit 1
    fi
    echo "$chosen"
}


# =============================================================================
# Usage
# =============================================================================

usage() {
    printf "${BLD}${CYN}"
    cat <<'BANNER'
  ╔═══════════════════════════════════════════════════════╗
  ║            YubiKey Entropy Toolkit                    ║
  ╚═══════════════════════════════════════════════════════╝
BANNER
    printf "${RST}"
    echo ""
    printf "${BLD}Seed Generation:${RST}\n"
    printf "  ${GRN}bootstrap${RST}  [count] [extra|--mux]      Generate seeds from scratch (default: 15)\n"
    printf "  ${GRN}mux${RST}                                 Pair passwords from 2 existing YubiKeys\n"
    printf "  ${GRN}enrich${RST}                              Enrich latest seed file with external entropy\n"
    echo ""
    printf "${BLD}Key Programming:${RST}\n"
    printf "  ${GRN}configure${RST}  <mode> [serial]          Program a YubiKey from seed pool\n"
    printf "  ${GRN}init${RST}       <mode> [serial]           Full pipeline: 2 keys → mux → enrich → program\n"
    echo ""
    printf "${BLD}Info:${RST}\n"
    printf "  ${GRN}list${RST}                                 Show connected YubiKeys\n"
    printf "  ${GRN}info${RST}       [serial]                  Detailed info (auto-detects single key)\n"
    printf "  ${GRN}status${RST}                               Show seed pool status\n"
    printf "  ${GRN}purge${RST}                                Securely wipe empty/exhausted seed files\n"
    echo ""
    printf "${BLD}Modes:${RST}  otp | static | mixed\n"
    echo ""
    printf "${DIM}All seeds stored in: ~/.yubikey-seeds/${RST}\n"
    echo ""
    printf "${DIM}Examples:${RST}\n"
    echo "  yubi.sh bootstrap"
    echo "  yubi.sh bootstrap 20"
    echo "  yubi.sh bootstrap 15 ~/extra-passwords.txt"
    echo "  yubi.sh bootstrap 15 --mux"
    echo "  yubi.sh configure otp"
    echo "  yubi.sh configure mixed 35276256"
    echo "  yubi.sh init otp"
    echo "  yubi.sh status"
    echo "  yubi.sh list"
    exit 1
}

# --- Require ykman for key operations ---
require_ykman() {
    if ! command -v ykman &>/dev/null; then
        log_err "ykman not found — install with: sudo apt install yubikey-manager"
        exit 1
    fi
}

# =============================================================================
# Subcommand dispatch
# =============================================================================

if [[ $# -lt 1 ]]; then
    usage
fi

CMD="$1"; shift

case "$CMD" in

    # ----- Seed generation -----

    bootstrap)
        ensure_seed_dir
        count="${1:-15}"
        extra_arg="${2:-}"
        outfile=$(seed_filename "bootstrap")
        log_info "Seeds will be written to: $outfile"

        if [[ "$extra_arg" == "--mux" ]]; then
            # Collect 2-device input on the fly, mux it, use as extra data
            mux_tmp=$(seed_filename "mux-extra")
            log_info "Collecting extra entropy via 2-device mux..."
            "$SCRIPT_DIR/yubi-mux.sh" "$mux_tmp"
            log_info "Muxed extra data: $mux_tmp"
            "$SCRIPT_DIR/bootstrap-entropy.sh" "$outfile" "$count" "$mux_tmp"
            # Secure delete the mux temp — it's been mixed in
            source "$SCRIPT_DIR/yubi-lib.sh"
            secure_delete "$mux_tmp" true
        elif [[ -n "$extra_arg" && -f "$extra_arg" ]]; then
            log_info "Extra entropy from: $extra_arg"
            exec "$SCRIPT_DIR/bootstrap-entropy.sh" "$outfile" "$count" "$extra_arg"
        else
            exec "$SCRIPT_DIR/bootstrap-entropy.sh" "$outfile" "$count"
        fi
        ;;

    mux)
        ensure_seed_dir
        outfile=$(seed_filename "mux")
        log_info "Compound passwords will be written to: $outfile"
        exec "$SCRIPT_DIR/yubi-mux.sh" "$outfile"
        ;;

    enrich)
        ensure_seed_dir
        # Find the latest seed file to enrich
        infile=""
        if [[ $# -ge 1 ]]; then
            infile="$1"
        else
            infile=$(find_active_pool) || true
            if [[ -z "$infile" ]]; then
                log_err "No seed files found in $SEED_DIR"
                log_err "Run 'yubi.sh bootstrap' or 'yubi.sh mux' first"
                exit 1
            fi
        fi
        outfile=$(seed_filename "enriched")
        log_info "Enriching: $infile"
        log_info "Output:    $outfile"
        exec "$SCRIPT_DIR/entropy-mix.sh" "$infile" "$outfile"
        ;;

    # ----- Key programming -----

    configure)
        ensure_seed_dir
        require_ykman
        if [[ $# -lt 1 ]]; then
            log_err "Usage: yubi.sh configure <mode> [serial]"
            exit 1
        fi
        mode="$1"
        serial="${2:-}"

        if [[ -z "$serial" ]]; then
            serial=$(detect_serial)
        fi

        # Find active seed pool
        pool=$(find_active_pool) || true
        if [[ -z "$pool" ]]; then
            log_err "No seed files with enough seeds (need 5)"
            log_err "Run 'yubi.sh bootstrap' or 'yubi.sh mux' + 'yubi.sh enrich' first"
            exit 1
        fi

        seeds_left=$(grep -c '.' "$pool" || true)
        log_info "Using seed pool: $pool ($seeds_left seeds)"
        exec "$SCRIPT_DIR/configure-yubi.sh" "$mode" "$serial" "$pool"
        ;;

    init)
        require_ykman
        if [[ $# -lt 1 ]]; then
            log_err "Usage: yubi.sh init <mode> [serial]"
            exit 1
        fi
        mode="$1"
        serial="${2:-}"

        if [[ -z "$serial" ]]; then
            serial=$(detect_serial)
        fi

        exec "$SCRIPT_DIR/init-yubi.sh" "$mode" "$serial"
        ;;

    # ----- Info commands -----

    list)
        require_ykman
        echo ""
        log_info "Connected YubiKeys:"
        echo ""
        ykman list 2>/dev/null | while IFS= read -r line; do
            printf "  %s\n" "$line"
        done
        echo ""
        serials=$(ykman list --serials 2>/dev/null)
        if [[ -z "$serials" ]]; then
            log_err "No YubiKeys detected"
            exit 1
        fi
        count=$(echo "$serials" | wc -l)
        log_ok "$count key(s) found"
        echo ""
        printf "${DIM}Use 'yubi.sh info [serial]' for details${RST}\n"
        ;;

    info)
        require_ykman
        serial="${1:-}"
        if [[ -z "$serial" ]]; then
            serial=$(detect_serial)
        fi
        echo ""
        log_info "YubiKey $serial — General:"
        ykman -d "$serial" info
        echo ""
        log_info "YubiKey $serial — OTP slots:"
        ykman -d "$serial" otp info
        echo ""
        log_info "YubiKey $serial — PIV:"
        ykman -d "$serial" piv info
        ;;

    status)
        ensure_seed_dir
        echo ""
        log_info "Seed directory: $SEED_DIR"
        echo ""

        found=false
        for f in "$SEED_DIR"/*.txt; do
            [[ -f "$f" ]] || continue
            found=true
            count=$(grep -c '.' "$f" 2>/dev/null || true)
            keys_possible=$(( count / 5 ))
            basename=$(basename "$f")
            mod_time=$(stat -c '%y' "$f" 2>/dev/null | cut -d. -f1)

            if [[ "$count" -ge 5 ]]; then
                printf "  ${GRN}%-40s${RST}  %3d seeds  (%d keys)  %s\n" \
                    "$basename" "$count" "$keys_possible" "$mod_time"
            elif [[ "$count" -gt 0 ]]; then
                printf "  ${YLW}%-40s${RST}  %3d seeds  (low)     %s\n" \
                    "$basename" "$count" "$mod_time"
            else
                printf "  ${DIM}%-40s${RST}    0 seeds  (empty)   %s\n" \
                    "$basename" "$mod_time"
            fi
        done

        if [[ "$found" == "false" ]]; then
            log_info "No seed files yet."
            echo ""
            printf "  Run ${GRN}yubi.sh bootstrap${RST} to generate seeds\n"
            printf "  or  ${GRN}yubi.sh mux${RST} to pair from existing keys\n"
        else
            echo ""
            pool=$(find_active_pool) || true
            if [[ -n "$pool" ]]; then
                pool_count=$(grep -c '.' "$pool" || true)
                log_ok "Active pool: $(basename "$pool") ($pool_count seeds, $(( pool_count / 5 )) keys)"
            else
                log_warn "No pool has enough seeds (need 5). Generate more."
            fi
        fi
        echo ""
        ;;

    purge)
        ensure_seed_dir
        echo ""
        log_info "Scanning $SEED_DIR for empty/exhausted files..."
        purged=0
        for f in "$SEED_DIR"/*.txt; do
            [[ -f "$f" ]] || continue
            count=$(grep -c '.' "$f" 2>/dev/null || true)
            if [[ "$count" -eq 0 ]]; then
                secure_delete "$f" true
                purged=$(( purged + 1 ))
            fi
        done
        if [[ "$purged" -eq 0 ]]; then
            log_info "Nothing to purge — all files have seeds remaining"
        else
            log_ok "Purged $purged file(s)"
        fi
        echo ""
        ;;

    # ----- Unknown -----

    help|-h|--help)
        usage
        ;;

    *)
        log_err "Unknown command: $CMD"
        echo ""
        usage
        ;;
esac

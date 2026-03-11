#!/usr/bin/env bash
# yubi.sh — Unified entry point for YubiKey entropy and provisioning toolkit
#
# Subcommands:
#   bootstrap        [count] [file|--mux] [--no-external|--entropy-file PATH]
#   mux                              Pair passwords from 2 existing YubiKeys
#   enrich           [file] [--no-external|--entropy-file PATH]
#   entropy-collect  [file] [--append] [--sources LIST] [--quiet]
#   entropy-verify   <file>          Validate a collected entropy file
#   configure   <mode> [serial]      Program a YubiKey from seed pool
#   init        <mode> [serial] [--no-external|--entropy-file PATH]
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
    printf "  ${GRN}bootstrap${RST}        [count] [extra|--mux]  Generate seeds from scratch (default: 15)\n"
    printf "  ${GRN}mux${RST}                                    Pair passwords from 2 existing YubiKeys\n"
    printf "  ${GRN}enrich${RST}           [file]                Enrich latest seed file with external entropy\n"
    echo ""
    printf "${BLD}Entropy Collection (air-gapped workflows):${RST}\n"
    printf "  ${GRN}entropy-collect${RST}  [file] [--append]     Collect external entropy to portable file\n"
    printf "  ${GRN}entropy-verify${RST}   <file>                Validate a collected entropy file\n"
    echo ""
    printf "${BLD}Key Programming:${RST}\n"
    printf "  ${GRN}configure${RST}        <mode> [serial]       Program a YubiKey from seed pool\n"
    printf "  ${GRN}init${RST}             <mode> [serial]       Full pipeline: 2 keys → mux → enrich → program\n"
    echo ""
    printf "${BLD}Info:${RST}\n"
    printf "  ${GRN}list${RST}                                   Show connected YubiKeys\n"
    printf "  ${GRN}info${RST}             [serial]              Detailed info (auto-detects single key)\n"
    printf "  ${GRN}status${RST}                                 Show seed pool status\n"
    printf "  ${GRN}purge${RST}                                  Securely wipe empty/exhausted seed files\n"
    echo ""
    printf "${BLD}Modes:${RST}  otp | static | mixed\n"
    echo ""
    printf "${BLD}Flags${RST} (for bootstrap, enrich, init):\n"
    printf "  ${DIM}--no-external${RST}         Skip external API calls (local entropy only)\n"
    printf "  ${DIM}--entropy-file PATH${RST}   Use pre-collected entropy instead of live APIs\n"
    printf "  ${DIM}--image-dir PATH${RST}      Hash image files as additional entropy (bootstrap only)\n"
    echo ""
    printf "${DIM}All seeds stored in: ~/.yubikey-seeds/${RST}\n"
    echo ""
    printf "${DIM}Examples:${RST}\n"
    echo "  yubi.sh bootstrap"
    echo "  yubi.sh bootstrap 20"
    echo "  yubi.sh bootstrap 15 ~/extra-passwords.txt"
    echo "  yubi.sh bootstrap 15 --mux"
    echo "  yubi.sh bootstrap 15 --no-external"
    echo "  yubi.sh bootstrap 15 --entropy-file ~/entropy-data/pool.bin"
    echo "  yubi.sh bootstrap 15 --image-dir ~/photos"
    echo "  yubi.sh entropy-collect"
    echo "  yubi.sh entropy-collect --append ~/entropy-data/pool.bin"
    echo "  yubi.sh entropy-verify ~/entropy-data/pool.bin"
    echo "  yubi.sh configure otp"
    echo "  yubi.sh configure mixed 35276256"
    echo "  yubi.sh init otp"
    echo "  yubi.sh init otp --entropy-file ~/entropy-data/pool.bin"
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
        # Parse bootstrap-specific args, separating passthrough flags
        count="15"
        extra_arg=""
        passthrough_args=()
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --no-external)  passthrough_args+=(--no-external); shift ;;
                --entropy-file) passthrough_args+=(--entropy-file "$2"); shift 2 ;;
                --image-dir)    passthrough_args+=(--image-dir "$2"); shift 2 ;;
                --mux)          extra_arg="--mux"; shift ;;
                *)
                    if [[ "$1" =~ ^[0-9]+$ && "$count" == "15" ]]; then
                        count="$1"
                    elif [[ -z "$extra_arg" ]]; then
                        extra_arg="$1"
                    fi
                    shift
                    ;;
            esac
        done
        outfile=$(seed_filename "bootstrap")
        log_info "Seeds will be written to: $outfile"

        if [[ "$extra_arg" == "--mux" ]]; then
            mux_tmp=$(seed_filename "mux-extra")
            log_info "Collecting extra entropy via 2-device mux..."
            "$SCRIPT_DIR/yubi-mux.sh" "$mux_tmp"
            log_info "Muxed extra data: $mux_tmp"
            "$SCRIPT_DIR/bootstrap-entropy.sh" "$outfile" "$count" "$mux_tmp" \
                "${passthrough_args[@]+"${passthrough_args[@]}"}"
            secure_delete "$mux_tmp" true
        elif [[ -n "$extra_arg" && -f "$extra_arg" ]]; then
            log_info "Extra entropy from: $extra_arg"
            exec "$SCRIPT_DIR/bootstrap-entropy.sh" "$outfile" "$count" "$extra_arg" \
                "${passthrough_args[@]+"${passthrough_args[@]}"}"
        else
            exec "$SCRIPT_DIR/bootstrap-entropy.sh" "$outfile" "$count" \
                "${passthrough_args[@]+"${passthrough_args[@]}"}"
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
        # Parse enrich args, separating passthrough flags
        infile=""
        passthrough_args=()
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --no-external)  passthrough_args+=(--no-external); shift ;;
                --entropy-file) passthrough_args+=(--entropy-file "$2"); shift 2 ;;
                *)
                    if [[ -z "$infile" ]]; then
                        infile="$1"
                    fi
                    shift
                    ;;
            esac
        done
        if [[ -z "$infile" ]]; then
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
        exec "$SCRIPT_DIR/entropy-mix.sh" "$infile" "$outfile" \
            "${passthrough_args[@]+"${passthrough_args[@]}"}"
        ;;

    # ----- Entropy collection (air-gapped workflows) -----

    entropy-collect)
        exec "$SCRIPT_DIR/entropy-collect.sh" "$@"
        ;;

    entropy-verify)
        if [[ $# -lt 1 ]]; then
            log_err "Usage: yubi.sh entropy-verify <entropy_file>"
            exit 1
        fi
        exec "$SCRIPT_DIR/entropy-verify.sh" "$@"
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
            log_err "Usage: yubi.sh init <mode> [serial] [--no-external|--entropy-file PATH]"
            exit 1
        fi
        mode="$1"; shift
        serial=""
        passthrough_args=()
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --no-external)  passthrough_args+=(--no-external); shift ;;
                --entropy-file) passthrough_args+=(--entropy-file "$2"); shift 2 ;;
                *)
                    if [[ -z "$serial" ]]; then
                        serial="$1"
                    fi
                    shift
                    ;;
            esac
        done

        if [[ -z "$serial" ]]; then
            serial=$(detect_serial)
        fi

        exec "$SCRIPT_DIR/init-yubi.sh" "$mode" "$serial" \
            "${passthrough_args[@]+"${passthrough_args[@]}"}"
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

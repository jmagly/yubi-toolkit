#!/usr/bin/env bash
# entropy-collect.sh — Collect external entropy into a portable file
#
# Standalone tool for gathering entropy from external APIs (random.org,
# NIST Beacon, drand) into a file that can be transferred via sneakernet
# to an air-gapped machine for YubiKey provisioning.
#
# Usage: ./entropy-collect.sh [output_file] [options]
#   --append           Append to existing file instead of creating new
#   --sources LIST     Comma-separated source list (random.org,nist,drand)
#   --quiet            Minimal output (cron-friendly)
#
# Output: entropy file in YUBI-ENTROPY-V1 format
#
# Requires: openssl, curl

set -euo pipefail
umask 077
ulimit -c 0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/yubi-lib.sh"

# =============================================================================
# Arguments
# =============================================================================

OUTPUT_FILE=""
APPEND_MODE=false
SOURCES="random.org,nist,drand"
QUIET=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --append)
            APPEND_MODE=true
            shift
            ;;
        --sources)
            SOURCES="$2"
            shift 2
            ;;
        --quiet)
            QUIET=true
            shift
            ;;
        --help|-h)
            cat <<'USAGE'
Usage: entropy-collect.sh [output_file] [options]

  output_file         Where to write entropy (default: entropy-<timestamp>.bin)

Options:
  --append            Append to existing file instead of creating new
  --sources LIST      Comma-separated: random.org,nist,drand (default: all)
  --quiet             Minimal output (cron-friendly)

Collects external entropy from API sources into a portable file for
air-gapped YubiKey provisioning workflows.

Examples:
  # One-shot collection to auto-named file
  ./entropy-collect.sh

  # Accumulate over time
  ./entropy-collect.sh --append ~/entropy-data/pool.bin

  # Specific sources only
  ./entropy-collect.sh --sources random.org,drand

  # Cron-friendly
  ./entropy-collect.sh --append ~/entropy-data/pool.bin --quiet
USAGE
            exit 0
            ;;
        -*)
            log_err "Unknown option: $1"
            exit 1
            ;;
        *)
            OUTPUT_FILE="$1"
            shift
            ;;
    esac
done

# Default output file
if [[ -z "$OUTPUT_FILE" ]]; then
    OUTPUT_FILE="entropy-$(date +%Y%m%d-%H%M%S).bin"
fi

# =============================================================================
# Prerequisites
# =============================================================================

for cmd in openssl curl; do
    if ! command -v "$cmd" &>/dev/null; then
        log_err "Required command not found: $cmd"
        exit 1
    fi
done

# =============================================================================
# Collect
# =============================================================================

if [[ "$QUIET" == "false" ]]; then
    echo ""
    log_info "Entropy collection starting"
    log_info "Output: $OUTPUT_FILE"
    log_info "Mode: $(if [[ "$APPEND_MODE" == "true" ]]; then echo "append"; else echo "new file"; fi)"
    log_info "Sources: $SOURCES"
    echo ""
fi

# Initialize or validate existing file
if [[ "$APPEND_MODE" == "true" && -f "$OUTPUT_FILE" ]]; then
    # Validate existing file before appending
    if ! validate_entropy_file "$OUTPUT_FILE"; then
        log_err "Cannot append to invalid entropy file"
        exit 1
    fi
    [[ "$QUIET" == "false" ]] && log_ok "Existing file validated, appending..."
else
    init_entropy_file "$OUTPUT_FILE"
fi

# Parse source list
IFS=',' read -ra SOURCE_LIST <<< "$SOURCES"
collected=0

for src in "${SOURCE_LIST[@]}"; do
    case "$src" in
        random.org)
            [[ "$QUIET" == "false" ]] && log_info "Fetching random.org..."
            raw=""
            if raw=$(call_external "random.org" \
                "https://www.random.org/integers/?num=10&min=0&max=1000000000&col=1&base=10&format=plain&rnd=new"); then
                write_entropy_block "$OUTPUT_FILE" "random.org" "$raw"
                [[ "$QUIET" == "false" ]] && log_ok "random.org: collected"
                collected=$(( collected + 1 ))
            else
                [[ "$QUIET" == "false" ]] && log_warn "random.org: failed"
            fi
            ;;
        nist)
            [[ "$QUIET" == "false" ]] && log_info "Fetching NIST Beacon..."
            raw=""
            if raw=$(call_external "NIST Beacon" \
                "https://beacon.nist.gov/beacon/2.0/pulse/last"); then
                write_entropy_block "$OUTPUT_FILE" "nist" "$raw"
                [[ "$QUIET" == "false" ]] && log_ok "NIST Beacon: collected"
                collected=$(( collected + 1 ))
            else
                [[ "$QUIET" == "false" ]] && log_warn "NIST Beacon: failed"
            fi
            ;;
        drand)
            [[ "$QUIET" == "false" ]] && log_info "Fetching drand..."
            raw=""
            if raw=$(call_external "drand" \
                "https://drand.cloudflare.com/public/latest"); then
                write_entropy_block "$OUTPUT_FILE" "drand" "$raw"
                [[ "$QUIET" == "false" ]] && log_ok "drand: collected"
                collected=$(( collected + 1 ))
            else
                [[ "$QUIET" == "false" ]] && log_warn "drand: failed"
            fi
            ;;
        *)
            log_warn "Unknown source: $src (skipping)"
            ;;
    esac
done

# =============================================================================
# Report
# =============================================================================

if [[ $collected -eq 0 ]]; then
    log_err "No sources collected successfully"
    exit 1
fi

if [[ "$QUIET" == "false" ]]; then
    echo ""
    log_ok "Collected $collected/${#SOURCE_LIST[@]} sources"
    log_ok "Output: $OUTPUT_FILE (mode 600)"
    echo ""
    log_info "Next steps:"
    echo "  # Verify the file"
    echo "  ./yubi.sh entropy-verify $OUTPUT_FILE"
    echo ""
    echo "  # Use on air-gapped machine"
    echo "  ./yubi.sh bootstrap 15 --entropy-file $OUTPUT_FILE"
    echo ""
    echo "  # Accumulate more entropy later"
    echo "  ./yubi.sh entropy-collect --append $OUTPUT_FILE"
else
    echo "OK: $collected sources -> $OUTPUT_FILE"
fi

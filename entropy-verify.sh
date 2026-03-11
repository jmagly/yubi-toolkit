#!/usr/bin/env bash
# entropy-verify.sh — Validate a collected entropy file
#
# Checks block structure integrity, verifies SHA-256 hashes, and reports
# source breakdown, time range, total entropy size, and staleness warnings.
#
# Usage: ./entropy-verify.sh <entropy_file>
#
# Requires: openssl

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/yubi-lib.sh"

# =============================================================================
# Arguments
# =============================================================================

if [[ $# -lt 1 || "$1" == "--help" || "$1" == "-h" ]]; then
    cat <<'USAGE'
Usage: entropy-verify.sh <entropy_file>

Validates a collected entropy file without consuming it:
  - Verifies block structure integrity
  - Checks SHA-256 hashes for each block
  - Reports source breakdown, time range, total entropy size
  - Warns if file appears stale (all blocks >30 days old)

Example:
  ./entropy-verify.sh ~/entropy-data/pool.bin
USAGE
    exit 1
fi

ENTROPY_FILE="$1"

# =============================================================================
# Validate
# =============================================================================

echo ""
log_info "Validating entropy file: $ENTROPY_FILE"
echo ""

if validate_entropy_file "$ENTROPY_FILE"; then
    log_ok "Integrity check: PASSED"
else
    log_err "Integrity check: FAILED"
    exit 1
fi

# =============================================================================
# Report
# =============================================================================

report_entropy_file "$ENTROPY_FILE"

# Per-source block count
echo ""
log_info "Per-source breakdown:"
for src in "random.org" "nist" "drand"; do
    count=$(grep -c "^SOURCE:${src}$" "$ENTROPY_FILE" 2>/dev/null || true)
    if [[ $count -gt 0 ]]; then
        log_ok "  $src: $count block(s)"
    else
        log_warn "  $src: 0 blocks"
    fi
done

echo ""
log_ok "File is valid and ready for use."
echo ""
log_info "Usage:"
echo "  ./yubi.sh bootstrap 15 --entropy-file $ENTROPY_FILE"
echo "  ./yubi.sh init otp --entropy-file $ENTROPY_FILE"
echo "  ./yubi.sh enrich --entropy-file $ENTROPY_FILE"
echo ""

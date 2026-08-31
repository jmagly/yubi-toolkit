#!/usr/bin/env bash
# Live public-beacon collection is intentionally unavailable.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/yubi-lib.sh"

log_err "entropy-collect was removed: unverified public responses are not credential entropy"
log_err "Use the platform CSPRNG-rooted offline workflow; see README.md"
exit 1

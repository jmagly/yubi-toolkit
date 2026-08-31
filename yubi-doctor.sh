#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/yubi-lib.sh"

json=false
serial=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --json) json=true ;;
        *) serial="$1" ;;
    esac
    shift
done

bash_version="${BASH_VERSION}"
python_version=$(python3 --version 2>&1 | awk '{print $2}' || true)
openssl_version=$(openssl version 2>/dev/null | awk '{print $2}' || true)
ykman_version=$(ykman --version 2>/dev/null | sed -n 's/.*version: //p' || true)

bash_status=unsupported
version_triplet "${bash_version%%(*}" && [[ "$VERSION_MAJOR" -eq 3 || "$VERSION_MAJOR" -eq 4 || "$VERSION_MAJOR" -eq 5 ]] && bash_status=supported
python_status=missing
[[ -n "$python_version" ]] && python_status=supported
openssl_status=unsupported
if version_triplet "$openssl_version" && [[ "$VERSION_MAJOR" -eq 3 ]] && openssl_hkdf_kat; then openssl_status=supported; fi
ykman_status=unsupported
ykman_supported_version && ykman_status=supported
device_status=not-checked
if [[ -n "$serial" ]]; then
    device_status=unsupported
    yubikey_capability_preflight "$serial" >/dev/null 2>&1 && device_status=supported
fi

overall=ok
for status in "$bash_status" "$python_status" "$openssl_status" "$ykman_status"; do
    [[ "$status" == supported ]] || overall=failed
done
[[ "$device_status" == unsupported ]] && overall=failed

if [[ "$json" == true ]]; then
    printf '{"overall":"%s","bash":{"version":"%s","status":"%s"},"python":{"version":"%s","status":"%s"},"openssl":{"version":"%s","status":"%s","hkdf_kat":%s},"ykman":{"version":"%s","status":"%s"},"device":{"serial":"%s","status":"%s"}}\n' \
        "$overall" "$bash_version" "$bash_status" "$python_version" "$python_status" \
        "$openssl_version" "$openssl_status" "$([[ "$openssl_status" == supported ]] && echo true || echo false)" \
        "$ykman_version" "$ykman_status" "$serial" "$device_status"
else
    printf 'Overall: %s\nBash: %s (%s)\nPython: %s (%s)\nOpenSSL: %s (%s; HKDF KAT)\nykman: %s (%s)\nDevice: %s (%s)\n' \
        "$overall" "$bash_version" "$bash_status" "$python_version" "$python_status" \
        "$openssl_version" "$openssl_status" "$ykman_version" "$ykman_status" "${serial:-not requested}" "$device_status"
fi
[[ "$overall" == ok ]]

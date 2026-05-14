#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Run all host-side integration scripts; default BUILD_DIR prefers ./build
# then ./build-docker (built gw), unless ATSC3_BUILD_DIR is set — see _lib.sh.
# RTCM leg uses a smaller frame count than rtcm_integration_test.sh defaults
# so local/CI-adjacent runs stay quick.
#
# Usage:
#   scripts/run_all_integration.sh [BUILD_DIR]

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
. "${script_dir}/_lib.sh"
build_dir="${1:-$(detect_default_build_dir "${repo_root}")}"

run() {
    local name="$1"
    shift
    echo ">>> ${name}"
    "${script_dir}/${name}" "$@"
}

run integration_test.sh "${build_dir}"
run udp_integration_test.sh "${build_dir}"
run ipv4udp_file_integration_test.sh "${build_dir}"
run stltp_integration_test.sh "${build_dir}"
run lls_integration_test.sh "${build_dir}"
run admin_patch_config_integration_test.sh "${build_dir}"
run m7_operator_integration_test.sh "${build_dir}"
run lct_word0_integration_test.sh "${build_dir}"
# Fewer frames / moderate payload than default 32×128 — still exercises RTCM+CRC path.
run rtcm_integration_test.sh "${build_dir}" 12 96

echo ">>> run_all_integration: PASS (all scripts)"

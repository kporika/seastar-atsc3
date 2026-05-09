# SPDX-License-Identifier: Apache-2.0
#
# Shared helpers for atsc3_proto/scripts/*.sh. Source from the calling
# script after `set -euo pipefail`:
#
#   . "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
#   gw_bin="$(resolve_bin "${ATSC3_GW:-}"  "${build_dir}/gw/atsc3_gw"          atsc3_gw)"
#   probe_bin="$(resolve_bin "${MMT_PROBE:-}" "${build_dir}/mmt_probe/mmt_probe" mmt_probe)"
#
# resolve_bin tries, in order:
#   1) $1 — explicit override (env var); errors if set but not executable.
#   2) $2 — dev-tree path (e.g. ./build/gw/atsc3_gw).
#   3) $3 — bare command name on $PATH (atsc3-proto runtime image installs
#           binaries under /usr/local/bin, which is on $PATH).
resolve_bin() {
    local override="${1:-}"
    local dev_path="${2:-}"
    local path_name="${3:-}"
    if [[ -n "${override}" ]]; then
        if [[ ! -x "${override}" ]]; then
            echo "resolve_bin: not executable: ${override}" >&2
            return 2
        fi
        echo "${override}"
        return 0
    fi
    if [[ -x "${dev_path}" ]]; then
        echo "${dev_path}"
        return 0
    fi
    if command -v "${path_name}" >/dev/null 2>&1; then
        command -v "${path_name}"
        return 0
    fi
    echo "resolve_bin: tried ${dev_path} and \$PATH for ${path_name}" >&2
    return 2
}

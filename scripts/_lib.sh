# SPDX-License-Identifier: Apache-2.0
#
# Shared helpers for atsc3_proto/scripts/*.sh. Source from the calling
# script after `set -euo pipefail`:
#
#   . "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
#   repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
#   build_dir="${1:-$(detect_default_build_dir "${repo_root}")}"
#   gw_bin="$(resolve_bin "${ATSC3_GW:-}"  "${build_dir}/gw/atsc3_gw"          atsc3_gw)"
#
# Integration default build dir (when $1 omitted or empty):
#   - $ATSC3_BUILD_DIR if set ("build", "build-docker", or absolute)
#   - else repo_root/build if gw binary exists there
#   - else repo_root/build-docker if gw binary exists there
#   - else repo_root/build (failure path gives a stable message from resolve_bin)
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

detect_default_build_dir() {
    local repo_root="${1:?}"
    local rel
    if [[ -n "${ATSC3_BUILD_DIR:-}" ]]; then
        rel="${ATSC3_BUILD_DIR}"
        if [[ "${rel}" == /* ]]; then
            echo "${rel}"
        else
            echo "${repo_root}/${rel}"
        fi
        return 0
    fi
    if [[ -x "${repo_root}/build/gw/atsc3_gw" ]]; then
        echo "${repo_root}/build"
        return 0
    fi
    if [[ -x "${repo_root}/build-docker/gw/atsc3_gw" ]]; then
        echo "${repo_root}/build-docker"
        return 0
    fi
    echo "${repo_root}/build"
}

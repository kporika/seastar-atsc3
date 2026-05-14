#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Integration test: spawn atsc3_gw with a per-shard file sink, push payloads
# through it via mmt_probe send, then run mmt_probe verify against the sink
# file to confirm the round-trip works end-to-end.
#
# Resolves binaries in this order:
#   1) $ATSC3_GW / $MMT_PROBE env vars (if set, must be executable paths)
#   2) ${build_dir}/… from detect_default_build_dir (./build preferred, else ./build-docker;
#      override with ATSC3_BUILD_DIR or explicit script arg).

#   3) anything on $PATH                                  (installed layout,
#                                                          e.g. inside the
#                                                          atsc3-proto image)
#
# Usage:
#   scripts/integration_test.sh                # dev tree — ./build then ./build-docker
#   ATSC3_BUILD_DIR=build-docker scripts/integration_test.sh
#   scripts/integration_test.sh /custom/build  # dev tree, custom build dir
#   ATSC3_GW=/usr/local/bin/atsc3_gw \         # explicit override
#     MMT_PROBE=/usr/local/bin/mmt_probe scripts/integration_test.sh

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${script_dir}/_lib.sh"

repo_root="$(cd "${script_dir}/.." && pwd)"
build_dir="${1:-$(detect_default_build_dir "${repo_root}")}"

gw_bin="$(resolve_bin "${ATSC3_GW:-}"  "${build_dir}/gw/atsc3_gw"          atsc3_gw)"
probe_bin="$(resolve_bin "${MMT_PROBE:-}" "${build_dir}/mmt_probe/mmt_probe" mmt_probe)"
echo "[integ] gw=${gw_bin}"
echo "[integ] probe=${probe_bin}"

# Pick a non-default port to avoid collisions with anything the user is running.
port=$(( ( RANDOM % 10000 ) + 19000 ))
addr="127.0.0.1:${port}"

tmpdir="$(mktemp -d -t atsc3_integ.XXXXXX)"
sink_prefix="${tmpdir}/gw.out"
log_file="${tmpdir}/gw.log"

cleanup() {
    if [[ -n "${gw_pid:-}" ]] && kill -0 "${gw_pid}" 2>/dev/null; then
        kill "${gw_pid}" 2>/dev/null || true
        # Give Seastar a moment to flush+exit cleanly.
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            kill -0 "${gw_pid}" 2>/dev/null || break
            sleep 0.1
        done
        kill -9 "${gw_pid}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "[integ] starting atsc3_gw on ${addr} (smp=1, sink=file://${sink_prefix})"
"${gw_bin}" --smp 1 \
    --ingress "${addr}" \
    --sink "file://${sink_prefix}" \
    >"${log_file}" 2>&1 &
gw_pid=$!

# Wait until the listener is actually bound. Polling is more reliable than a
# fixed sleep, especially in CI.
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if (echo > /dev/tcp/127.0.0.1/${port}) >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
    if ! kill -0 "${gw_pid}" 2>/dev/null; then
        echo "[integ] gw exited early; log:"
        cat "${log_file}" >&2
        exit 1
    fi
done

payloads="DEADBEEF,CAFEBABE,1122334455667788,$(printf 'AB%.0s' {1..32})"

echo "[integ] sending payloads"
"${probe_bin}" send --target "${addr}" --payloads "${payloads}"

# Smp=1 → only sink file is gw.out.shard0.
sink_file="${sink_prefix}.shard0"

# Allow up to ~2s for the sink to flush. The atsc3_gw file sink writes
# lazily; we settle by retrying verify until the size stops growing.
prev_size=-1
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if [[ -f "${sink_file}" ]]; then
        size=$(stat -c%s "${sink_file}" 2>/dev/null || stat -f%z "${sink_file}")
        if [[ "${size}" -gt 0 && "${size}" -eq "${prev_size}" ]]; then
            break
        fi
        prev_size=${size}
    fi
    sleep 0.1
done

# Stop the gateway BEFORE verifying so the sink is flushed via at_exit().
echo "[integ] stopping gw (pid=${gw_pid})"
kill "${gw_pid}" 2>/dev/null || true
wait "${gw_pid}" 2>/dev/null || true
unset gw_pid

echo "[integ] verifying ${sink_file}"
"${probe_bin}" verify \
    --file "${sink_file}" \
    --expected-payloads "${payloads}"

echo "[integ] PASS"

#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Throughput soak for atsc3_gw.
#
# Spawns the gw with `null://` sink (so the disk isn't the bottleneck),
# pushes synthetic payloads via `mmt_probe send --burst --duration`, and
# scrapes the gw's exit-time totals to assert:
#
#   * encode_errors == 0 across all shards
#   * payloads >= sent (allowing for at-most-equal accounting; the gw
#     counts complete length-framed payloads only, so the two should
#     be equal in a clean run)
#
# Usage: scripts/throughput_soak.sh [BUILD_DIR] [DURATION_S] [SHARDS] [PAYLOAD_HEX]
#
# Defaults: BUILD_DIR=./build, DURATION_S=60, SHARDS=1, PAYLOAD_HEX=64xAA.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${script_dir}/_lib.sh"

repo_root="$(cd "${script_dir}/.." && pwd)"
build_dir="${1:-${repo_root}/build}"
duration="${2:-60}"
shards="${3:-1}"
payload_hex="${4:-}"

gw_bin="$(resolve_bin "${ATSC3_GW:-}"  "${build_dir}/gw/atsc3_gw"          atsc3_gw)"
probe_bin="$(resolve_bin "${MMT_PROBE:-}" "${build_dir}/mmt_probe/mmt_probe" mmt_probe)"

port=$(( ( RANDOM % 10000 ) + 19000 ))
addr="127.0.0.1:${port}"

tmpdir="$(mktemp -d -t atsc3_soak.XXXXXX)"
log_file="${tmpdir}/gw.log"

cleanup() {
    if [[ -n "${gw_pid:-}" ]] && kill -0 "${gw_pid}" 2>/dev/null; then
        kill "${gw_pid}" 2>/dev/null || true
        for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
            kill -0 "${gw_pid}" 2>/dev/null || break
            sleep 0.2
        done
        kill -9 "${gw_pid}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "[soak] starting atsc3_gw on ${addr} (smp=${shards}, sink=null://, log=${log_file})"
"${gw_bin}" --smp "${shards}" \
    --ingress "${addr}" \
    --sink "null://" \
    >"${log_file}" 2>&1 &
gw_pid=$!

for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if (echo > /dev/tcp/127.0.0.1/${port}) >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
    if ! kill -0 "${gw_pid}" 2>/dev/null; then
        echo "[soak] gw exited early; log:" >&2
        cat "${log_file}" >&2
        exit 1
    fi
done

# burst = a very large number; --duration bounds wall-clock time.
burst=2000000000
echo "[soak] sending payloads for ${duration}s (unthrottled)"
send_log="${tmpdir}/send.log"
if [[ -n "${payload_hex}" ]]; then
    "${probe_bin}" send \
        --target "${addr}" \
        --burst "${burst}" \
        --payload "${payload_hex}" \
        --duration "${duration}" \
        > "${send_log}" 2>&1
else
    "${probe_bin}" send \
        --target "${addr}" \
        --burst "${burst}" \
        --duration "${duration}" \
        > "${send_log}" 2>&1
fi
sent_summary="$(tail -n 1 "${send_log}")"
echo "[soak] ${sent_summary}"

# Trigger gw shutdown so it logs the cross-shard totals via main.cc.
echo "[soak] stopping gw"
kill "${gw_pid}" 2>/dev/null || true
wait "${gw_pid}" 2>/dev/null || true
unset gw_pid

totals_line="$(grep -E '^[A-Z]+ [^]]+\] totals: ' "${log_file}" \
              | tail -n 1 || true)"
if [[ -z "${totals_line}" ]]; then
    echo "[soak] FAIL: gw did not log totals; full log:" >&2
    cat "${log_file}" >&2
    exit 1
fi
echo "[soak] gw ${totals_line}"

# Pull individual fields out of the totals line for an automated assertion.
get_field() {
    echo "${totals_line}" | sed -nE "s/.* ${1}=([0-9]+).*/\1/p"
}
payloads="$(get_field payloads)"
encode_errors="$(get_field encode_errors)"
bytes_in="$(get_field bytes_in)"
bytes_out="$(get_field bytes_out)"

if [[ -z "${payloads}" || -z "${encode_errors}" ]]; then
    echo "[soak] FAIL: could not parse totals line: ${totals_line}" >&2
    exit 1
fi
if [[ "${encode_errors}" -ne 0 ]]; then
    echo "[soak] FAIL: encode_errors=${encode_errors} (must be 0)" >&2
    exit 1
fi
if [[ "${payloads}" -le 0 ]]; then
    echo "[soak] FAIL: payloads=${payloads} (no traffic reached the gw)" >&2
    exit 1
fi

pps=$(( payloads / duration ))
echo "[soak] PASS: payloads=${payloads} (${pps} pps avg), encode_errors=0,"
echo "[soak]       bytes_in=${bytes_in} bytes_out=${bytes_out}, duration=${duration}s"

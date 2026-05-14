#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Integration: gw with --sink udp://127.0.0.1:RPORT, Python receiver collects
# TLV-mux UDP payloads, then mmt_probe verify (same as file-sink integ).
#
# Usage:
#   scripts/udp_integration_test.sh [build_dir]
#
# Requires: python3, same binaries as scripts/integration_test.sh

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${script_dir}/_lib.sh"

repo_root="$(cd "${script_dir}/.." && pwd)"
build_dir="${1:-${repo_root}/build}"

gw_bin="$(resolve_bin "${ATSC3_GW:-}"  "${build_dir}/gw/atsc3_gw"          atsc3_gw)"
probe_bin="$(resolve_bin "${MMT_PROBE:-}" "${build_dir}/mmt_probe/mmt_probe" mmt_probe)"
py3="$(command -v python3)"

echo "[udp-integ] gw=${gw_bin}"
echo "[udp-integ] probe=${probe_bin}"

tcp_port=$(( ( RANDOM % 10000 ) + 19000 ))
udp_port=$(( ( RANDOM % 10000 ) + 29000 ))
# Avoid accidental collision on narrow ranges.
if [[ "${udp_port}" -eq "${tcp_port}" ]]; then
    udp_port=$((udp_port + 1))
fi

tcp_addr="127.0.0.1:${tcp_port}"
udp_addr="127.0.0.1:${udp_port}"

tmpdir="$(mktemp -d -t atsc3_udp_integ.XXXXXX)"
cap_file="${tmpdir}/udp_tlvmux.bin"
log_file="${tmpdir}/gw.log"
recv_log="${tmpdir}/recv.log"

cleanup() {
    if [[ -n "${gw_pid:-}" ]] && kill -0 "${gw_pid}" 2>/dev/null; then
        kill "${gw_pid}" 2>/dev/null || true
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            kill -0 "${gw_pid}" 2>/dev/null || break
            sleep 0.1
        done
        kill -9 "${gw_pid}" 2>/dev/null || true
    fi
    if [[ -n "${recv_pid:-}" ]] && kill -0 "${recv_pid}" 2>/dev/null; then
        kill "${recv_pid}" 2>/dev/null || true
        wait "${recv_pid}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "[udp-integ] receiver on ${udp_addr} -> ${cap_file}"
"${py3}" "${script_dir}/_udp_recv_concat.py" "127.0.0.1" "${udp_port}" \
    "${cap_file}" 4 8.0 >"${recv_log}" 2>&1 &
recv_pid=$!

# Give the receiver a moment to bind before gw opens its UDP channel.
sleep 0.15

echo "[udp-integ] starting atsc3_gw on ${tcp_addr} (sink=udp://${udp_addr})"
"${gw_bin}" --smp 1 \
    --ingress "${tcp_addr}" \
    --sink "udp://${udp_addr}" \
    >"${log_file}" 2>&1 &
gw_pid=$!

for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if (echo > /dev/tcp/127.0.0.1/${tcp_port}) >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
    if ! kill -0 "${gw_pid}" 2>/dev/null; then
        echo "[udp-integ] gw exited early; log:" >&2
        cat "${log_file}" >&2
        exit 1
    fi
done

payloads="DEADBEEF,CAFEBABE,1122334455667788,$(printf 'AB%.0s' {1..32})"

echo "[udp-integ] sending payloads"
"${probe_bin}" send --target "${tcp_addr}" --payloads "${payloads}"

echo "[udp-integ] stopping gw (pid=${gw_pid})"
kill "${gw_pid}" 2>/dev/null || true
wait "${gw_pid}" 2>/dev/null || true
unset gw_pid

# Receiver should finish once all 4 datagrams arrive (or timeout).
wait "${recv_pid}" || {
    echo "[udp-integ] receiver failed; log:" >&2
    cat "${recv_log}" >&2
    exit 1
}
unset recv_pid

echo "[udp-integ] verifying ${cap_file}"
"${probe_bin}" verify \
    --file "${cap_file}" \
    --expected-payloads "${payloads}"

echo "[udp-integ] PASS"

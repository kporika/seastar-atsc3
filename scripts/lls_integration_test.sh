#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Integration: gw --sink lls://127.0.0.1:R (cleartext XML ingress → Table 6.1
# + gzip UDP). Python validates one received datagram against expected XML.
#
# Usage:
#   scripts/lls_integration_test.sh [build_dir]

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${script_dir}/_lib.sh"

repo_root="$(cd "${script_dir}/.." && pwd)"
build_dir="${1:-${repo_root}/build}"

gw_bin="$(resolve_bin "${ATSC3_GW:-}"  "${build_dir}/gw/atsc3_gw"          atsc3_gw)"
probe_bin="$(resolve_bin "${MMT_PROBE:-}" "${build_dir}/mmt_probe/mmt_probe" mmt_probe)"
py3="$(command -v python3)"

echo "[lls-integ] gw=${gw_bin}"
echo "[lls-integ] probe=${probe_bin}"

tcp_port=$(( ( RANDOM % 10000 ) + 19000 ))
udp_port=$(( ( RANDOM % 10000 ) + 29000 ))
if [[ "${udp_port}" -eq "${tcp_port}" ]]; then
    udp_port=$((udp_port + 1))
fi

tcp_addr="127.0.0.1:${tcp_port}"
udp_addr="127.0.0.1:${udp_port}"

tmpdir="$(mktemp -d -t atsc3_lls_integ.XXXXXX)"
expected_xml="${tmpdir}/expected.xml"
log_file="${tmpdir}/gw.log"
recv_log="${tmpdir}/recv.log"

# Minimal cleartext “XML” for lab (gateway gzips and prefixes per A/331).
printf '%s' '<a/>' >"${expected_xml}"
# mmt_probe --payloads expects hex; UTF-8 of "<a/>" (no xxd in slim images)
payload_hex="3c612f3e"

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

echo "[lls-integ] receiver on ${udp_addr} (validating against ${expected_xml})"
"${py3}" "${script_dir}/_lls_lab_integ_recv.py" "127.0.0.1" "${udp_port}" \
    12.0 "${expected_xml}" >"${recv_log}" 2>&1 &
recv_pid=$!

sleep 0.15

echo "[lls-integ] starting atsc3_gw on ${tcp_addr} (sink=lls://${udp_addr})"
"${gw_bin}" --smp 1 \
    --ingress "${tcp_addr}" \
    --sink "lls://${udp_addr}" \
    >"${log_file}" 2>&1 &
gw_pid=$!

for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if (echo > /dev/tcp/127.0.0.1/${tcp_port}) >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
    if ! kill -0 "${gw_pid}" 2>/dev/null; then
        echo "[lls-integ] gw exited early; log:" >&2
        cat "${log_file}" >&2
        exit 1
    fi
done

echo "[lls-integ] sending cleartext XML as one TCP payload"
"${probe_bin}" send --target "${tcp_addr}" --payloads "${payload_hex}"

echo "[lls-integ] stopping gw (pid=${gw_pid})"
kill "${gw_pid}" 2>/dev/null || true
wait "${gw_pid}" 2>/dev/null || true
unset gw_pid

wait "${recv_pid}" || {
    echo "[lls-integ] receiver failed; log:" >&2
    cat "${recv_log}" >&2
    exit 1
}
unset recv_pid

echo "[lls-integ] PASS"

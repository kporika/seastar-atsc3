#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Integration: gw --sink ipv4udp-file://… (M8 append per frame), then
# tools/m8_bin_to_pcap.py --extract-tlvmux and mmt_probe verify.
#
# Usage:
#   scripts/ipv4udp_file_integration_test.sh [build_dir]
#
# Requires: python3, same binaries as scripts/integration_test.sh

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${script_dir}/_lib.sh"

repo_root="$(cd "${script_dir}/.." && pwd)"
build_dir="${1:-$(detect_default_build_dir "${repo_root}")}"

gw_bin="$(resolve_bin "${ATSC3_GW:-}"  "${build_dir}/gw/atsc3_gw"          atsc3_gw)"
probe_bin="$(resolve_bin "${MMT_PROBE:-}" "${build_dir}/mmt_probe/mmt_probe" mmt_probe)"
py3="$(command -v python3)"
m8_tool="${repo_root}/tools/m8_bin_to_pcap.py"

echo "[m8-integ] gw=${gw_bin}"
echo "[m8-integ] probe=${probe_bin}"

tcp_port=$(( ( RANDOM % 10000 ) + 19000 ))
addr="127.0.0.1:${tcp_port}"

tmpdir="$(mktemp -d -t atsc3_m8_integ.XXXXXX)"
sink_prefix="${tmpdir}/gw.m8"
tlv_extracted="${tmpdir}/tlv_concat.bin"
log_file="${tmpdir}/gw.log"

cleanup() {
    if [[ -n "${gw_pid:-}" ]] && kill -0 "${gw_pid}" 2>/dev/null; then
        kill "${gw_pid}" 2>/dev/null || true
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            kill -0 "${gw_pid}" 2>/dev/null || break
            sleep 0.1
        done
        kill -9 "${gw_pid}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Lab-only addresses (never sent on a wire; only embedded in the M8 file).
sink_uri="ipv4udp-file://${sink_prefix}?src=10.45.67.89&dst=10.98.76.54&srcport=33333&dstport=44444"

echo "[m8-integ] starting atsc3_gw on ${addr} (sink=${sink_uri})"
"${gw_bin}" --smp 1 \
    --ingress "${addr}" \
    --sink "${sink_uri}" \
    >"${log_file}" 2>&1 &
gw_pid=$!

for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if (echo > /dev/tcp/127.0.0.1/${tcp_port}) >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
    if ! kill -0 "${gw_pid}" 2>/dev/null; then
        echo "[m8-integ] gw exited early; log:" >&2
        cat "${log_file}" >&2
        exit 1
    fi
done

payloads="DEADBEEF,CAFEBABE,1122334455667788,$(printf 'AB%.0s' {1..32})"

echo "[m8-integ] sending payloads"
"${probe_bin}" send --target "${addr}" --payloads "${payloads}"

shard_file="${sink_prefix}.shard0"

prev_size=-1
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if [[ -f "${shard_file}" ]]; then
        size=$(stat -c%s "${shard_file}" 2>/dev/null || stat -f%z "${shard_file}")
        if [[ "${size}" -gt 0 && "${size}" -eq "${prev_size}" ]]; then
            break
        fi
        prev_size=${size}
    fi
    sleep 0.1
done

echo "[m8-integ] stopping gw (pid=${gw_pid})"
kill "${gw_pid}" 2>/dev/null || true
wait "${gw_pid}" 2>/dev/null || true
unset gw_pid

if [[ ! -f "${shard_file}" ]]; then
    echo "[m8-integ] missing shard file ${shard_file}" >&2
    exit 1
fi

echo "[m8-integ] extracting TLV-mux from M8 capture -> ${tlv_extracted}"
"${py3}" "${m8_tool}" -i "${shard_file}" --extract-tlvmux "${tlv_extracted}"

echo "[m8-integ] verifying ${tlv_extracted}"
"${probe_bin}" verify \
    --file "${tlv_extracted}" \
    --expected-payloads "${payloads}"

echo "[m8-integ] PASS"

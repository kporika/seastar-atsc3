#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Integration: (E) MMTP word-0 only; (F) MMTP word-0 then LCT word-0 (gw lab order).
#
# Usage:
#   scripts/mmtp_word0_integration_test.sh [BUILD_DIR]

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${script_dir}/_lib.sh"

repo_root="$(cd "${script_dir}/.." && pwd)"
build_dir="${1:-$(detect_default_build_dir "${repo_root}")}"

gw_bin="$(resolve_bin "${ATSC3_GW:-}"  "${build_dir}/gw/atsc3_gw"          atsc3_gw)"
probe_bin="$(resolve_bin "${MMT_PROBE:-}" "${build_dir}/mmt_probe/mmt_probe" mmt_probe)"

mmtp_pt=2
mmtp_pid=16
lct_cp=91

echo "[mmtp_word0_integ] gw=${gw_bin}"
echo "[mmtp_word0_integ] probe=${probe_bin}"

payloads="DEADBEEF,CAFEBABE,1122334455667788,$(printf 'AB%.0s' {1..32})"
tmpdir="$(mktemp -d -t atsc3_mmtp.XXXXXX)"

gw_pid=""
cleanup_gw() {
    if [[ -n "${gw_pid}" ]] && kill -0 "${gw_pid}" 2>/dev/null; then
        kill "${gw_pid}" 2>/dev/null || true
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            kill -0 "${gw_pid}" 2>/dev/null || break
            sleep 0.1
        done
        kill -9 "${gw_pid}" 2>/dev/null || true
    fi
    gw_pid=""
}

trap cleanup_gw EXIT

run_phase() {
    local phase_name="$1" port="$2" sink_pfx="$3" gw_log="$4"
    shift 4
    local -a gw_extra=("$@")

    cleanup_gw
    "${gw_bin}" --smp 1 \
        --ingress "127.0.0.1:${port}" \
        --sink "file://${sink_pfx}" \
        "${gw_extra[@]}" \
        >"${gw_log}" 2>&1 &
    gw_pid=$!

    local i
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        if (echo > "/dev/tcp/127.0.0.1/${port}") >/dev/null 2>&1; then
            break
        fi
        sleep 0.1
        if ! kill -0 "${gw_pid}" 2>/dev/null; then
            echo "[mmtp_word0_integ:${phase_name}] gw exited early; log:"
            cat "${gw_log}" >&2
            exit 1
        fi
    done

    echo "[mmtp_word0_integ:${phase_name}] send"
    "${probe_bin}" send --target "127.0.0.1:${port}" --payloads "${payloads}"

    local sink_file="${sink_pfx}.shard0"
    local prev=-1 _
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        if [[ -f "${sink_file}" ]]; then
            local size
            size=$(stat -c%s "${sink_file}" 2>/dev/null || stat -f%z "${sink_file}")
            if [[ "${size}" -gt 0 && "${size}" -eq "${prev}" ]]; then
                break
            fi
            prev=${size}
        fi
        sleep 0.1
    done

    cleanup_gw

    echo "[mmtp_word0_integ:${phase_name}] verify ${sink_file}"
}

port_e=$(( ( RANDOM % 10000 ) + 27000 ))
port_f=$(( ( RANDOM % 10000 ) + 37000 ))

echo "[mmtp_word0_integ] phase E: MMTP word-0 only (payload_type=${mmtp_pt} packet_id=${mmtp_pid})"
run_phase "E" "${port_e}" "${tmpdir}/e.out" "${tmpdir}/gw_e.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}"
"${probe_bin}" verify \
    --file "${tmpdir}/e.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --expected-payloads "${payloads}"

echo "[mmtp_word0_integ] phase F: MMTP then LCT word-0 (codepoint=${lct_cp})"
run_phase "F" "${port_f}" "${tmpdir}/f.out" "${tmpdir}/gw_f.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-lct-word0 \
    --lct-codepoint "${lct_cp}"
"${probe_bin}" verify \
    --file "${tmpdir}/f.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-lct-word0 \
    --expect-lct-codepoint "${lct_cp}" \
    --expected-payloads "${payloads}"

echo "[mmtp_word0_integ] PASS"

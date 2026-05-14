#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Integration: (A) word-0 only; (B) + TSI BE32; (C) + TOI (**RFC5651 O**=1).
#
# Usage:
#   scripts/lct_word0_integration_test.sh [BUILD_DIR]

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${script_dir}/_lib.sh"

repo_root="$(cd "${script_dir}/.." && pwd)"
build_dir="${1:-$(detect_default_build_dir "${repo_root}")}"

gw_bin="$(resolve_bin "${ATSC3_GW:-}"  "${build_dir}/gw/atsc3_gw"          atsc3_gw)"
probe_bin="$(resolve_bin "${MMT_PROBE:-}" "${build_dir}/mmt_probe/mmt_probe" mmt_probe)"

lct_cp=91
lct_tsi=60221
lct_toi=44103

echo "[lct_word0_integ] gw=${gw_bin}"
echo "[lct_word0_integ] probe=${probe_bin}"

payloads="DEADBEEF,CAFEBABE,1122334455667788,$(printf 'AB%.0s' {1..32})"
tmpdir="$(mktemp -d -t atsc3_lct.XXXXXX)"

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
        --prepend-lct-word0 \
        --lct-codepoint "${lct_cp}" \
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
            echo "[lct_word0_integ:${phase_name}] gw exited early; log:"
            cat "${gw_log}" >&2
            exit 1
        fi
    done

    echo "[lct_word0_integ:${phase_name}] send"
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

    echo "[lct_word0_integ:${phase_name}] verify ${sink_file}"
}

port_a=$(( ( RANDOM % 10000 ) + 29000 ))
port_b=$(( ( RANDOM % 10000 ) + 39000 ))
port_c=$(( ( RANDOM % 10000 ) + 49000 ))

echo "[lct_word0_integ] phase A: word-0 only (codepoint=${lct_cp})"
run_phase "A" "${port_a}" "${tmpdir}/a.out" "${tmpdir}/gw_a.log"
"${probe_bin}" verify \
    --file "${tmpdir}/a.out.shard0" \
    --strip-lct-word0 \
    --expect-lct-codepoint "${lct_cp}" \
    --expected-payloads "${payloads}"

echo "[lct_word0_integ] phase B: word-0 + 32-bit TSI (${lct_tsi})"
run_phase "B" "${port_b}" "${tmpdir}/b.out" "${tmpdir}/gw_b.log" \
    --lct-include-tsi --lct-tsi "${lct_tsi}"
"${probe_bin}" verify \
    --file "${tmpdir}/b.out.shard0" \
    --strip-lct-word0 \
    --expect-lct-codepoint "${lct_cp}" \
    --expect-lct-tsi "${lct_tsi}" \
    --expected-payloads "${payloads}"

echo "[lct_word0_integ] phase C: word-0 + 32-bit TOI O=1 (${lct_toi})"
run_phase "C" "${port_c}" "${tmpdir}/c.out" "${tmpdir}/gw_c.log" \
    --lct-include-toi --lct-toi "${lct_toi}"
"${probe_bin}" verify \
    --file "${tmpdir}/c.out.shard0" \
    --strip-lct-word0 \
    --expect-lct-codepoint "${lct_cp}" \
    --expect-lct-toi "${lct_toi}" \
    --expected-payloads "${payloads}"

echo "[lct_word0_integ] PASS"

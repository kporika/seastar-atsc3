#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Integration: (E) word-0 only; (F) word-0+LCT; (G) word-0+ts_psn; (H) word-0+extension;
# (I) word-0+ts_psn+extension; (J) word-0+ts_psn+packet_counter; (K) word-0+ts_psn+counter+extension;
# (L) word-0 + signalling payload prefix (§9.3.4, 16b); (M) word-0 + two chained **X** extensions;
# (N) word-0 + signalling prefix (L=1, A=1) + §9.3.4 aggregated bodies (32b lengths);
# (O) word-0 (**payload_type**=**0**) + **ISOBMFF** payload prefix (64b Figure 3, **A**=**0**);
# (P) word-0 + **ISOBMFF** **A**=**1** + **DU_length**+body pairs (**--mmtp-isobmff-aggregate-hex**).
# (Q) word-0 + **ISOBMFF** **A**=**0** + optional **DU_header** (Fig. 5, **T**=**0**) + verify strip.
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
mmtp_ts=305419896   # 0x12345678
mmtp_psn=42
mmtp_ext_type=43981   # 0xABCD (matches mmtp_header_extension fixture four_byte_value)
mmtp_ext_hex=DEADBEEF
mmtp_ext2_type=7
mmtp_ext2_hex=0102
mmtp_pc=3735928559    # 0xDEADBEEF (mmtp_header_counter32 fixture)
mmtp_iso_seq=287454020  # 0x11223344 (mmtp_payload_isobmff_prefix fixture media_unit_single_du)

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
port_g=$(( ( RANDOM % 10000 ) + 47000 ))
port_h=$(( ( RANDOM % 10000 ) + 57000 ))
port_i=$(( ( RANDOM % 10000 ) + 67000 ))
port_j=$(( ( RANDOM % 10000 ) + 77000 ))
port_k=$(( ( RANDOM % 10000 ) + 87000 ))
port_l=$(( ( RANDOM % 10000 ) + 97000 ))
port_m=$(( ( RANDOM % 10000 ) + 107000 ))
port_n=$(( ( RANDOM % 10000 ) + 117000 ))
port_o=$(( ( RANDOM % 10000 ) + 127000 ))
port_p=$(( ( RANDOM % 10000 ) + 137000 ))
port_q=$(( ( RANDOM % 10000 ) + 147000 ))

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

echo "[mmtp_word0_integ] phase G: MMTP word-0 + ts_psn (ts=${mmtp_ts} psn=${mmtp_psn})"
run_phase "G" "${port_g}" "${tmpdir}/g.out" "${tmpdir}/gw_g.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-ts-psn \
    --mmtp-timestamp "${mmtp_ts}" \
    --mmtp-psn "${mmtp_psn}"
"${probe_bin}" verify \
    --file "${tmpdir}/g.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-ts-psn \
    --expect-mmtp-timestamp "${mmtp_ts}" \
    --expect-mmtp-psn "${mmtp_psn}" \
    --expected-payloads "${payloads}"

echo "[mmtp_word0_integ] phase H: MMTP word-0 + header extension (type=${mmtp_ext_type})"
run_phase "H" "${port_h}" "${tmpdir}/h.out" "${tmpdir}/gw_h.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-extension \
    --mmtp-extension-type "${mmtp_ext_type}" \
    --mmtp-extension-hex "${mmtp_ext_hex}"
"${probe_bin}" verify \
    --file "${tmpdir}/h.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-extension \
    --expect-mmtp-extension-type "${mmtp_ext_type}" \
    --expect-mmtp-extension-hex "${mmtp_ext_hex}" \
    --expected-payloads "${payloads}"

echo "[mmtp_word0_integ] phase I: MMTP word-0 + ts_psn + extension"
run_phase "I" "${port_i}" "${tmpdir}/i.out" "${tmpdir}/gw_i.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-ts-psn \
    --mmtp-timestamp "${mmtp_ts}" \
    --mmtp-psn "${mmtp_psn}" \
    --prepend-mmtp-extension \
    --mmtp-extension-type "${mmtp_ext_type}" \
    --mmtp-extension-hex "${mmtp_ext_hex}"
"${probe_bin}" verify \
    --file "${tmpdir}/i.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-ts-psn \
    --expect-mmtp-timestamp "${mmtp_ts}" \
    --expect-mmtp-psn "${mmtp_psn}" \
    --strip-mmtp-extension \
    --expect-mmtp-extension-type "${mmtp_ext_type}" \
    --expect-mmtp-extension-hex "${mmtp_ext_hex}" \
    --expected-payloads "${payloads}"

echo "[mmtp_word0_integ] phase J: MMTP word-0 + ts_psn + packet_counter (pc=${mmtp_pc})"
run_phase "J" "${port_j}" "${tmpdir}/j.out" "${tmpdir}/gw_j.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-ts-psn \
    --mmtp-timestamp "${mmtp_ts}" \
    --mmtp-psn "${mmtp_psn}" \
    --prepend-mmtp-packet-counter \
    --mmtp-packet-counter "${mmtp_pc}"
"${probe_bin}" verify \
    --file "${tmpdir}/j.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-ts-psn \
    --expect-mmtp-timestamp "${mmtp_ts}" \
    --expect-mmtp-psn "${mmtp_psn}" \
    --strip-mmtp-packet-counter \
    --expect-mmtp-packet-counter "${mmtp_pc}" \
    --expected-payloads "${payloads}"

echo "[mmtp_word0_integ] phase K: MMTP word-0 + ts_psn + packet_counter + extension"
run_phase "K" "${port_k}" "${tmpdir}/k.out" "${tmpdir}/gw_k.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-ts-psn \
    --mmtp-timestamp "${mmtp_ts}" \
    --mmtp-psn "${mmtp_psn}" \
    --prepend-mmtp-packet-counter \
    --mmtp-packet-counter "${mmtp_pc}" \
    --prepend-mmtp-extension \
    --mmtp-extension-type "${mmtp_ext_type}" \
    --mmtp-extension-hex "${mmtp_ext_hex}"
"${probe_bin}" verify \
    --file "${tmpdir}/k.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-ts-psn \
    --expect-mmtp-timestamp "${mmtp_ts}" \
    --expect-mmtp-psn "${mmtp_psn}" \
    --strip-mmtp-packet-counter \
    --expect-mmtp-packet-counter "${mmtp_pc}" \
    --strip-mmtp-extension \
    --expect-mmtp-extension-type "${mmtp_ext_type}" \
    --expect-mmtp-extension-hex "${mmtp_ext_hex}" \
    --expected-payloads "${payloads}"

echo "[mmtp_word0_integ] phase L: MMTP word-0 + signalling payload prefix (FI=1 L=1 frag_ctr=7 → 42 07)"
run_phase "L" "${port_l}" "${tmpdir}/l.out" "${tmpdir}/gw_l.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --mmtp-signalling-fragmentation 1 \
    --mmtp-signalling-length-extension \
    --mmtp-signalling-fragment-counter 7
"${probe_bin}" verify \
    --file "${tmpdir}/l.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 1 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 1 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 7 \
    --expected-payloads "${payloads}"

echo "[mmtp_word0_integ] phase M: MMTP word-0 + chained header extensions (2× X)"
run_phase "M" "${port_m}" "${tmpdir}/m.out" "${tmpdir}/gw_m.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-extension \
    --mmtp-extension "${mmtp_ext_type}:${mmtp_ext_hex}" \
    --mmtp-extension "${mmtp_ext2_type}:${mmtp_ext2_hex}"
"${probe_bin}" verify \
    --file "${tmpdir}/m.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-extension \
    --strip-mmtp-extension-count 2 \
    --expect-mmtp-extension-pair "${mmtp_ext_type}:${mmtp_ext_hex}" \
    --expect-mmtp-extension-pair "${mmtp_ext2_type}:${mmtp_ext2_hex}" \
    --expected-payloads "${payloads}"

echo "[mmtp_word0_integ] phase N: MMTP word-0 + signalling (L=1, A=1) + aggregated bodies (32b lengths)"
run_phase "N" "${port_n}" "${tmpdir}/n.out" "${tmpdir}/gw_n.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --mmtp-signalling-length-extension \
    --mmtp-signalling-aggregation \
    --mmtp-signalling-aggregate-hex 010203 --mmtp-signalling-aggregate-hex FEED
"${probe_bin}" verify \
    --file "${tmpdir}/n.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 1 \
    --expect-mmtp-signalling-aggregation 1 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmtp-signalling-aggregate-count 2 \
    --expect-mmtp-signalling-aggregate-hex 010203 \
    --expect-mmtp-signalling-aggregate-hex FEED \
    --expected-payloads "${payloads}"

echo "[mmtp_word0_integ] phase O: MMTP word-0 (ISOBMFF **payload_type**=**0**) + **mmtp_payload_isobmff_prefix** (FT=2, T=1, seq=0x11223344)"
run_phase "O" "${port_o}" "${tmpdir}/o.out" "${tmpdir}/gw_o.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type 0 \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-isobmff-prefix \
    --mmtp-isobmff-fragment-type 2 \
    --mmtp-isobmff-timed \
    --mmtp-isobmff-fragmentation 0 \
    --mmtp-isobmff-fragment-counter 0 \
    --mmtp-isobmff-sequence-number "${mmtp_iso_seq}"
"${probe_bin}" verify \
    --file "${tmpdir}/o.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type 0 \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-isobmff-prefix \
    --expect-mmtp-isobmff-fragment-type 2 \
    --expect-mmtp-isobmff-timed 1 \
    --expect-mmtp-isobmff-fragmentation 0 \
    --expect-mmtp-isobmff-aggregation 0 \
    --expect-mmtp-isobmff-fragment-counter 0 \
    --expect-mmtp-isobmff-sequence-number "${mmtp_iso_seq}" \
    --expected-payloads "${payloads}"

echo "[mmtp_word0_integ] phase P: MMTP word-0 + ISOBMFF prefix (**A**=**1**) + **DU_length** + body pairs + CSV tail"
run_phase "P" "${port_p}" "${tmpdir}/p.out" "${tmpdir}/gw_p.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type 0 \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-isobmff-prefix \
    --mmtp-isobmff-fragment-type 2 \
    --mmtp-isobmff-timed \
    --mmtp-isobmff-fragmentation 0 \
    --mmtp-isobmff-aggregation \
    --mmtp-isobmff-aggregate-hex AABB --mmtp-isobmff-aggregate-hex CC \
    --mmtp-isobmff-fragment-counter 0 \
    --mmtp-isobmff-sequence-number "${mmtp_iso_seq}"
"${probe_bin}" verify \
    --file "${tmpdir}/p.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type 0 \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-isobmff-prefix \
    --expect-mmtp-isobmff-fragment-type 2 \
    --expect-mmtp-isobmff-timed 1 \
    --expect-mmtp-isobmff-fragmentation 0 \
    --expect-mmtp-isobmff-aggregation 1 \
    --expect-mmtp-isobmff-fragment-counter 0 \
    --expect-mmtp-isobmff-sequence-number "${mmtp_iso_seq}" \
    --expect-mmtp-isobmff-aggregate-hex AABB \
    --expect-mmtp-isobmff-aggregate-hex CC \
    --expected-payloads "${payloads}"

echo "[mmtp_word0_integ] phase Q: MMTP word-0 + ISOBMFF (**T**=**0**) + **DU_header** + verify strip"
run_phase "Q" "${port_q}" "${tmpdir}/q.out" "${tmpdir}/gw_q.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type 0 \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-isobmff-prefix \
    --mmtp-isobmff-fragment-type 2 \
    --mmtp-isobmff-fragmentation 0 \
    --mmtp-isobmff-fragment-counter 0 \
    --mmtp-isobmff-sequence-number "${mmtp_iso_seq}" \
    --prepend-mmtp-isobmff-du-header \
    --mmtp-isobmff-du-item-id "${mmtp_ts}"
"${probe_bin}" verify \
    --file "${tmpdir}/q.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type 0 \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-isobmff-prefix \
    --expect-mmtp-isobmff-fragment-type 2 \
    --expect-mmtp-isobmff-timed 0 \
    --expect-mmtp-isobmff-fragmentation 0 \
    --expect-mmtp-isobmff-aggregation 0 \
    --expect-mmtp-isobmff-fragment-counter 0 \
    --expect-mmtp-isobmff-sequence-number "${mmtp_iso_seq}" \
    --strip-mmtp-isobmff-du-header \
    --expect-mmtp-isobmff-du-item-id "${mmtp_ts}" \
    --expected-payloads "${payloads}"

echo "[mmtp_word0_integ] PASS"

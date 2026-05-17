#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Integration: (E) word-0 only; (F) word-0+LCT; (G) word-0+ts_psn; (H) word-0+extension;
# (I) word-0+ts_psn+extension; (J) word-0+ts_psn+packet_counter; (K) word-0+ts_psn+counter+extension;
# (L) word-0 + signalling payload prefix (§9.3.4, 16b); (M) word-0 + two chained **X** extensions;
# (N) word-0 + signalling prefix (L=1, A=1) + §9.3.4 aggregated bodies (32b lengths);
# (O) word-0 (**payload_type**=**0**) + **ISOBMFF** payload prefix (64b Figure 3, **A**=**0**);
# (P) word-0 + **ISOBMFF** **A**=**1** + **DU_length**+body pairs (**--mmtp-isobmff-aggregate-hex**).
# (R) word-0 + **ISOBMFF** **A**=**1** + **DU_header** per **DU** + **mmt_probe** strip (**aggregate-hex** = media only).
# (Q) word-0 + **ISOBMFF** **A**=**0** + optional **DU_header** (Fig. 5, **T**=**0**) + verify strip.
# (S) word-0 (**payload_type**=**1**) + **GFD** payload header (Fig. 6) + **mmt_probe** **`--strip-mmtp-gfd-header`**.
# (T) **ALP** §5.2 **`--alp-payload-config`** + **`--alp-header-mode`** on the wire + **mmt_probe** **`--expect-alp-*`**.
# (U) word-0 (**payload_type**=**0**) + **ISOBMFF** prefix **FT**=**1** (media fragment / **MFU**, no **DU_header**) + verify.
# (V)–(X) **MMT-SI routing lab:** **payload_type**=**2** + **§9.3.4** prefix (**00 00**) + same user payloads;
# **`packet_id`** **0** / **1** / **2** (informative: some ARIB MMT broadcast descriptions use **PID** **0** for **PA**).
# (Y) **§10.2-style lab envelope:** same as (L) default signalling + **`mmt_si_length32_envelope`** (**BE32** len + body) + **mmt_probe** peel.
# (Z) **§10.3 table-region lab:** same default signalling + **`mmt_si_descriptor_loop_u32`** (**BE32** + **mmtp_desc** region) + **mmt_probe** peel.
# (**ZA**) **Stacked SI lab:** same as **Z** plus **`mmt_si_length32_envelope`** around the descriptor loop (**§10.2** wrap of **§10.3** region) + **mmt_probe** peel (**length32** then **descriptor loop**).
# (**ZB**) **§10.3 message header lab:** default signalling + **`mmt_si_message_header_len32`** (**message_id**/**version**/**BE32** **message_byte_length** + ingress) + **mmt_probe** peel (outermost vs **Y**/**Z**/**ZA**).
# (**ZC**) **§10.3 PA table index lab:** same as **ZB** plus **`mmt_si_pa_table_headers`** (**number_of_tables** + header rows) **inside** the message body before ingress + **mmt_probe** peel (**message** then **PA index**).
# (**ZD**) **§10.3 PA table body lab:** same as **ZC** with one MPT row **table_length** = ingress size (ingress is the table body octets).
# (**ZE**) **§10.3 multi-table body lab:** two PA rows (MPT + PLT), both **table_length** > 0; ingress = bodies concatenated in row order.
# (**ZF**) **§10.3 mixed PA rows + SI tail lab:** MPT body row + PLT index-only row; ingress = table body octets then SI tail.
# (**ZG**) **§10.3 MPT table wire lab:** ingress is **mmt_si_mpt_table** (**table_id** **0x20**) + **PA** row **32:1:N**; **gw** validates parse.
# (**ZH**) **§10.3 PLT table wire lab:** ingress is **mmt_si_plt_table** (**table_id** **0x80**) + **PA** row **128:0:N**.
# (**ZI**) **§10.3 MPT table body prefix lab:** **ZG** + **`mmt_si_mpt_table_body_prefix`** parse (**number_of_assets** **0**).
# (**ZJ**) **§10.3 PLT table body prefix lab:** **ZH** + **`mmt_si_plt_table_body_prefix`** parse.
# (**ZK**) **§10.3 MPT asset lab:** **ZG**-style ingress with **one** **`mmt_si_mpt_asset`** (**asset_id_length** **0**).
# (**ZL**) **§10.3 PLT DeliveryInfo lab:** **ZH**-style ingress with **one** **`mmt_si_plt_delivery_info`** (**location_type** **0**).
# (**ZM**) **§10.3 PLT DeliveryInfo IPv4 lab:** **ZH**-style ingress with **one** **`mmt_si_plt_delivery_info_ipv4`** (**location_type** **1**).
# (**ZN**) **§10.3 PLT DeliveryInfo IPv6 lab:** **ZH**-style ingress with **one** **`mmt_si_plt_delivery_info_ipv6`** (**location_type** **2**).
# (**ZO**) **§10.3 PLT DeliveryInfo URL lab:** **ZH**-style ingress with **one** **`mmt_si_plt_delivery_info_url`** (**location_type** **5**, **url_length** **0**).
# (**ZP**) **§10.3 PLT package entry lab:** **ZH**-style ingress with **one** **`mmt_si_plt_package_entry`** (**MMT_package_id_length** **0**, **location_type** **0**).
# (**ZQ**) **§10.3 PLT DeliveryInfo URL (3 B) lab:** **ZH**-style ingress with **one** **`mmt_si_plt_delivery_info_url_3`** (**url_length** **3**, URL **lab**).
# (**ZR**) **§10.3 PLT package entry (1 B id) lab:** **ZH**-style ingress with **one** **`mmt_si_plt_package_entry_id8`** (**MMT_package_id_length** **1**, **MMT_package_id** **0x01**).
# (**ZS**) **§10.3 MPT asset (1 B id) lab:** **ZG**-style ingress with **one** **`mmt_si_mpt_asset_id8`** (**asset_id_length** **1**, **asset_id** **0x01**).
# (**ZT**) **§10.3 MPT asset (same-flow location) lab:** **ZG**-style ingress with **one** **`mmt_si_mpt_asset_location0`** (**asset_id_length** **0**, **location_count** **1**, **location_type** **0**, **packet_id** **0**).
# (**ZU**) **§10.3 PLT package entry (IPv4 location) lab:** **ZH**-style ingress with **one** **`mmt_si_plt_package_entry_ipv4`** (**MMT_package_id_length** **0**, **location_type** **1**).
# (**ZV**) **§10.3 MPT asset (IPv4 location) lab:** **ZG**-style ingress with **one** **`mmt_si_mpt_asset_location_ipv4`** (**asset_id_length** **0**, **location_count** **1**, **location_type** **1**).
# (**ZW**) **§10.3 MPT asset (1 B id + IPv4 location) lab:** **ZG**-style ingress with **one** **`mmt_si_mpt_asset_id8_location_ipv4`** (**asset_id_length** **1**, **asset_id** **0x01**, **location_type** **1**).
# (**ZX**) **§10.3 PLT package entry (1 B id + IPv4 location) lab:** **ZH**-style ingress with **one** **`mmt_si_plt_package_entry_id8_location_ipv4`** (**MMT_package_id_length** **1**, **MMT_package_id** **0x01**, **location_type** **1**).
# (**ZY**) **§10.3 MPT asset (IPv6 location) lab:** **ZG**-style ingress with **one** **`mmt_si_mpt_asset_location_ipv6`** (**asset_id_length** **0**, **location_count** **1**, **location_type** **2**).
# (**ZZ**) **§10.3 PLT package entry (IPv6 location) lab:** **ZH**-style ingress with **one** **`mmt_si_plt_package_entry_ipv6`** (**MMT_package_id_length** **0**, **location_type** **2**).
# (**AAA**) **§10.3 MPT asset (1 B id + IPv6 location) lab:** **ZG**-style ingress with **one** **`mmt_si_mpt_asset_id8_location_ipv6`** (**asset_id_length** **1**, **asset_id** **0x01**, **location_type** **2**).
# (**AAB**) **§10.3 PLT package entry (1 B id + IPv6 location) lab:** **ZH**-style ingress with **one** **`mmt_si_plt_package_entry_id8_location_ipv6`** (**MMT_package_id_length** **1**, **MMT_package_id** **0x01**, **location_type** **2**).
# (**AAC**) **§10.3 MPT asset (4 B descriptors) lab:** **ZG**-style ingress with **one** **`mmt_si_mpt_asset_descriptors4`** (**asset_id_length** **0**, **asset_descriptors_length** **4**).
# (**AAD**) **§10.3 PLT DeliveryInfo URL (4 B) lab:** **ZH**-style ingress with **one** **`mmt_si_plt_delivery_info_url_4`** (**url_length** **4**, URL **http**).
# (**AAF**) **§10.3 MPT asset IPv4 location (non-zero addrs) lab:** **ZV**-style ingress with **`mmt_si_mpt_asset_location_ipv4_nz`** (**10.0.0.1** → **224.0.0.1:5000**).
# (**AAG**) **§10.3 MPT asset (2 B asset_id) lab:** **ZS**-style ingress with **`mmt_si_mpt_asset_id16`** (**asset_id_length** **2**, **0x01** **0x02**).
# (**AAH**) **§10.3 MPT asset IPv6 location (non-zero addrs) lab:** **ZY**-style ingress with **`mmt_si_mpt_asset_location_ipv6_nz`** (**::ffff:10.0.0.1** → **::ffff:224.0.0.1:5000**).
# (**AAI**) **§10.3 PLT package entry IPv4 (non-zero addrs) lab:** **ZU**-style ingress with **`mmt_si_plt_package_entry_ipv4_nz`** (**10.0.0.1** → **224.0.0.1:5000**).
# (**AAJ**) **§10.3 PLT package entry IPv6 (non-zero addrs) lab:** **ZZ**-style ingress with **`mmt_si_plt_package_entry_ipv6_nz`** (**::ffff:10.0.0.1** → **::ffff:224.0.0.1:5000**).
# (**AAK**) **§10.3 PLT package entry (1 B id + IPv4 non-zero addrs) lab:** **ZX**-style ingress with **`mmt_si_plt_package_entry_id8_location_ipv4_nz`** (**MMT_package_id** **0x01**, **10.0.0.1** → **224.0.0.1:5000**).
# (**AAL**) **§10.3 PLT package entry (1 B id + IPv6 non-zero addrs) lab:** **AAB**-style ingress with **`mmt_si_plt_package_entry_id8_location_ipv6_nz`** (**MMT_package_id** **0x01**, **::ffff:10.0.0.1** → **::ffff:224.0.0.1:5000**).
# (**AAM**) **§10.3 MPT asset (1 B id + IPv4 non-zero addrs) lab:** **ZW**-style ingress with **`mmt_si_mpt_asset_id8_location_ipv4_nz`** (**asset_id** **0x01**, **10.0.0.1** → **224.0.0.1:5000**).
# (**AAN**) **§10.3 MPT asset (1 B id + IPv6 non-zero addrs) lab:** **AAA**-style ingress with **`mmt_si_mpt_asset_id8_location_ipv6_nz`** (**asset_id** **0x01**, **::ffff:10.0.0.1** → **::ffff:224.0.0.1:5000**).
# (**AAO**) **§10.3 MPT asset (2 B id + IPv4 zero addrs) lab:** **`mmt_si_mpt_asset_id16_location_ipv4`** (**asset_id** **0x01** **0x02**, **table_length** **32**).
# (**AAP**) **§10.3 MPT asset (2 B id + IPv4 non-zero addrs) lab:** **`mmt_si_mpt_asset_id16_location_ipv4_nz`** (**10.0.0.1** → **224.0.0.1:5000**).
# (**AAQ**) **§10.3 MPT asset (2 B id + IPv6 zero addrs) lab:** **`mmt_si_mpt_asset_id16_location_ipv6`** (**table_length** **55**).
# (**AAR**) **§10.3 MPT asset (2 B id + IPv6 non-zero addrs) lab:** **`mmt_si_mpt_asset_id16_location_ipv6_nz`** (**::ffff:10.0.0.1** → **::ffff:224.0.0.1:5000**).
# (**AAS**) **§10.3 MPT asset (2 B id + 4 B descriptors) lab:** **`mmt_si_mpt_asset_id16_descriptors4`** (**DEADBEEF**).
# (**AAT**) **§10.3 MPT asset (1 B id + 4 B descriptors) lab:** **`mmt_si_mpt_asset_id8_descriptors4`** (**asset_id** **0x01**, **DEADBEEF**).
# (**AAE**) **§10.3 PLT DeliveryInfo IPv4 (non-zero addrs) lab:** **ZM**-style ingress with **`mmt_si_plt_delivery_info_ipv4_nz`** (**10.0.0.1** → **224.0.0.1:5000**).
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
port_r=$(( ( RANDOM % 10000 ) + 157000 ))
port_q=$(( ( RANDOM % 10000 ) + 147000 ))
port_s=$(( ( RANDOM % 10000 ) + 167000 ))
port_t=$(( ( RANDOM % 10000 ) + 177000 ))
port_u=$(( ( RANDOM % 10000 ) + 187000 ))
port_v=$(( ( RANDOM % 10000 ) + 197000 ))
port_w=$(( ( RANDOM % 10000 ) + 207000 ))
port_x=$(( ( RANDOM % 10000 ) + 217000 ))
port_y=$(( ( RANDOM % 10000 ) + 227000 ))
port_z=$(( ( RANDOM % 10000 ) + 237000 ))
port_za=$(( ( RANDOM % 10000 ) + 247000 ))
port_zb=$(( ( RANDOM % 10000 ) + 257000 ))
port_zc=$(( ( RANDOM % 10000 ) + 267000 ))
port_zd=$(( ( RANDOM % 10000 ) + 277000 ))
port_ze=$(( ( RANDOM % 10000 ) + 287000 ))
port_zf=$(( ( RANDOM % 10000 ) + 297000 ))
port_zg=$(( ( RANDOM % 10000 ) + 307000 ))
port_zh=$(( ( RANDOM % 10000 ) + 317000 ))
port_zi=$(( ( RANDOM % 10000 ) + 327000 ))
port_zj=$(( ( RANDOM % 10000 ) + 337000 ))
port_zk=$(( ( RANDOM % 10000 ) + 347000 ))
port_zl=$(( ( RANDOM % 10000 ) + 357000 ))
port_zm=$(( ( RANDOM % 10000 ) + 367000 ))
port_zn=$(( ( RANDOM % 10000 ) + 377000 ))
port_zo=$(( ( RANDOM % 10000 ) + 387000 ))
port_zp=$(( ( RANDOM % 10000 ) + 397000 ))
port_zq=$(( ( RANDOM % 10000 ) + 407000 ))
port_zr=$(( ( RANDOM % 10000 ) + 417000 ))
port_zs=$(( ( RANDOM % 10000 ) + 427000 ))
port_zt=$(( ( RANDOM % 10000 ) + 437000 ))
port_zu=$(( ( RANDOM % 10000 ) + 447000 ))
port_zv=$(( ( RANDOM % 10000 ) + 457000 ))
port_zw=$(( ( RANDOM % 10000 ) + 467000 ))
port_zx=$(( ( RANDOM % 10000 ) + 477000 ))
port_zy=$(( ( RANDOM % 10000 ) + 487000 ))
port_zz=$(( ( RANDOM % 10000 ) + 497000 ))
port_aaa=$(( ( RANDOM % 10000 ) + 507000 ))
port_aab=$(( ( RANDOM % 10000 ) + 508000 ))
port_aac=$(( ( RANDOM % 10000 ) + 509000 ))
port_aad=$(( ( RANDOM % 10000 ) + 510000 ))
port_aae=$(( ( RANDOM % 10000 ) + 511000 ))
port_aaf=$(( ( RANDOM % 10000 ) + 512000 ))
port_aag=$(( ( RANDOM % 10000 ) + 513000 ))
port_aah=$(( ( RANDOM % 10000 ) + 523000 ))
port_aai=$(( ( RANDOM % 10000 ) + 533000 ))
port_aaj=$(( ( RANDOM % 10000 ) + 543000 ))
port_aak=$(( ( RANDOM % 10000 ) + 553000 ))
port_aal=$(( ( RANDOM % 10000 ) + 563000 ))
port_aam=$(( ( RANDOM % 10000 ) + 573000 ))
port_aan=$(( ( RANDOM % 10000 ) + 583000 ))
port_aao=$(( ( RANDOM % 10000 ) + 593000 ))
port_aap=$(( ( RANDOM % 10000 ) + 603000 ))
port_aaq=$(( ( RANDOM % 10000 ) + 613000 ))
port_aar=$(( ( RANDOM % 10000 ) + 623000 ))
port_aas=$(( ( RANDOM % 10000 ) + 633000 ))
port_aat=$(( ( RANDOM % 10000 ) + 643000 ))

mmtp_gfd_toi=$((0xDEADBEEF))
mmtp_gfd_start=$((0x112233445566))

echo "[mmtp_word0_integ] phase E: MMTP word-0 only (payload_type=${mmtp_pt} packet_id=${mmtp_pid})"
run_phase "E" "${port_e}" "${tmpdir}/e.out" "${tmpdir}/gw_e.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}"
"${probe_bin}" verify \
    --file "${tmpdir}/e.out.shard0" \
    --expect-alp-payload-config 0 \
    --expect-alp-header-mode 0 \
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

echo "[mmtp_word0_integ] phase R: MMTP word-0 + ISOBMFF **A**=**1** + **DU_header** per **DU** + verify strip (media-only expects)"
run_phase "R" "${port_r}" "${tmpdir}/r.out" "${tmpdir}/gw_r.log" \
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
    --mmtp-isobmff-sequence-number "${mmtp_iso_seq}" \
    --prepend-mmtp-isobmff-du-header
"${probe_bin}" verify \
    --file "${tmpdir}/r.out.shard0" \
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
    --strip-mmtp-isobmff-du-header \
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

echo "[mmtp_word0_integ] phase S: MMTP word-0 (**payload_type**=**1**) + **GFD** payload header + **mmt_probe** strip"
run_phase "S" "${port_s}" "${tmpdir}/s.out" "${tmpdir}/gw_s.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type 1 \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-gfd-header \
    --mmtp-gfd-session-last \
    --mmtp-gfd-object-last-byte \
    --mmtp-gfd-code-point 9 \
    --mmtp-gfd-reserved 5 \
    --mmtp-gfd-toi "${mmtp_gfd_toi}" \
    --mmtp-gfd-start-offset "${mmtp_gfd_start}"
"${probe_bin}" verify \
    --file "${tmpdir}/s.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type 1 \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-gfd-header \
    --expect-mmtp-gfd-session-last 1 \
    --expect-mmtp-gfd-object-last-packet 0 \
    --expect-mmtp-gfd-object-last-byte 1 \
    --expect-mmtp-gfd-code-point 9 \
    --expect-mmtp-gfd-reserved 5 \
    --expect-mmtp-gfd-toi "${mmtp_gfd_toi}" \
    --expect-mmtp-gfd-start-offset "${mmtp_gfd_start}" \
    --expected-payloads "${payloads}"

echo "[mmtp_word0_integ] phase T: **ALP** **pc**/**hm** via gw flags + **mmt_probe** expect"
run_phase "T" "${port_t}" "${tmpdir}/t.out" "${tmpdir}/gw_t.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --alp-payload-config \
    --alp-header-mode
"${probe_bin}" verify \
    --file "${tmpdir}/t.out.shard0" \
    --expect-alp-payload-config 1 \
    --expect-alp-header-mode 1 \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --expected-payloads "${payloads}"

echo "[mmtp_word0_integ] phase U: MMTP word-0 (**payload_type**=**0**) + **ISOBMFF** prefix **FT**=**1** (**MFU** / media fragment, no **DU_header**)"
run_phase "U" "${port_u}" "${tmpdir}/u.out" "${tmpdir}/gw_u.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type 0 \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-isobmff-prefix \
    --mmtp-isobmff-fragment-type 1 \
    --mmtp-isobmff-fragmentation 0 \
    --mmtp-isobmff-fragment-counter 0 \
    --mmtp-isobmff-sequence-number "${mmtp_iso_seq}"
"${probe_bin}" verify \
    --file "${tmpdir}/u.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type 0 \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-isobmff-prefix \
    --expect-mmtp-isobmff-fragment-type 1 \
    --expect-mmtp-isobmff-timed 0 \
    --expect-mmtp-isobmff-fragmentation 0 \
    --expect-mmtp-isobmff-aggregation 0 \
    --expect-mmtp-isobmff-fragment-counter 0 \
    --expect-mmtp-isobmff-sequence-number "${mmtp_iso_seq}" \
    --expected-payloads "${payloads}"

echo "[mmtp_word0_integ] phase V: **signalling** (**payload_type**=**2**) + §**9.3.4** prefix + **packet_id**=**0** (PA-style SI sub-flow lab)"
run_phase "V" "${port_v}" "${tmpdir}/v.out" "${tmpdir}/gw_v.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type 2 \
    --mmtp-packet-id 0 \
    --prepend-mmtp-signalling-prefix
"${probe_bin}" verify \
    --file "${tmpdir}/v.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type 2 \
    --expect-mmtp-packet-id 0 \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --expected-payloads "${payloads}"

echo "[mmtp_word0_integ] phase W: **signalling** + §**9.3.4** prefix + **packet_id**=**1** (MPI-style SI sub-flow lab)"
run_phase "W" "${port_w}" "${tmpdir}/w.out" "${tmpdir}/gw_w.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type 2 \
    --mmtp-packet-id 1 \
    --prepend-mmtp-signalling-prefix
"${probe_bin}" verify \
    --file "${tmpdir}/w.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type 2 \
    --expect-mmtp-packet-id 1 \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --expected-payloads "${payloads}"

echo "[mmtp_word0_integ] phase X: **signalling** + §**9.3.4** prefix + **packet_id**=**2** (MPT-style SI sub-flow lab)"
run_phase "X" "${port_x}" "${tmpdir}/x.out" "${tmpdir}/gw_x.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type 2 \
    --mmtp-packet-id 2 \
    --prepend-mmtp-signalling-prefix
"${probe_bin}" verify \
    --file "${tmpdir}/x.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type 2 \
    --expect-mmtp-packet-id 2 \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --expected-payloads "${payloads}"

echo "[mmtp_word0_integ] phase Y: signalling + §10.2-style mmt_si_length32_envelope (BE32 length + body) + mmt_probe strip"
run_phase "Y" "${port_y}" "${tmpdir}/y.out" "${tmpdir}/gw_y.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-length32-envelope
"${probe_bin}" verify \
    --file "${tmpdir}/y.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-length32-envelope \
    --expect-mmt-si-body-byte-length 4 \
    --expect-mmt-si-body-byte-length 4 \
    --expect-mmt-si-body-byte-length 8 \
    --expect-mmt-si-body-byte-length 32 \
    --expected-payloads "${payloads}"

z_payloads="0500,1004DEADBEEF,1010112233445566778899AABBCCDDEEFF00,0500"
saved_payloads="${payloads}"
payloads="${z_payloads}"

echo "[mmtp_word0_integ] phase Z: signalling + §10.3-style mmt_si_descriptor_loop_u32 (BE32 + mmtp_desc region) + mmt_probe strip"
run_phase "Z" "${port_z}" "${tmpdir}/z.out" "${tmpdir}/gw_z.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-descriptor-loop-u32
"${probe_bin}" verify \
    --file "${tmpdir}/z.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-descriptor-loop-u32 \
    --expect-mmt-si-descriptor-loop-length 2 \
    --expect-mmt-si-descriptor-loop-length 6 \
    --expect-mmt-si-descriptor-loop-length 18 \
    --expect-mmt-si-descriptor-loop-length 2 \
    --expected-payloads "${z_payloads}"

payloads="${saved_payloads}"

echo "[mmtp_word0_integ] phase ZA: signalling + §10.3 mmt_si_descriptor_loop_u32 + §10.2 mmt_si_length32_envelope (nested peels)"
payloads="${z_payloads}"
run_phase "ZA" "${port_za}" "${tmpdir}/za.out" "${tmpdir}/gw_za.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-descriptor-loop-u32 \
    --prepend-mmt-si-length32-envelope
"${probe_bin}" verify \
    --file "${tmpdir}/za.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-length32-envelope \
    --expect-mmt-si-body-byte-length 6 \
    --expect-mmt-si-body-byte-length 10 \
    --expect-mmt-si-body-byte-length 22 \
    --expect-mmt-si-body-byte-length 6 \
    --strip-mmt-si-descriptor-loop-u32 \
    --expect-mmt-si-descriptor-loop-length 2 \
    --expect-mmt-si-descriptor-loop-length 6 \
    --expect-mmt-si-descriptor-loop-length 18 \
    --expect-mmt-si-descriptor-loop-length 2 \
    --expected-payloads "${z_payloads}"

payloads="${saved_payloads}"

echo "[mmtp_word0_integ] phase ZB: signalling + §10.3 mmt_si_message_header_len32 (PA id=0, version=1) + mmt_probe strip"
run_phase "ZB" "${port_zb}" "${tmpdir}/zb.out" "${tmpdir}/gw_zb.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1
"${probe_bin}" verify \
    --file "${tmpdir}/zb.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 4 \
    --expect-mmt-si-message-byte-length 4 \
    --expect-mmt-si-message-byte-length 8 \
    --expect-mmt-si-message-byte-length 32 \
    --expected-payloads "${payloads}"

echo "[mmtp_word0_integ] phase ZC: signalling + §10.3 mmt_si_message_header_len32 + mmt_si_pa_table_headers (one MPT row) + mmt_probe peel"
run_phase "ZC" "${port_zc}" "${tmpdir}/zc.out" "${tmpdir}/gw_zc.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 32:1:0
"${probe_bin}" verify \
    --file "${tmpdir}/zc.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 11 \
    --expect-mmt-si-message-byte-length 11 \
    --expect-mmt-si-message-byte-length 15 \
    --expect-mmt-si-message-byte-length 39 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expected-payloads "${payloads}"

zd_payloads="DEADBEEF,CAFEBABE,11223344,01020304"
saved_payloads_zd="${payloads}"
payloads="${zd_payloads}"

echo "[mmtp_word0_integ] phase ZD: signalling + PA table index + non-zero table_length (ingress = table body)"
run_phase "ZD" "${port_zd}" "${tmpdir}/zd.out" "${tmpdir}/gw_zd.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 32:1:4
"${probe_bin}" verify \
    --file "${tmpdir}/zd.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 11 \
    --expect-mmt-si-message-byte-length 11 \
    --expect-mmt-si-message-byte-length 11 \
    --expect-mmt-si-message-byte-length 11 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expected-payloads "${zd_payloads}"

payloads="${saved_payloads_zd}"

ze_payloads="DEADBEEFCAFEBABE,1122334455667788,0102030405060708,AABBCCDDEEFF0011"
saved_payloads_ze="${payloads}"
payloads="${ze_payloads}"

echo "[mmtp_word0_integ] phase ZE: signalling + PA table index + multi-table concatenated bodies (MPT 4B + PLT 4B)"
run_phase "ZE" "${port_ze}" "${tmpdir}/ze.out" "${tmpdir}/gw_ze.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 32:1:4 \
    --mmtp-si-pa-table-row 128:0:4
"${probe_bin}" verify \
    --file "${tmpdir}/ze.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 19 \
    --expect-mmt-si-message-byte-length 19 \
    --expect-mmt-si-message-byte-length 19 \
    --expect-mmt-si-message-byte-length 19 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 2 \
    --expect-mmt-si-pa-number-of-tables 2 \
    --expect-mmt-si-pa-number-of-tables 2 \
    --expect-mmt-si-pa-number-of-tables 2 \
    --expected-payloads "${ze_payloads}"

payloads="${saved_payloads_ze}"

zf_payloads="DEADBEEF102030,CAFEBABE112233,01020304050607,AABBCCDDEEFF00"
saved_payloads_zf="${payloads}"
payloads="${zf_payloads}"

echo "[mmtp_word0_integ] phase ZF: signalling + PA index + mixed table_length (MPT 4B body + PLT len 0) + SI tail"
run_phase "ZF" "${port_zf}" "${tmpdir}/zf.out" "${tmpdir}/gw_zf.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 32:1:4 \
    --mmtp-si-pa-table-row 128:0:0
"${probe_bin}" verify \
    --file "${tmpdir}/zf.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 18 \
    --expect-mmt-si-message-byte-length 18 \
    --expect-mmt-si-message-byte-length 18 \
    --expect-mmt-si-message-byte-length 18 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 2 \
    --expect-mmt-si-pa-number-of-tables 2 \
    --expect-mmt-si-pa-number-of-tables 2 \
    --expect-mmt-si-pa-number-of-tables 2 \
    --expected-payloads "${zf_payloads}"

payloads="${saved_payloads_zf}"

zg_payloads="200100050000000000,200100050000000000,200100050000000000,200100050000000000"
saved_payloads_zg="${payloads}"
payloads="${zg_payloads}"

echo "[mmtp_word0_integ] phase ZG: signalling + PA + mmt_si_mpt_table body (minimal MPT, table_id 0x20)"
run_phase "ZG" "${port_zg}" "${tmpdir}/zg.out" "${tmpdir}/gw_zg.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 32:1:9 \
    --validate-mmt-si-mpt-table-body
"${probe_bin}" verify \
    --file "${tmpdir}/zg.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 16 \
    --expect-mmt-si-message-byte-length 16 \
    --expect-mmt-si-message-byte-length 16 \
    --expect-mmt-si-message-byte-length 16 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-length 5 \
    --expect-mmt-si-mpt-table-length 5 \
    --expect-mmt-si-mpt-table-length 5 \
    --expect-mmt-si-mpt-table-length 5 \
    --expected-payloads "${zg_payloads}"

payloads="${saved_payloads_zg}"

zh_payloads="800000020000,800000020000,800000020000,800000020000"
saved_payloads_zh="${payloads}"
payloads="${zh_payloads}"

echo "[mmtp_word0_integ] phase ZH: signalling + PA + mmt_si_plt_table body (minimal PLT, table_id 0x80)"
run_phase "ZH" "${port_zh}" "${tmpdir}/zh.out" "${tmpdir}/gw_zh.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 128:0:6 \
    --validate-mmt-si-plt-table-body
"${probe_bin}" verify \
    --file "${tmpdir}/zh.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 13 \
    --expect-mmt-si-message-byte-length 13 \
    --expect-mmt-si-message-byte-length 13 \
    --expect-mmt-si-message-byte-length 13 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-length 2 \
    --expect-mmt-si-plt-table-length 2 \
    --expect-mmt-si-plt-table-length 2 \
    --expect-mmt-si-plt-table-length 2 \
    --expected-payloads "${zh_payloads}"

payloads="${saved_payloads_zh}"

payloads="${zg_payloads}"

echo "[mmtp_word0_integ] phase ZI: ZG + mmt_si_mpt_table_body_prefix (minimal MPT inner parse)"
run_phase "ZI" "${port_zi}" "${tmpdir}/zi.out" "${tmpdir}/gw_zi.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 32:1:9 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-table-body-prefix
"${probe_bin}" verify \
    --file "${tmpdir}/zi.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 16 \
    --expect-mmt-si-message-byte-length 16 \
    --expect-mmt-si-message-byte-length 16 \
    --expect-mmt-si-message-byte-length 16 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-length 5 \
    --expect-mmt-si-mpt-table-length 5 \
    --expect-mmt-si-mpt-table-length 5 \
    --expect-mmt-si-mpt-table-length 5 \
    --expect-mmt-si-mpt-table-body-num-assets 0 \
    --expect-mmt-si-mpt-table-body-num-assets 0 \
    --expect-mmt-si-mpt-table-body-num-assets 0 \
    --expect-mmt-si-mpt-table-body-num-assets 0 \
    --expected-payloads "${zg_payloads}"

payloads="${zh_payloads}"

echo "[mmtp_word0_integ] phase ZJ: ZH + mmt_si_plt_table_body_prefix (minimal PLT inner parse)"
run_phase "ZJ" "${port_zj}" "${tmpdir}/zj.out" "${tmpdir}/gw_zj.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 128:0:6 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-table-body-prefix
"${probe_bin}" verify \
    --file "${tmpdir}/zj.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 13 \
    --expect-mmt-si-message-byte-length 13 \
    --expect-mmt-si-message-byte-length 13 \
    --expect-mmt-si-message-byte-length 13 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-length 2 \
    --expect-mmt-si-plt-table-length 2 \
    --expect-mmt-si-plt-table-length 2 \
    --expect-mmt-si-plt-table-length 2 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expected-payloads "${zh_payloads}"

zk_payloads="2001001300000000010000000000000000000000000000,2001001300000000010000000000000000000000000000,2001001300000000010000000000000000000000000000,2001001300000000010000000000000000000000000000"
saved_payloads_zk="${payloads}"
payloads="${zk_payloads}"

echo "[mmtp_word0_integ] phase ZK: ZG + mmt_si_mpt_asset (one zero-id asset, table_length 19)"
run_phase "ZK" "${port_zk}" "${tmpdir}/zk.out" "${tmpdir}/gw_zk.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 32:1:23 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset
"${probe_bin}" verify \
    --file "${tmpdir}/zk.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 30 \
    --expect-mmt-si-message-byte-length 30 \
    --expect-mmt-si-message-byte-length 30 \
    --expect-mmt-si-message-byte-length 30 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-length 19 \
    --expect-mmt-si-mpt-table-length 19 \
    --expect-mmt-si-mpt-table-length 19 \
    --expect-mmt-si-mpt-table-length 19 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expected-payloads "${zk_payloads}"

payloads="${saved_payloads_zk}"

zl_payloads="80000009000100000000000000,80000009000100000000000000,80000009000100000000000000,80000009000100000000000000"
saved_payloads_zl="${payloads}"
payloads="${zl_payloads}"

echo "[mmtp_word0_integ] phase ZL: ZH + mmt_si_plt_delivery_info (one location_type 0 DeliveryInfo, table_length 9)"
run_phase "ZL" "${port_zl}" "${tmpdir}/zl.out" "${tmpdir}/gw_zl.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 128:0:13 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-delivery-info
"${probe_bin}" verify \
    --file "${tmpdir}/zl.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 20 \
    --expect-mmt-si-message-byte-length 20 \
    --expect-mmt-si-message-byte-length 20 \
    --expect-mmt-si-message-byte-length 20 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-length 9 \
    --expect-mmt-si-plt-table-length 9 \
    --expect-mmt-si-plt-table-length 9 \
    --expect-mmt-si-plt-table-length 9 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-delivery-info-location-type 0 \
    --expect-mmt-si-plt-delivery-info-location-type 0 \
    --expect-mmt-si-plt-delivery-info-location-type 0 \
    --expect-mmt-si-plt-delivery-info-location-type 0 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expected-payloads "${zl_payloads}"

payloads="${saved_payloads_zl}"

zm_payloads="8000001300010000000001000000000000000000000000,8000001300010000000001000000000000000000000000,8000001300010000000001000000000000000000000000,8000001300010000000001000000000000000000000000"
saved_payloads_zm="${payloads}"
payloads="${zm_payloads}"

echo "[mmtp_word0_integ] phase ZM: ZH + mmt_si_plt_delivery_info_ipv4 (one IPv4 DeliveryInfo, table_length 19)"
run_phase "ZM" "${port_zm}" "${tmpdir}/zm.out" "${tmpdir}/gw_zm.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 128:0:23 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-delivery-info-ipv4
"${probe_bin}" verify \
    --file "${tmpdir}/zm.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 30 \
    --expect-mmt-si-message-byte-length 30 \
    --expect-mmt-si-message-byte-length 30 \
    --expect-mmt-si-message-byte-length 30 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-length 19 \
    --expect-mmt-si-plt-table-length 19 \
    --expect-mmt-si-plt-table-length 19 \
    --expect-mmt-si-plt-table-length 19 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-delivery-info-location-type 1 \
    --expect-mmt-si-plt-delivery-info-location-type 1 \
    --expect-mmt-si-plt-delivery-info-location-type 1 \
    --expect-mmt-si-plt-delivery-info-location-type 1 \
    --expect-mmt-si-plt-delivery-info-ipv4-dst-port 0 \
    --expect-mmt-si-plt-delivery-info-ipv4-dst-port 0 \
    --expect-mmt-si-plt-delivery-info-ipv4-dst-port 0 \
    --expect-mmt-si-plt-delivery-info-ipv4-dst-port 0 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expected-payloads "${zm_payloads}"

payloads="${saved_payloads_zm}"

zn_payload="8000002b00010000000002000000000000000000000000000000000000000000000000000000000000000000000000"
zn_payloads="${zn_payload},${zn_payload},${zn_payload},${zn_payload}"
saved_payloads_zn="${payloads}"
payloads="${zn_payloads}"

echo "[mmtp_word0_integ] phase ZN: ZH + mmt_si_plt_delivery_info_ipv6 (one IPv6 DeliveryInfo, table_length 43)"
run_phase "ZN" "${port_zn}" "${tmpdir}/zn.out" "${tmpdir}/gw_zn.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 128:0:47 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-delivery-info-ipv6
"${probe_bin}" verify \
    --file "${tmpdir}/zn.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 54 \
    --expect-mmt-si-message-byte-length 54 \
    --expect-mmt-si-message-byte-length 54 \
    --expect-mmt-si-message-byte-length 54 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-length 43 \
    --expect-mmt-si-plt-table-length 43 \
    --expect-mmt-si-plt-table-length 43 \
    --expect-mmt-si-plt-table-length 43 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-delivery-info-location-type 2 \
    --expect-mmt-si-plt-delivery-info-location-type 2 \
    --expect-mmt-si-plt-delivery-info-location-type 2 \
    --expect-mmt-si-plt-delivery-info-location-type 2 \
    --expect-mmt-si-plt-delivery-info-ipv6-dst-port 0 \
    --expect-mmt-si-plt-delivery-info-ipv6-dst-port 0 \
    --expect-mmt-si-plt-delivery-info-ipv6-dst-port 0 \
    --expect-mmt-si-plt-delivery-info-ipv6-dst-port 0 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expected-payloads "${zn_payloads}"

payloads="${saved_payloads_zn}"

zo_payload="8000000a00010000000005000000"
zo_payloads="${zo_payload},${zo_payload},${zo_payload},${zo_payload}"
saved_payloads_zo="${payloads}"
payloads="${zo_payloads}"

echo "[mmtp_word0_integ] phase ZO: ZH + mmt_si_plt_delivery_info_url (one URL DeliveryInfo, table_length 10)"
run_phase "ZO" "${port_zo}" "${tmpdir}/zo.out" "${tmpdir}/gw_zo.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 128:0:14 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-delivery-info-url
"${probe_bin}" verify \
    --file "${tmpdir}/zo.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 21 \
    --expect-mmt-si-message-byte-length 21 \
    --expect-mmt-si-message-byte-length 21 \
    --expect-mmt-si-message-byte-length 21 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-length 10 \
    --expect-mmt-si-plt-table-length 10 \
    --expect-mmt-si-plt-table-length 10 \
    --expect-mmt-si-plt-table-length 10 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-delivery-info-location-type 5 \
    --expect-mmt-si-plt-delivery-info-location-type 5 \
    --expect-mmt-si-plt-delivery-info-location-type 5 \
    --expect-mmt-si-plt-delivery-info-location-type 5 \
    --expect-mmt-si-plt-delivery-info-url-length 0 \
    --expect-mmt-si-plt-delivery-info-url-length 0 \
    --expect-mmt-si-plt-delivery-info-url-length 0 \
    --expect-mmt-si-plt-delivery-info-url-length 0 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expected-payloads "${zo_payloads}"

payloads="${saved_payloads_zo}"

zp_payload="80000006010000000000"
zp_payloads="${zp_payload},${zp_payload},${zp_payload},${zp_payload}"
saved_payloads_zp="${payloads}"
payloads="${zp_payloads}"

echo "[mmtp_word0_integ] phase ZP: ZH + mmt_si_plt_package_entry (one zero-id package, table_length 6)"
run_phase "ZP" "${port_zp}" "${tmpdir}/zp.out" "${tmpdir}/gw_zp.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 128:0:10 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-package-entry
"${probe_bin}" verify \
    --file "${tmpdir}/zp.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 17 \
    --expect-mmt-si-message-byte-length 17 \
    --expect-mmt-si-message-byte-length 17 \
    --expect-mmt-si-message-byte-length 17 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-length 6 \
    --expect-mmt-si-plt-table-length 6 \
    --expect-mmt-si-plt-table-length 6 \
    --expect-mmt-si-plt-table-length 6 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-package-id-length 0 \
    --expect-mmt-si-plt-package-id-length 0 \
    --expect-mmt-si-plt-package-id-length 0 \
    --expect-mmt-si-plt-package-id-length 0 \
    --expect-mmt-si-plt-package-location-type 0 \
    --expect-mmt-si-plt-package-location-type 0 \
    --expect-mmt-si-plt-package-location-type 0 \
    --expect-mmt-si-plt-package-location-type 0 \
    --expect-mmt-si-plt-package-packet-id 0 \
    --expect-mmt-si-plt-package-packet-id 0 \
    --expect-mmt-si-plt-package-packet-id 0 \
    --expect-mmt-si-plt-package-packet-id 0 \
    --expected-payloads "${zp_payloads}"

payloads="${saved_payloads_zp}"

zq_payload="8000000d00010000000005036c61620000"
zq_payloads="${zq_payload},${zq_payload},${zq_payload},${zq_payload}"
saved_payloads_zq="${payloads}"
payloads="${zq_payloads}"

echo "[mmtp_word0_integ] phase ZQ: ZH + mmt_si_plt_delivery_info_url_3 (one URL DeliveryInfo, table_length 13)"
run_phase "ZQ" "${port_zq}" "${tmpdir}/zq.out" "${tmpdir}/gw_zq.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 128:0:17 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-delivery-info-url-3
"${probe_bin}" verify \
    --file "${tmpdir}/zq.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 24 \
    --expect-mmt-si-message-byte-length 24 \
    --expect-mmt-si-message-byte-length 24 \
    --expect-mmt-si-message-byte-length 24 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-length 13 \
    --expect-mmt-si-plt-table-length 13 \
    --expect-mmt-si-plt-table-length 13 \
    --expect-mmt-si-plt-table-length 13 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-delivery-info-location-type 5 \
    --expect-mmt-si-plt-delivery-info-location-type 5 \
    --expect-mmt-si-plt-delivery-info-location-type 5 \
    --expect-mmt-si-plt-delivery-info-location-type 5 \
    --expect-mmt-si-plt-delivery-info-url-length 3 \
    --expect-mmt-si-plt-delivery-info-url-length 3 \
    --expect-mmt-si-plt-delivery-info-url-length 3 \
    --expect-mmt-si-plt-delivery-info-url-length 3 \
    --expect-mmt-si-plt-delivery-info-url-3-byte0 108 \
    --expect-mmt-si-plt-delivery-info-url-3-byte0 108 \
    --expect-mmt-si-plt-delivery-info-url-3-byte0 108 \
    --expect-mmt-si-plt-delivery-info-url-3-byte0 108 \
    --expect-mmt-si-plt-delivery-info-url-3-byte1 97 \
    --expect-mmt-si-plt-delivery-info-url-3-byte1 97 \
    --expect-mmt-si-plt-delivery-info-url-3-byte1 97 \
    --expect-mmt-si-plt-delivery-info-url-3-byte1 97 \
    --expect-mmt-si-plt-delivery-info-url-3-byte2 98 \
    --expect-mmt-si-plt-delivery-info-url-3-byte2 98 \
    --expect-mmt-si-plt-delivery-info-url-3-byte2 98 \
    --expect-mmt-si-plt-delivery-info-url-3-byte2 98 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expected-payloads "${zq_payloads}"

payloads="${saved_payloads_zq}"

zr_payload="8000000701000101000000"
zr_payloads="${zr_payload},${zr_payload},${zr_payload},${zr_payload}"
saved_payloads_zr="${payloads}"
payloads="${zr_payloads}"

echo "[mmtp_word0_integ] phase ZR: ZH + mmt_si_plt_package_entry_id8 (one-byte package id, table_length 7)"
run_phase "ZR" "${port_zr}" "${tmpdir}/zr.out" "${tmpdir}/gw_zr.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 128:0:11 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-package-entry-id8
"${probe_bin}" verify \
    --file "${tmpdir}/zr.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 18 \
    --expect-mmt-si-message-byte-length 18 \
    --expect-mmt-si-message-byte-length 18 \
    --expect-mmt-si-message-byte-length 18 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-length 7 \
    --expect-mmt-si-plt-table-length 7 \
    --expect-mmt-si-plt-table-length 7 \
    --expect-mmt-si-plt-table-length 7 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-package-id-length 1 \
    --expect-mmt-si-plt-package-id-length 1 \
    --expect-mmt-si-plt-package-id-length 1 \
    --expect-mmt-si-plt-package-id-length 1 \
    --expect-mmt-si-plt-package-mmt-package-id 1 \
    --expect-mmt-si-plt-package-mmt-package-id 1 \
    --expect-mmt-si-plt-package-mmt-package-id 1 \
    --expect-mmt-si-plt-package-mmt-package-id 1 \
    --expect-mmt-si-plt-package-location-type 0 \
    --expect-mmt-si-plt-package-location-type 0 \
    --expect-mmt-si-plt-package-location-type 0 \
    --expect-mmt-si-plt-package-location-type 0 \
    --expect-mmt-si-plt-package-packet-id 0 \
    --expect-mmt-si-plt-package-packet-id 0 \
    --expect-mmt-si-plt-package-packet-id 0 \
    --expect-mmt-si-plt-package-packet-id 0 \
    --expected-payloads "${zr_payloads}"

payloads="${saved_payloads_zr}"

zs_payload="200100140000000001000000000001010000000000000000"
zs_payloads="${zs_payload},${zs_payload},${zs_payload},${zs_payload}"
saved_payloads_zs="${payloads}"
payloads="${zs_payloads}"

echo "[mmtp_word0_integ] phase ZS: ZG + mmt_si_mpt_asset_id8 (one-byte asset id, table_length 20)"
run_phase "ZS" "${port_zs}" "${tmpdir}/zs.out" "${tmpdir}/gw_zs.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 32:1:24 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id8
"${probe_bin}" verify \
    --file "${tmpdir}/zs.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 31 \
    --expect-mmt-si-message-byte-length 31 \
    --expect-mmt-si-message-byte-length 31 \
    --expect-mmt-si-message-byte-length 31 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-length 20 \
    --expect-mmt-si-mpt-table-length 20 \
    --expect-mmt-si-mpt-table-length 20 \
    --expect-mmt-si-mpt-table-length 20 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-asset-id-length 1 \
    --expect-mmt-si-mpt-asset-id-length 1 \
    --expect-mmt-si-mpt-asset-id-length 1 \
    --expect-mmt-si-mpt-asset-id-length 1 \
    --expect-mmt-si-mpt-asset-asset-id 1 \
    --expect-mmt-si-mpt-asset-asset-id 1 \
    --expect-mmt-si-mpt-asset-asset-id 1 \
    --expect-mmt-si-mpt-asset-asset-id 1 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expected-payloads "${zs_payloads}"

payloads="${saved_payloads_zs}"

zt_payload="2001001600000000010000000000000000000000010000000000"
zt_payloads="${zt_payload},${zt_payload},${zt_payload},${zt_payload}"
saved_payloads_zt="${payloads}"
payloads="${zt_payloads}"

echo "[mmtp_word0_integ] phase ZT: ZG + mmt_si_mpt_asset_location0 (same-flow location, table_length 22)"
run_phase "ZT" "${port_zt}" "${tmpdir}/zt.out" "${tmpdir}/gw_zt.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 32:1:26 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-location0
"${probe_bin}" verify \
    --file "${tmpdir}/zt.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 33 \
    --expect-mmt-si-message-byte-length 33 \
    --expect-mmt-si-message-byte-length 33 \
    --expect-mmt-si-message-byte-length 33 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-length 22 \
    --expect-mmt-si-mpt-table-length 22 \
    --expect-mmt-si-mpt-table-length 22 \
    --expect-mmt-si-mpt-table-length 22 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-type 0 \
    --expect-mmt-si-mpt-asset-location-type 0 \
    --expect-mmt-si-mpt-asset-location-type 0 \
    --expect-mmt-si-mpt-asset-location-type 0 \
    --expect-mmt-si-mpt-asset-packet-id 0 \
    --expect-mmt-si-mpt-asset-packet-id 0 \
    --expect-mmt-si-mpt-asset-packet-id 0 \
    --expect-mmt-si-mpt-asset-packet-id 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expected-payloads "${zt_payloads}"

payloads="${saved_payloads_zt}"

zu_payload="8000000e0100000100000000000000000000"
zu_payloads="${zu_payload},${zu_payload},${zu_payload},${zu_payload}"
saved_payloads_zu="${payloads}"
payloads="${zu_payloads}"

echo "[mmtp_word0_integ] phase ZU: ZH + mmt_si_plt_package_entry_ipv4 (IPv4 package location, table_length 14)"
run_phase "ZU" "${port_zu}" "${tmpdir}/zu.out" "${tmpdir}/gw_zu.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 128:0:18 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-package-entry-ipv4
"${probe_bin}" verify \
    --file "${tmpdir}/zu.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 25 \
    --expect-mmt-si-message-byte-length 25 \
    --expect-mmt-si-message-byte-length 25 \
    --expect-mmt-si-message-byte-length 25 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-length 14 \
    --expect-mmt-si-plt-table-length 14 \
    --expect-mmt-si-plt-table-length 14 \
    --expect-mmt-si-plt-table-length 14 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-package-id-length 0 \
    --expect-mmt-si-plt-package-id-length 0 \
    --expect-mmt-si-plt-package-id-length 0 \
    --expect-mmt-si-plt-package-id-length 0 \
    --expect-mmt-si-plt-package-location-type 1 \
    --expect-mmt-si-plt-package-location-type 1 \
    --expect-mmt-si-plt-package-location-type 1 \
    --expect-mmt-si-plt-package-location-type 1 \
    --expect-mmt-si-plt-package-ipv4-dst-port 0 \
    --expect-mmt-si-plt-package-ipv4-dst-port 0 \
    --expect-mmt-si-plt-package-ipv4-dst-port 0 \
    --expect-mmt-si-plt-package-ipv4-dst-port 0 \
    --expected-payloads "${zu_payloads}"

payloads="${saved_payloads_zu}"

zv_payload="2001001e000000000100000000000000000000000101000000000000000000000000"
zv_payloads="${zv_payload},${zv_payload},${zv_payload},${zv_payload}"
saved_payloads_zv="${payloads}"
payloads="${zv_payloads}"

echo "[mmtp_word0_integ] phase ZV: ZG + mmt_si_mpt_asset_location_ipv4 (IPv4 asset location, table_length 30)"
run_phase "ZV" "${port_zv}" "${tmpdir}/zv.out" "${tmpdir}/gw_zv.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 32:1:34 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-location-ipv4
"${probe_bin}" verify \
    --file "${tmpdir}/zv.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 41 \
    --expect-mmt-si-message-byte-length 41 \
    --expect-mmt-si-message-byte-length 41 \
    --expect-mmt-si-message-byte-length 41 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-length 30 \
    --expect-mmt-si-mpt-table-length 30 \
    --expect-mmt-si-mpt-table-length 30 \
    --expect-mmt-si-mpt-table-length 30 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expected-payloads "${zv_payloads}"

payloads="${saved_payloads_zv}"

zw_payload="2001001f00000000010000000000010100000000000101000000000000000000000000"
zw_payloads="${zw_payload},${zw_payload},${zw_payload},${zw_payload}"
saved_payloads_zw="${payloads}"
payloads="${zw_payloads}"

echo "[mmtp_word0_integ] phase ZW: ZG + mmt_si_mpt_asset_id8_location_ipv4 (1 B asset id + IPv4 location, table_length 31)"
run_phase "ZW" "${port_zw}" "${tmpdir}/zw.out" "${tmpdir}/gw_zw.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 32:1:35 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id8-location-ipv4
"${probe_bin}" verify \
    --file "${tmpdir}/zw.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 42 \
    --expect-mmt-si-message-byte-length 42 \
    --expect-mmt-si-message-byte-length 42 \
    --expect-mmt-si-message-byte-length 42 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-length 31 \
    --expect-mmt-si-mpt-table-length 31 \
    --expect-mmt-si-mpt-table-length 31 \
    --expect-mmt-si-mpt-table-length 31 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-asset-id-length 1 \
    --expect-mmt-si-mpt-asset-id-length 1 \
    --expect-mmt-si-mpt-asset-id-length 1 \
    --expect-mmt-si-mpt-asset-id-length 1 \
    --expect-mmt-si-mpt-asset-asset-id 1 \
    --expect-mmt-si-mpt-asset-asset-id 1 \
    --expect-mmt-si-mpt-asset-asset-id 1 \
    --expect-mmt-si-mpt-asset-asset-id 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expected-payloads "${zw_payloads}"

payloads="${saved_payloads_zw}"

zx_payload="8000000f010001010100000000000000000000"
zx_payloads="${zx_payload},${zx_payload},${zx_payload},${zx_payload}"
saved_payloads_zx="${payloads}"
payloads="${zx_payloads}"

echo "[mmtp_word0_integ] phase ZX: ZH + mmt_si_plt_package_entry_id8_location_ipv4 (1 B package id + IPv4 location, table_length 15)"
run_phase "ZX" "${port_zx}" "${tmpdir}/zx.out" "${tmpdir}/gw_zx.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 128:0:19 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-package-entry-id8-location-ipv4
"${probe_bin}" verify \
    --file "${tmpdir}/zx.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 26 \
    --expect-mmt-si-message-byte-length 26 \
    --expect-mmt-si-message-byte-length 26 \
    --expect-mmt-si-message-byte-length 26 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-length 15 \
    --expect-mmt-si-plt-table-length 15 \
    --expect-mmt-si-plt-table-length 15 \
    --expect-mmt-si-plt-table-length 15 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-package-id-length 1 \
    --expect-mmt-si-plt-package-id-length 1 \
    --expect-mmt-si-plt-package-id-length 1 \
    --expect-mmt-si-plt-package-id-length 1 \
    --expect-mmt-si-plt-package-mmt-package-id 1 \
    --expect-mmt-si-plt-package-mmt-package-id 1 \
    --expect-mmt-si-plt-package-mmt-package-id 1 \
    --expect-mmt-si-plt-package-mmt-package-id 1 \
    --expect-mmt-si-plt-package-location-type 1 \
    --expect-mmt-si-plt-package-location-type 1 \
    --expect-mmt-si-plt-package-location-type 1 \
    --expect-mmt-si-plt-package-location-type 1 \
    --expect-mmt-si-plt-package-ipv4-dst-port 0 \
    --expect-mmt-si-plt-package-ipv4-dst-port 0 \
    --expect-mmt-si-plt-package-ipv4-dst-port 0 \
    --expect-mmt-si-plt-package-ipv4-dst-port 0 \
    --expected-payloads "${zx_payloads}"

payloads="${saved_payloads_zx}"

zy_payload="20010036000000000100000000000000000000000102000000000000000000000000000000000000000000000000000000000000000000000000"
zy_payloads="${zy_payload},${zy_payload},${zy_payload},${zy_payload}"
saved_payloads_zy="${payloads}"
payloads="${zy_payloads}"

echo "[mmtp_word0_integ] phase ZY: ZG + mmt_si_mpt_asset_location_ipv6 (IPv6 asset location, table_length 54)"
run_phase "ZY" "${port_zy}" "${tmpdir}/zy.out" "${tmpdir}/gw_zy.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 32:1:58 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-location-ipv6
"${probe_bin}" verify \
    --file "${tmpdir}/zy.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 65 \
    --expect-mmt-si-message-byte-length 65 \
    --expect-mmt-si-message-byte-length 65 \
    --expect-mmt-si-message-byte-length 65 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-length 54 \
    --expect-mmt-si-mpt-table-length 54 \
    --expect-mmt-si-mpt-table-length 54 \
    --expect-mmt-si-mpt-table-length 54 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expected-payloads "${zy_payloads}"

payloads="${saved_payloads_zy}"

zz_payload="800000260100000200000000000000000000000000000000000000000000000000000000000000000000"
zz_payloads="${zz_payload},${zz_payload},${zz_payload},${zz_payload}"
saved_payloads_zz="${payloads}"
payloads="${zz_payloads}"

echo "[mmtp_word0_integ] phase ZZ: ZH + mmt_si_plt_package_entry_ipv6 (IPv6 package location, table_length 38)"
run_phase "ZZ" "${port_zz}" "${tmpdir}/zz.out" "${tmpdir}/gw_zz.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 128:0:42 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-package-entry-ipv6
"${probe_bin}" verify \
    --file "${tmpdir}/zz.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 49 \
    --expect-mmt-si-message-byte-length 49 \
    --expect-mmt-si-message-byte-length 49 \
    --expect-mmt-si-message-byte-length 49 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-length 38 \
    --expect-mmt-si-plt-table-length 38 \
    --expect-mmt-si-plt-table-length 38 \
    --expect-mmt-si-plt-table-length 38 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-package-id-length 0 \
    --expect-mmt-si-plt-package-id-length 0 \
    --expect-mmt-si-plt-package-id-length 0 \
    --expect-mmt-si-plt-package-id-length 0 \
    --expect-mmt-si-plt-package-location-type 2 \
    --expect-mmt-si-plt-package-location-type 2 \
    --expect-mmt-si-plt-package-location-type 2 \
    --expect-mmt-si-plt-package-location-type 2 \
    --expect-mmt-si-plt-package-ipv6-dst-port 0 \
    --expect-mmt-si-plt-package-ipv6-dst-port 0 \
    --expect-mmt-si-plt-package-ipv6-dst-port 0 \
    --expect-mmt-si-plt-package-ipv6-dst-port 0 \
    --expected-payloads "${zz_payloads}"

payloads="${saved_payloads_zz}"

aaa_payload="2001003700000000010000000000010100000000000102000000000000000000000000000000000000000000000000000000000000000000000000"
aaa_payloads="${aaa_payload},${aaa_payload},${aaa_payload},${aaa_payload}"
saved_payloads_aaa="${payloads}"
payloads="${aaa_payloads}"

echo "[mmtp_word0_integ] phase AAA: ZG + mmt_si_mpt_asset_id8_location_ipv6 (1 B asset id + IPv6 location, table_length 55)"
run_phase "AAA" "${port_aaa}" "${tmpdir}/aaa.out" "${tmpdir}/gw_aaa.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 32:1:59 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id8-location-ipv6
"${probe_bin}" verify \
    --file "${tmpdir}/aaa.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 66 \
    --expect-mmt-si-message-byte-length 66 \
    --expect-mmt-si-message-byte-length 66 \
    --expect-mmt-si-message-byte-length 66 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-length 55 \
    --expect-mmt-si-mpt-table-length 55 \
    --expect-mmt-si-mpt-table-length 55 \
    --expect-mmt-si-mpt-table-length 55 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-asset-id-length 1 \
    --expect-mmt-si-mpt-asset-id-length 1 \
    --expect-mmt-si-mpt-asset-id-length 1 \
    --expect-mmt-si-mpt-asset-id-length 1 \
    --expect-mmt-si-mpt-asset-asset-id 1 \
    --expect-mmt-si-mpt-asset-asset-id 1 \
    --expect-mmt-si-mpt-asset-asset-id 1 \
    --expect-mmt-si-mpt-asset-asset-id 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expected-payloads "${aaa_payloads}"

payloads="${saved_payloads_aaa}"

aab_payload="80000027010001010200000000000000000000000000000000000000000000000000000000000000000000"
aab_payloads="${aab_payload},${aab_payload},${aab_payload},${aab_payload}"
saved_payloads_aab="${payloads}"
payloads="${aab_payloads}"

echo "[mmtp_word0_integ] phase AAB: ZH + mmt_si_plt_package_entry_id8_location_ipv6 (1 B package id + IPv6 location, table_length 39)"
run_phase "AAB" "${port_aab}" "${tmpdir}/aab.out" "${tmpdir}/gw_aab.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 128:0:43 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-package-entry-id8-location-ipv6
"${probe_bin}" verify \
    --file "${tmpdir}/aab.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 50 \
    --expect-mmt-si-message-byte-length 50 \
    --expect-mmt-si-message-byte-length 50 \
    --expect-mmt-si-message-byte-length 50 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-length 39 \
    --expect-mmt-si-plt-table-length 39 \
    --expect-mmt-si-plt-table-length 39 \
    --expect-mmt-si-plt-table-length 39 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-package-id-length 1 \
    --expect-mmt-si-plt-package-id-length 1 \
    --expect-mmt-si-plt-package-id-length 1 \
    --expect-mmt-si-plt-package-id-length 1 \
    --expect-mmt-si-plt-package-mmt-package-id 1 \
    --expect-mmt-si-plt-package-mmt-package-id 1 \
    --expect-mmt-si-plt-package-mmt-package-id 1 \
    --expect-mmt-si-plt-package-mmt-package-id 1 \
    --expect-mmt-si-plt-package-location-type 2 \
    --expect-mmt-si-plt-package-location-type 2 \
    --expect-mmt-si-plt-package-location-type 2 \
    --expect-mmt-si-plt-package-location-type 2 \
    --expect-mmt-si-plt-package-ipv6-dst-port 0 \
    --expect-mmt-si-plt-package-ipv6-dst-port 0 \
    --expect-mmt-si-plt-package-ipv6-dst-port 0 \
    --expect-mmt-si-plt-package-ipv6-dst-port 0 \
    --expected-payloads "${aab_payloads}"

payloads="${saved_payloads_aab}"

aac_payload="2001001700000000010000000000000000000000000004DEADBEEF"
aac_payloads="${aac_payload},${aac_payload},${aac_payload},${aac_payload}"
saved_payloads_aac="${payloads}"
payloads="${aac_payloads}"

echo "[mmtp_word0_integ] phase AAC: ZG + mmt_si_mpt_asset_descriptors4 (4 B asset descriptors, table_length 23)"
run_phase "AAC" "${port_aac}" "${tmpdir}/aac.out" "${tmpdir}/gw_aac.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 32:1:27 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-descriptors4
"${probe_bin}" verify \
    --file "${tmpdir}/aac.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 34 \
    --expect-mmt-si-message-byte-length 34 \
    --expect-mmt-si-message-byte-length 34 \
    --expect-mmt-si-message-byte-length 34 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-length 23 \
    --expect-mmt-si-mpt-table-length 23 \
    --expect-mmt-si-mpt-table-length 23 \
    --expect-mmt-si-mpt-table-length 23 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 4 \
    --expect-mmt-si-mpt-asset-descriptors-length 4 \
    --expect-mmt-si-mpt-asset-descriptors-length 4 \
    --expect-mmt-si-mpt-asset-descriptors-length 4 \
    --expected-payloads "${aac_payloads}"

payloads="${saved_payloads_aac}"

aad_payload="8000000e0001000000000504687474700000"
aad_payloads="${aad_payload},${aad_payload},${aad_payload},${aad_payload}"
saved_payloads_aad="${payloads}"
payloads="${aad_payloads}"

echo "[mmtp_word0_integ] phase AAD: ZH + mmt_si_plt_delivery_info_url_4 (4 B URL http, table_length 14)"
run_phase "AAD" "${port_aad}" "${tmpdir}/aad.out" "${tmpdir}/gw_aad.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 128:0:18 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-delivery-info-url-4
"${probe_bin}" verify \
    --file "${tmpdir}/aad.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 25 \
    --expect-mmt-si-message-byte-length 25 \
    --expect-mmt-si-message-byte-length 25 \
    --expect-mmt-si-message-byte-length 25 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-length 14 \
    --expect-mmt-si-plt-table-length 14 \
    --expect-mmt-si-plt-table-length 14 \
    --expect-mmt-si-plt-table-length 14 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-delivery-info-location-type 5 \
    --expect-mmt-si-plt-delivery-info-location-type 5 \
    --expect-mmt-si-plt-delivery-info-location-type 5 \
    --expect-mmt-si-plt-delivery-info-location-type 5 \
    --expect-mmt-si-plt-delivery-info-url-length 4 \
    --expect-mmt-si-plt-delivery-info-url-length 4 \
    --expect-mmt-si-plt-delivery-info-url-length 4 \
    --expect-mmt-si-plt-delivery-info-url-length 4 \
    --expect-mmt-si-plt-delivery-info-url-4-byte0 104 \
    --expect-mmt-si-plt-delivery-info-url-4-byte0 104 \
    --expect-mmt-si-plt-delivery-info-url-4-byte0 104 \
    --expect-mmt-si-plt-delivery-info-url-4-byte0 104 \
    --expect-mmt-si-plt-delivery-info-url-4-byte1 116 \
    --expect-mmt-si-plt-delivery-info-url-4-byte1 116 \
    --expect-mmt-si-plt-delivery-info-url-4-byte1 116 \
    --expect-mmt-si-plt-delivery-info-url-4-byte1 116 \
    --expect-mmt-si-plt-delivery-info-url-4-byte2 116 \
    --expect-mmt-si-plt-delivery-info-url-4-byte2 116 \
    --expect-mmt-si-plt-delivery-info-url-4-byte2 116 \
    --expect-mmt-si-plt-delivery-info-url-4-byte2 116 \
    --expect-mmt-si-plt-delivery-info-url-4-byte3 112 \
    --expect-mmt-si-plt-delivery-info-url-4-byte3 112 \
    --expect-mmt-si-plt-delivery-info-url-4-byte3 112 \
    --expect-mmt-si-plt-delivery-info-url-4-byte3 112 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expected-payloads "${aad_payloads}"

payloads="${saved_payloads_aad}"

aae_payload="80000013000100000000010a000001e000000113880000"
aae_payloads="${aae_payload},${aae_payload},${aae_payload},${aae_payload}"
saved_payloads_aae="${payloads}"
payloads="${aae_payloads}"

echo "[mmtp_word0_integ] phase AAE: ZM + mmt_si_plt_delivery_info_ipv4_nz (10.0.0.1 -> 224.0.0.1:5000, table_length 19)"
run_phase "AAE" "${port_aae}" "${tmpdir}/aae.out" "${tmpdir}/gw_aae.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 128:0:23 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-delivery-info-ipv4-nz
"${probe_bin}" verify \
    --file "${tmpdir}/aae.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 30 \
    --expect-mmt-si-message-byte-length 30 \
    --expect-mmt-si-message-byte-length 30 \
    --expect-mmt-si-message-byte-length 30 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-length 19 \
    --expect-mmt-si-plt-table-length 19 \
    --expect-mmt-si-plt-table-length 19 \
    --expect-mmt-si-plt-table-length 19 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-packages 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 1 \
    --expect-mmt-si-plt-delivery-info-location-type 1 \
    --expect-mmt-si-plt-delivery-info-location-type 1 \
    --expect-mmt-si-plt-delivery-info-location-type 1 \
    --expect-mmt-si-plt-delivery-info-location-type 1 \
    --expect-mmt-si-plt-delivery-info-ipv4-src-addr 167772161 \
    --expect-mmt-si-plt-delivery-info-ipv4-src-addr 167772161 \
    --expect-mmt-si-plt-delivery-info-ipv4-src-addr 167772161 \
    --expect-mmt-si-plt-delivery-info-ipv4-src-addr 167772161 \
    --expect-mmt-si-plt-delivery-info-ipv4-dst-addr 3758096385 \
    --expect-mmt-si-plt-delivery-info-ipv4-dst-addr 3758096385 \
    --expect-mmt-si-plt-delivery-info-ipv4-dst-addr 3758096385 \
    --expect-mmt-si-plt-delivery-info-ipv4-dst-addr 3758096385 \
    --expect-mmt-si-plt-delivery-info-ipv4-dst-port 5000 \
    --expect-mmt-si-plt-delivery-info-ipv4-dst-port 5000 \
    --expect-mmt-si-plt-delivery-info-ipv4-dst-port 5000 \
    --expect-mmt-si-plt-delivery-info-ipv4-dst-port 5000 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expect-mmt-si-plt-delivery-info-descriptor-loop-length 0 \
    --expected-payloads "${aae_payloads}"

payloads="${saved_payloads_aae}"

aaf_payload="2001001e0000000001000000000000000000000001010a000001e000000113880000"
aaf_payloads="${aaf_payload},${aaf_payload},${aaf_payload},${aaf_payload}"
saved_payloads_aaf="${payloads}"
payloads="${aaf_payloads}"

echo "[mmtp_word0_integ] phase AAF: ZV + mmt_si_mpt_asset_location_ipv4_nz (10.0.0.1 -> 224.0.0.1:5000, table_length 30)"
run_phase "AAF" "${port_aaf}" "${tmpdir}/aaf.out" "${tmpdir}/gw_aaf.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 32:1:34 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-location-ipv4-nz
"${probe_bin}" verify \
    --file "${tmpdir}/aaf.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 41 \
    --expect-mmt-si-message-byte-length 41 \
    --expect-mmt-si-message-byte-length 41 \
    --expect-mmt-si-message-byte-length 41 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-length 30 \
    --expect-mmt-si-mpt-table-length 30 \
    --expect-mmt-si-mpt-table-length 30 \
    --expect-mmt-si-mpt-table-length 30 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-ipv4-src-addr 167772161 \
    --expect-mmt-si-mpt-asset-ipv4-src-addr 167772161 \
    --expect-mmt-si-mpt-asset-ipv4-src-addr 167772161 \
    --expect-mmt-si-mpt-asset-ipv4-src-addr 167772161 \
    --expect-mmt-si-mpt-asset-ipv4-dst-addr 3758096385 \
    --expect-mmt-si-mpt-asset-ipv4-dst-addr 3758096385 \
    --expect-mmt-si-mpt-asset-ipv4-dst-addr 3758096385 \
    --expect-mmt-si-mpt-asset-ipv4-dst-addr 3758096385 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 5000 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 5000 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 5000 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 5000 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expected-payloads "${aaf_payloads}"

payloads="${saved_payloads_aaf}"

aag_payload="20010015000000000100000000000201020000000000000000"
aag_payloads="${aag_payload},${aag_payload},${aag_payload},${aag_payload}"
saved_payloads_aag="${payloads}"
payloads="${aag_payloads}"

echo "[mmtp_word0_integ] phase AAG: ZS + mmt_si_mpt_asset_id16 (2 B asset_id 01 02, table_length 21)"
run_phase "AAG" "${port_aag}" "${tmpdir}/aag.out" "${tmpdir}/gw_aag.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 32:1:25 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id16
"${probe_bin}" verify \
    --file "${tmpdir}/aag.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 32 \
    --expect-mmt-si-message-byte-length 32 \
    --expect-mmt-si-message-byte-length 32 \
    --expect-mmt-si-message-byte-length 32 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-length 21 \
    --expect-mmt-si-mpt-table-length 21 \
    --expect-mmt-si-mpt-table-length 21 \
    --expect-mmt-si-mpt-table-length 21 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-asset-id-length 2 \
    --expect-mmt-si-mpt-asset-id-length 2 \
    --expect-mmt-si-mpt-asset-id-length 2 \
    --expect-mmt-si-mpt-asset-id-length 2 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expected-payloads "${aag_payloads}"

payloads="${saved_payloads_aag}"

aah_payload="2001003600000000010000000000000000000000010200000000000000000000ffff0a00000100000000000000000000ffffe000000113880000"
aah_payloads="${aah_payload},${aah_payload},${aah_payload},${aah_payload}"
saved_payloads_aah="${payloads}"
payloads="${aah_payloads}"

echo "[mmtp_word0_integ] phase AAH: ZY + mmt_si_mpt_asset_location_ipv6_nz (::ffff:10.0.0.1 -> ::ffff:224.0.0.1:5000, table_length 54)"
run_phase "AAH" "${port_aah}" "${tmpdir}/aah.out" "${tmpdir}/gw_aah.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 32:1:58 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-location-ipv6-nz
"${probe_bin}" verify \
    --file "${tmpdir}/aah.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 65 \
    --expect-mmt-si-message-byte-length 65 \
    --expect-mmt-si-message-byte-length 65 \
    --expect-mmt-si-message-byte-length 65 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-length 54 \
    --expect-mmt-si-mpt-table-length 54 \
    --expect-mmt-si-mpt-table-length 54 \
    --expect-mmt-si-mpt-table-length 54 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-id-length 0 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-ipv6-src-addr-3 167772161 \
    --expect-mmt-si-mpt-asset-ipv6-src-addr-3 167772161 \
    --expect-mmt-si-mpt-asset-ipv6-src-addr-3 167772161 \
    --expect-mmt-si-mpt-asset-ipv6-src-addr-3 167772161 \
    --expect-mmt-si-mpt-asset-ipv6-dst-addr-3 3758096385 \
    --expect-mmt-si-mpt-asset-ipv6-dst-addr-3 3758096385 \
    --expect-mmt-si-mpt-asset-ipv6-dst-addr-3 3758096385 \
    --expect-mmt-si-mpt-asset-ipv6-dst-addr-3 3758096385 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 5000 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 5000 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 5000 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 5000 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expected-payloads "${aah_payloads}"

payloads="${saved_payloads_aah}"

aai_payload="8000000e010000010a000001e00000011388"
aai_payloads="${aai_payload},${aai_payload},${aai_payload},${aai_payload}"
saved_payloads_aai="${payloads}"
payloads="${aai_payloads}"

echo "[mmtp_word0_integ] phase AAI: ZU + mmt_si_plt_package_entry_ipv4_nz (10.0.0.1 -> 224.0.0.1:5000, table_length 14)"
run_phase "AAI" "${port_aai}" "${tmpdir}/aai.out" "${tmpdir}/gw_aai.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 128:0:18 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-package-entry-ipv4-nz
"${probe_bin}" verify \
    --file "${tmpdir}/aai.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 25 \
    --expect-mmt-si-message-byte-length 25 \
    --expect-mmt-si-message-byte-length 25 \
    --expect-mmt-si-message-byte-length 25 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-length 14 \
    --expect-mmt-si-plt-table-length 14 \
    --expect-mmt-si-plt-table-length 14 \
    --expect-mmt-si-plt-table-length 14 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-package-id-length 0 \
    --expect-mmt-si-plt-package-id-length 0 \
    --expect-mmt-si-plt-package-id-length 0 \
    --expect-mmt-si-plt-package-id-length 0 \
    --expect-mmt-si-plt-package-location-type 1 \
    --expect-mmt-si-plt-package-location-type 1 \
    --expect-mmt-si-plt-package-location-type 1 \
    --expect-mmt-si-plt-package-location-type 1 \
    --expect-mmt-si-plt-package-ipv4-src-addr 167772161 \
    --expect-mmt-si-plt-package-ipv4-src-addr 167772161 \
    --expect-mmt-si-plt-package-ipv4-src-addr 167772161 \
    --expect-mmt-si-plt-package-ipv4-src-addr 167772161 \
    --expect-mmt-si-plt-package-ipv4-dst-addr 3758096385 \
    --expect-mmt-si-plt-package-ipv4-dst-addr 3758096385 \
    --expect-mmt-si-plt-package-ipv4-dst-addr 3758096385 \
    --expect-mmt-si-plt-package-ipv4-dst-addr 3758096385 \
    --expect-mmt-si-plt-package-ipv4-dst-port 5000 \
    --expect-mmt-si-plt-package-ipv4-dst-port 5000 \
    --expect-mmt-si-plt-package-ipv4-dst-port 5000 \
    --expect-mmt-si-plt-package-ipv4-dst-port 5000 \
    --expected-payloads "${aai_payloads}"

payloads="${saved_payloads_aai}"

aaj_payload="800000260100000200000000000000000000ffff0a00000100000000000000000000ffffe00000011388"
aaj_payloads="${aaj_payload},${aaj_payload},${aaj_payload},${aaj_payload}"
saved_payloads_aaj="${payloads}"
payloads="${aaj_payloads}"

echo "[mmtp_word0_integ] phase AAJ: ZZ + mmt_si_plt_package_entry_ipv6_nz (::ffff:10.0.0.1 -> ::ffff:224.0.0.1:5000, table_length 38)"
run_phase "AAJ" "${port_aaj}" "${tmpdir}/aaj.out" "${tmpdir}/gw_aaj.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 128:0:42 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-package-entry-ipv6-nz
"${probe_bin}" verify \
    --file "${tmpdir}/aaj.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 49 \
    --expect-mmt-si-message-byte-length 49 \
    --expect-mmt-si-message-byte-length 49 \
    --expect-mmt-si-message-byte-length 49 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-length 38 \
    --expect-mmt-si-plt-table-length 38 \
    --expect-mmt-si-plt-table-length 38 \
    --expect-mmt-si-plt-table-length 38 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-package-id-length 0 \
    --expect-mmt-si-plt-package-id-length 0 \
    --expect-mmt-si-plt-package-id-length 0 \
    --expect-mmt-si-plt-package-id-length 0 \
    --expect-mmt-si-plt-package-location-type 2 \
    --expect-mmt-si-plt-package-location-type 2 \
    --expect-mmt-si-plt-package-location-type 2 \
    --expect-mmt-si-plt-package-location-type 2 \
    --expect-mmt-si-plt-package-ipv6-src-addr-3 167772161 \
    --expect-mmt-si-plt-package-ipv6-src-addr-3 167772161 \
    --expect-mmt-si-plt-package-ipv6-src-addr-3 167772161 \
    --expect-mmt-si-plt-package-ipv6-src-addr-3 167772161 \
    --expect-mmt-si-plt-package-ipv6-dst-addr-3 3758096385 \
    --expect-mmt-si-plt-package-ipv6-dst-addr-3 3758096385 \
    --expect-mmt-si-plt-package-ipv6-dst-addr-3 3758096385 \
    --expect-mmt-si-plt-package-ipv6-dst-addr-3 3758096385 \
    --expect-mmt-si-plt-package-ipv6-dst-port 5000 \
    --expect-mmt-si-plt-package-ipv6-dst-port 5000 \
    --expect-mmt-si-plt-package-ipv6-dst-port 5000 \
    --expect-mmt-si-plt-package-ipv6-dst-port 5000 \
    --expected-payloads "${aaj_payloads}"

payloads="${saved_payloads_aaj}"

aak_payload="8000000f01000101010a000001e00000011388"
aak_payloads="${aak_payload},${aak_payload},${aak_payload},${aak_payload}"
saved_payloads_aak="${payloads}"
payloads="${aak_payloads}"

echo "[mmtp_word0_integ] phase AAK: ZX + mmt_si_plt_package_entry_id8_location_ipv4_nz (package id 0x01, 10.0.0.1 -> 224.0.0.1:5000, table_length 15)"
run_phase "AAK" "${port_aak}" "${tmpdir}/aak.out" "${tmpdir}/gw_aak.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 128:0:19 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-package-entry-id8-location-ipv4-nz
"${probe_bin}" verify \
    --file "${tmpdir}/aak.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 26 \
    --expect-mmt-si-message-byte-length 26 \
    --expect-mmt-si-message-byte-length 26 \
    --expect-mmt-si-message-byte-length 26 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-length 15 \
    --expect-mmt-si-plt-table-length 15 \
    --expect-mmt-si-plt-table-length 15 \
    --expect-mmt-si-plt-table-length 15 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-package-id-length 1 \
    --expect-mmt-si-plt-package-id-length 1 \
    --expect-mmt-si-plt-package-id-length 1 \
    --expect-mmt-si-plt-package-id-length 1 \
    --expect-mmt-si-plt-package-mmt-package-id 1 \
    --expect-mmt-si-plt-package-mmt-package-id 1 \
    --expect-mmt-si-plt-package-mmt-package-id 1 \
    --expect-mmt-si-plt-package-mmt-package-id 1 \
    --expect-mmt-si-plt-package-location-type 1 \
    --expect-mmt-si-plt-package-location-type 1 \
    --expect-mmt-si-plt-package-location-type 1 \
    --expect-mmt-si-plt-package-location-type 1 \
    --expect-mmt-si-plt-package-ipv4-src-addr 167772161 \
    --expect-mmt-si-plt-package-ipv4-src-addr 167772161 \
    --expect-mmt-si-plt-package-ipv4-src-addr 167772161 \
    --expect-mmt-si-plt-package-ipv4-src-addr 167772161 \
    --expect-mmt-si-plt-package-ipv4-dst-addr 3758096385 \
    --expect-mmt-si-plt-package-ipv4-dst-addr 3758096385 \
    --expect-mmt-si-plt-package-ipv4-dst-addr 3758096385 \
    --expect-mmt-si-plt-package-ipv4-dst-addr 3758096385 \
    --expect-mmt-si-plt-package-ipv4-dst-port 5000 \
    --expect-mmt-si-plt-package-ipv4-dst-port 5000 \
    --expect-mmt-si-plt-package-ipv4-dst-port 5000 \
    --expect-mmt-si-plt-package-ipv4-dst-port 5000 \
    --expected-payloads "${aak_payloads}"

payloads="${saved_payloads_aak}"

aal_payload="80000027010001010200000000000000000000ffff0a00000100000000000000000000ffffe00000011388"
aal_payloads="${aal_payload},${aal_payload},${aal_payload},${aal_payload}"
saved_payloads_aal="${payloads}"
payloads="${aal_payloads}"

echo "[mmtp_word0_integ] phase AAL: AAB + mmt_si_plt_package_entry_id8_location_ipv6_nz (package id 0x01, ::ffff:10.0.0.1 -> ::ffff:224.0.0.1:5000, table_length 39)"
run_phase "AAL" "${port_aal}" "${tmpdir}/aal.out" "${tmpdir}/gw_aal.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 128:0:43 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-package-entry-id8-location-ipv6-nz
"${probe_bin}" verify \
    --file "${tmpdir}/aal.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 50 \
    --expect-mmt-si-message-byte-length 50 \
    --expect-mmt-si-message-byte-length 50 \
    --expect-mmt-si-message-byte-length 50 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-id 128 \
    --expect-mmt-si-plt-table-length 39 \
    --expect-mmt-si-plt-table-length 39 \
    --expect-mmt-si-plt-table-length 39 \
    --expect-mmt-si-plt-table-length 39 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-packages 1 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-table-body-num-ip-delivery 0 \
    --expect-mmt-si-plt-package-id-length 1 \
    --expect-mmt-si-plt-package-id-length 1 \
    --expect-mmt-si-plt-package-id-length 1 \
    --expect-mmt-si-plt-package-id-length 1 \
    --expect-mmt-si-plt-package-mmt-package-id 1 \
    --expect-mmt-si-plt-package-mmt-package-id 1 \
    --expect-mmt-si-plt-package-mmt-package-id 1 \
    --expect-mmt-si-plt-package-mmt-package-id 1 \
    --expect-mmt-si-plt-package-location-type 2 \
    --expect-mmt-si-plt-package-location-type 2 \
    --expect-mmt-si-plt-package-location-type 2 \
    --expect-mmt-si-plt-package-location-type 2 \
    --expect-mmt-si-plt-package-ipv6-src-addr-3 167772161 \
    --expect-mmt-si-plt-package-ipv6-src-addr-3 167772161 \
    --expect-mmt-si-plt-package-ipv6-src-addr-3 167772161 \
    --expect-mmt-si-plt-package-ipv6-src-addr-3 167772161 \
    --expect-mmt-si-plt-package-ipv6-dst-addr-3 3758096385 \
    --expect-mmt-si-plt-package-ipv6-dst-addr-3 3758096385 \
    --expect-mmt-si-plt-package-ipv6-dst-addr-3 3758096385 \
    --expect-mmt-si-plt-package-ipv6-dst-addr-3 3758096385 \
    --expect-mmt-si-plt-package-ipv6-dst-port 5000 \
    --expect-mmt-si-plt-package-ipv6-dst-port 5000 \
    --expect-mmt-si-plt-package-ipv6-dst-port 5000 \
    --expect-mmt-si-plt-package-ipv6-dst-port 5000 \
    --expected-payloads "${aal_payloads}"

payloads="${saved_payloads_aal}"

aam_payload="2001001f000000000100000000000101000000000001010a000001e000000113880000"
aam_payloads="${aam_payload},${aam_payload},${aam_payload},${aam_payload}"
saved_payloads_aam="${payloads}"
payloads="${aam_payloads}"

echo "[mmtp_word0_integ] phase AAM: ZW + mmt_si_mpt_asset_id8_location_ipv4_nz (asset id 0x01, 10.0.0.1 -> 224.0.0.1:5000, table_length 31)"
run_phase "AAM" "${port_aam}" "${tmpdir}/aam.out" "${tmpdir}/gw_aam.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 32:1:35 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id8-location-ipv4-nz
"${probe_bin}" verify \
    --file "${tmpdir}/aam.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 42 \
    --expect-mmt-si-message-byte-length 42 \
    --expect-mmt-si-message-byte-length 42 \
    --expect-mmt-si-message-byte-length 42 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-length 31 \
    --expect-mmt-si-mpt-table-length 31 \
    --expect-mmt-si-mpt-table-length 31 \
    --expect-mmt-si-mpt-table-length 31 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-asset-id-length 1 \
    --expect-mmt-si-mpt-asset-id-length 1 \
    --expect-mmt-si-mpt-asset-id-length 1 \
    --expect-mmt-si-mpt-asset-id-length 1 \
    --expect-mmt-si-mpt-asset-asset-id 1 \
    --expect-mmt-si-mpt-asset-asset-id 1 \
    --expect-mmt-si-mpt-asset-asset-id 1 \
    --expect-mmt-si-mpt-asset-asset-id 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-ipv4-src-addr 167772161 \
    --expect-mmt-si-mpt-asset-ipv4-src-addr 167772161 \
    --expect-mmt-si-mpt-asset-ipv4-src-addr 167772161 \
    --expect-mmt-si-mpt-asset-ipv4-src-addr 167772161 \
    --expect-mmt-si-mpt-asset-ipv4-dst-addr 3758096385 \
    --expect-mmt-si-mpt-asset-ipv4-dst-addr 3758096385 \
    --expect-mmt-si-mpt-asset-ipv4-dst-addr 3758096385 \
    --expect-mmt-si-mpt-asset-ipv4-dst-addr 3758096385 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 5000 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 5000 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 5000 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 5000 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expected-payloads "${aam_payloads}"

payloads="${saved_payloads_aam}"

aan_payload="200100370000000001000000000001010000000000010200000000000000000000ffff0a00000100000000000000000000ffffe000000113880000"
aan_payloads="${aan_payload},${aan_payload},${aan_payload},${aan_payload}"
saved_payloads_aan="${payloads}"
payloads="${aan_payloads}"

echo "[mmtp_word0_integ] phase AAN: AAA + mmt_si_mpt_asset_id8_location_ipv6_nz (asset id 0x01, ::ffff:10.0.0.1 -> ::ffff:224.0.0.1:5000, table_length 55)"
run_phase "AAN" "${port_aan}" "${tmpdir}/aan.out" "${tmpdir}/gw_aan.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 32:1:59 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id8-location-ipv6-nz
"${probe_bin}" verify \
    --file "${tmpdir}/aan.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 66 \
    --expect-mmt-si-message-byte-length 66 \
    --expect-mmt-si-message-byte-length 66 \
    --expect-mmt-si-message-byte-length 66 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-length 55 \
    --expect-mmt-si-mpt-table-length 55 \
    --expect-mmt-si-mpt-table-length 55 \
    --expect-mmt-si-mpt-table-length 55 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-asset-id-length 1 \
    --expect-mmt-si-mpt-asset-id-length 1 \
    --expect-mmt-si-mpt-asset-id-length 1 \
    --expect-mmt-si-mpt-asset-id-length 1 \
    --expect-mmt-si-mpt-asset-asset-id 1 \
    --expect-mmt-si-mpt-asset-asset-id 1 \
    --expect-mmt-si-mpt-asset-asset-id 1 \
    --expect-mmt-si-mpt-asset-asset-id 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-ipv6-src-addr-3 167772161 \
    --expect-mmt-si-mpt-asset-ipv6-src-addr-3 167772161 \
    --expect-mmt-si-mpt-asset-ipv6-src-addr-3 167772161 \
    --expect-mmt-si-mpt-asset-ipv6-src-addr-3 167772161 \
    --expect-mmt-si-mpt-asset-ipv6-dst-addr-3 3758096385 \
    --expect-mmt-si-mpt-asset-ipv6-dst-addr-3 3758096385 \
    --expect-mmt-si-mpt-asset-ipv6-dst-addr-3 3758096385 \
    --expect-mmt-si-mpt-asset-ipv6-dst-addr-3 3758096385 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 5000 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 5000 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 5000 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 5000 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expected-payloads "${aan_payloads}"

payloads="${saved_payloads_aan}"

payloads="${saved_payloads_aan}"

aao_payload="200100200000000001000000000002010200000000000101000000000000000000000000"
aao_payloads="${aao_payload},${aao_payload},${aao_payload},${aao_payload}"
saved_payloads_aao="${payloads}"
payloads="${aao_payloads}"

echo "[mmtp_word0_integ] phase AAO: mmt_si_mpt_asset_id16_location_ipv4 (asset id 0x01 0x02, zero IPv4, table_length 32)"
run_phase "AAO" "${port_aao}" "${tmpdir}/aao.out" "${tmpdir}/gw_aao.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 32:1:36 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id16-location-ipv4
"${probe_bin}" verify \
    --file "${tmpdir}/aao.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 43 \
    --expect-mmt-si-message-byte-length 43 \
    --expect-mmt-si-message-byte-length 43 \
    --expect-mmt-si-message-byte-length 43 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-length 32 \
    --expect-mmt-si-mpt-table-length 32 \
    --expect-mmt-si-mpt-table-length 32 \
    --expect-mmt-si-mpt-table-length 32 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-asset-id-length 2 \
    --expect-mmt-si-mpt-asset-id-length 2 \
    --expect-mmt-si-mpt-asset-id-length 2 \
    --expect-mmt-si-mpt-asset-id-length 2 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expected-payloads "${aao_payloads}"

payloads="${saved_payloads_aao}"

aap_payload="2001002000000000010000000000020102000000000001010a000001e000000113880000"
aap_payloads="${aap_payload},${aap_payload},${aap_payload},${aap_payload}"
saved_payloads_aap="${payloads}"
payloads="${aap_payloads}"

echo "[mmtp_word0_integ] phase AAP: mmt_si_mpt_asset_id16_location_ipv4_nz (asset id 0x01 0x02, 10.0.0.1 -> 224.0.0.1:5000, table_length 32)"
run_phase "AAP" "${port_aap}" "${tmpdir}/aap.out" "${tmpdir}/gw_aap.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 32:1:36 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id16-location-ipv4-nz
"${probe_bin}" verify \
    --file "${tmpdir}/aap.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 43 \
    --expect-mmt-si-message-byte-length 43 \
    --expect-mmt-si-message-byte-length 43 \
    --expect-mmt-si-message-byte-length 43 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-length 32 \
    --expect-mmt-si-mpt-table-length 32 \
    --expect-mmt-si-mpt-table-length 32 \
    --expect-mmt-si-mpt-table-length 32 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-asset-id-length 2 \
    --expect-mmt-si-mpt-asset-id-length 2 \
    --expect-mmt-si-mpt-asset-id-length 2 \
    --expect-mmt-si-mpt-asset-id-length 2 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-ipv4-src-addr 167772161 \
    --expect-mmt-si-mpt-asset-ipv4-src-addr 167772161 \
    --expect-mmt-si-mpt-asset-ipv4-src-addr 167772161 \
    --expect-mmt-si-mpt-asset-ipv4-src-addr 167772161 \
    --expect-mmt-si-mpt-asset-ipv4-dst-addr 3758096385 \
    --expect-mmt-si-mpt-asset-ipv4-dst-addr 3758096385 \
    --expect-mmt-si-mpt-asset-ipv4-dst-addr 3758096385 \
    --expect-mmt-si-mpt-asset-ipv4-dst-addr 3758096385 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 5000 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 5000 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 5000 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 5000 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expected-payloads "${aap_payloads}"

payloads="${saved_payloads_aap}"

aaq_payload="2001003700000000010000000000020102000000000001020000000000000000000000000000000000000000000000000000000000000000000000"
aaq_payloads="${aaq_payload},${aaq_payload},${aaq_payload},${aaq_payload}"
saved_payloads_aaq="${payloads}"
payloads="${aaq_payloads}"

echo "[mmtp_word0_integ] phase AAQ: mmt_si_mpt_asset_id16_location_ipv6 (asset id 0x01 0x02, zero IPv6, table_length 55)"
run_phase "AAQ" "${port_aaq}" "${tmpdir}/aaq.out" "${tmpdir}/gw_aaq.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 32:1:59 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id16-location-ipv6
"${probe_bin}" verify \
    --file "${tmpdir}/aaq.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 66 \
    --expect-mmt-si-message-byte-length 66 \
    --expect-mmt-si-message-byte-length 66 \
    --expect-mmt-si-message-byte-length 66 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-length 55 \
    --expect-mmt-si-mpt-table-length 55 \
    --expect-mmt-si-mpt-table-length 55 \
    --expect-mmt-si-mpt-table-length 55 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-asset-id-length 2 \
    --expect-mmt-si-mpt-asset-id-length 2 \
    --expect-mmt-si-mpt-asset-id-length 2 \
    --expect-mmt-si-mpt-asset-id-length 2 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expected-payloads "${aaq_payloads}"

payloads="${saved_payloads_aaq}"

aar_payload="20010038000000000100000000000201020000000000010200000000000000000000ffff0a00000100000000000000000000ffffe000000113880000"
aar_payloads="${aar_payload},${aar_payload},${aar_payload},${aar_payload}"
saved_payloads_aar="${payloads}"
payloads="${aar_payloads}"

echo "[mmtp_word0_integ] phase AAR: mmt_si_mpt_asset_id16_location_ipv6_nz (asset id 0x01 0x02, ::ffff:10.0.0.1 -> ::ffff:224.0.0.1:5000, table_length 56)"
run_phase "AAR" "${port_aar}" "${tmpdir}/aar.out" "${tmpdir}/gw_aar.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 32:1:60 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id16-location-ipv6-nz
"${probe_bin}" verify \
    --file "${tmpdir}/aar.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 67 \
    --expect-mmt-si-message-byte-length 67 \
    --expect-mmt-si-message-byte-length 67 \
    --expect-mmt-si-message-byte-length 67 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-length 56 \
    --expect-mmt-si-mpt-table-length 56 \
    --expect-mmt-si-mpt-table-length 56 \
    --expect-mmt-si-mpt-table-length 56 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-asset-id-length 2 \
    --expect-mmt-si-mpt-asset-id-length 2 \
    --expect-mmt-si-mpt-asset-id-length 2 \
    --expect-mmt-si-mpt-asset-id-length 2 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-ipv6-src-addr-3 167772161 \
    --expect-mmt-si-mpt-asset-ipv6-src-addr-3 167772161 \
    --expect-mmt-si-mpt-asset-ipv6-src-addr-3 167772161 \
    --expect-mmt-si-mpt-asset-ipv6-src-addr-3 167772161 \
    --expect-mmt-si-mpt-asset-ipv6-dst-addr-3 3758096385 \
    --expect-mmt-si-mpt-asset-ipv6-dst-addr-3 3758096385 \
    --expect-mmt-si-mpt-asset-ipv6-dst-addr-3 3758096385 \
    --expect-mmt-si-mpt-asset-ipv6-dst-addr-3 3758096385 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 5000 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 5000 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 5000 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 5000 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expected-payloads "${aar_payloads}"

payloads="${saved_payloads_aar}"

aas_payload="20010019000000000100000000000201020000000000000004deadbeef"
aas_payloads="${aas_payload},${aas_payload},${aas_payload},${aas_payload}"
saved_payloads_aas="${payloads}"
payloads="${aas_payloads}"

echo "[mmtp_word0_integ] phase AAS: mmt_si_mpt_asset_id16_descriptors4 (asset id 0x01 0x02, DEADBEEF, table_length 25)"
run_phase "AAS" "${port_aas}" "${tmpdir}/aas.out" "${tmpdir}/gw_aas.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 32:1:29 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id16-descriptors4
"${probe_bin}" verify \
    --file "${tmpdir}/aas.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 36 \
    --expect-mmt-si-message-byte-length 36 \
    --expect-mmt-si-message-byte-length 36 \
    --expect-mmt-si-message-byte-length 36 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-length 25 \
    --expect-mmt-si-mpt-table-length 25 \
    --expect-mmt-si-mpt-table-length 25 \
    --expect-mmt-si-mpt-table-length 25 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-asset-id-length 2 \
    --expect-mmt-si-mpt-asset-id-length 2 \
    --expect-mmt-si-mpt-asset-id-length 2 \
    --expect-mmt-si-mpt-asset-id-length 2 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 4 \
    --expect-mmt-si-mpt-asset-descriptors-length 4 \
    --expect-mmt-si-mpt-asset-descriptors-length 4 \
    --expect-mmt-si-mpt-asset-descriptors-length 4 \
    --expected-payloads "${aas_payloads}"

payloads="${saved_payloads_aas}"

aat_payload="200100180000000001000000000001010000000000000004deadbeef"
aat_payloads="${aat_payload},${aat_payload},${aat_payload},${aat_payload}"
saved_payloads_aat="${payloads}"
payloads="${aat_payloads}"

echo "[mmtp_word0_integ] phase AAT: mmt_si_mpt_asset_id8_descriptors4 (asset id 0x01, DEADBEEF, table_length 24)"
run_phase "AAT" "${port_aat}" "${tmpdir}/aat.out" "${tmpdir}/gw_aat.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --prepend-mmt-si-pa-table-headers \
    --mmtp-si-pa-table-row 32:1:28 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id8-descriptors4
"${probe_bin}" verify \
    --file "${tmpdir}/aat.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-byte-length 35 \
    --expect-mmt-si-message-byte-length 35 \
    --expect-mmt-si-message-byte-length 35 \
    --expect-mmt-si-message-byte-length 35 \
    --strip-mmt-si-pa-table-headers \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-pa-number-of-tables 1 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-id 32 \
    --expect-mmt-si-mpt-table-length 24 \
    --expect-mmt-si-mpt-table-length 24 \
    --expect-mmt-si-mpt-table-length 24 \
    --expect-mmt-si-mpt-table-length 24 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-table-body-num-assets 1 \
    --expect-mmt-si-mpt-asset-id-length 1 \
    --expect-mmt-si-mpt-asset-id-length 1 \
    --expect-mmt-si-mpt-asset-id-length 1 \
    --expect-mmt-si-mpt-asset-id-length 1 \
    --expect-mmt-si-mpt-asset-asset-id 1 \
    --expect-mmt-si-mpt-asset-asset-id 1 \
    --expect-mmt-si-mpt-asset-asset-id 1 \
    --expect-mmt-si-mpt-asset-asset-id 1 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 4 \
    --expect-mmt-si-mpt-asset-descriptors-length 4 \
    --expect-mmt-si-mpt-asset-descriptors-length 4 \
    --expect-mmt-si-mpt-asset-descriptors-length 4 \
    --expected-payloads "${aat_payloads}"

payloads="${saved_payloads_aat}"

echo "[mmtp_word0_integ] PASS"

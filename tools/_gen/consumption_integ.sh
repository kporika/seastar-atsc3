# (**ABU**) **§10.3 consumption + mpt_asset_location0 lab:** **message_id** **16** + **`mmt_si_mpt_asset_location0`** (**ZT** ingress, **packet_id** **2**).
# (**ABV**) **§10.3 consumption + mpt_asset_id8_location_ipv4 lab:** **message_id** **16** + **`mmt_si_mpt_asset_id8_location_ipv4`** (**ZW** ingress, **packet_id** **2**).
# (**ABW**) **§10.3 consumption + plt_package_entry_id8_location_ipv4 lab:** **message_id** **128** + **`mmt_si_plt_package_entry_id8_location_ipv4`** (**ZX** ingress).
# (**ABX**) **§10.3 consumption + mpt_asset_id8_location_ipv6 lab:** **message_id** **16** + **`mmt_si_mpt_asset_id8_location_ipv6`** (**AAA** ingress, **packet_id** **2**).
# (**ABY**) **§10.3 consumption + plt_package_entry_id8_location_ipv6 lab:** **message_id** **128** + **`mmt_si_plt_package_entry_id8_location_ipv6`** (**AAB** ingress).
# (**ABZ**) **§10.3 consumption + mpt_asset_location_ipv6_nz lab:** **message_id** **16** + **`mmt_si_mpt_asset_location_ipv6_nz`** (**AAH** ingress, **packet_id** **2**).
# (**ACA**) **§10.3 consumption + plt_package_entry_id8_location_ipv4_nz lab:** **message_id** **128** + **`mmt_si_plt_package_entry_id8_location_ipv4_nz`** (**AAK** ingress).
# (**ACB**) **§10.3 consumption + plt_package_entry_id8_location_ipv6_nz lab:** **message_id** **128** + **`mmt_si_plt_package_entry_id8_location_ipv6_nz`** (**AAL** ingress).
# (**ACC**) **§10.3 consumption + mpt_asset_id8_location_ipv4_nz lab:** **message_id** **16** + **`mmt_si_mpt_asset_id8_location_ipv4_nz`** (**AAM** ingress, **packet_id** **2**).
# (**ACD**) **§10.3 consumption + mpt_asset_id8_location_ipv6_nz lab:** **message_id** **16** + **`mmt_si_mpt_asset_id8_location_ipv6_nz`** (**AAN** ingress, **packet_id** **2**).
# (**ACE**) **§10.3 consumption + mpt_asset_id16_location_ipv4 lab:** **message_id** **16** + **`mmt_si_mpt_asset_id16_location_ipv4`** (**AAO** ingress, **packet_id** **2**).
# (**ACF**) **§10.3 consumption + mpt_asset_id16_location_ipv4_nz lab:** **message_id** **16** + **`mmt_si_mpt_asset_id16_location_ipv4_nz`** (**AAP** ingress, **packet_id** **2**).
# (**ACG**) **§10.3 consumption + mpt_asset_id16_location_ipv6 lab:** **message_id** **16** + **`mmt_si_mpt_asset_id16_location_ipv6`** (**AAQ** ingress, **packet_id** **2**).
# (**ACH**) **§10.3 consumption + mpt_asset_id16_location_ipv6_nz lab:** **message_id** **16** + **`mmt_si_mpt_asset_id16_location_ipv6_nz`** (**AAR** ingress, **packet_id** **2**).
# (**ACI**) **§10.3 consumption + mpt_asset_id16_descriptors4 lab:** **message_id** **16** + **`mmt_si_mpt_asset_id16_descriptors4`** (**AAS** ingress, **packet_id** **2**).

port_abu=$(( ( RANDOM % 10000 ) + 679000 ))
port_abv=$(( ( RANDOM % 10000 ) + 680000 ))
port_abw=$(( ( RANDOM % 10000 ) + 681000 ))
port_abx=$(( ( RANDOM % 10000 ) + 682000 ))
port_aby=$(( ( RANDOM % 10000 ) + 683000 ))
port_abz=$(( ( RANDOM % 10000 ) + 684000 ))
port_aca=$(( ( RANDOM % 10000 ) + 685000 ))
port_acb=$(( ( RANDOM % 10000 ) + 686000 ))
port_acc=$(( ( RANDOM % 10000 ) + 687000 ))
port_acd=$(( ( RANDOM % 10000 ) + 688000 ))
port_ace=$(( ( RANDOM % 10000 ) + 689000 ))
port_acf=$(( ( RANDOM % 10000 ) + 690000 ))
port_acg=$(( ( RANDOM % 10000 ) + 691000 ))
port_ach=$(( ( RANDOM % 10000 ) + 692000 ))
port_aci=$(( ( RANDOM % 10000 ) + 693000 ))

abu_payloads="${zt_payloads}"
saved_payloads_abu="${payloads}"
payloads="${abu_payloads}"

echo "[mmtp_word0_integ] phase ABU: consumption message (message_id=16) + mmt_si_mpt_asset_location0 (ZT ingress)"
run_phase "ABU" "${port_abu}" "${tmpdir}/abu.out" "${tmpdir}/gw_abu.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type 2 \
    --mmtp-packet-id 2 \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 16 \
    --mmtp-si-message-version 0 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-location0 \
"${probe_bin}" verify \
    --file "${tmpdir}/abu.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type 2 \
    --expect-mmtp-packet-id 2 \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-byte-length 26 \
    --expect-mmt-si-message-byte-length 26 \
    --expect-mmt-si-message-byte-length 26 \
    --expect-mmt-si-message-byte-length 26 \
    --expected-payloads "${abu_payloads}"

payloads="${saved_payloads_abu}"

abv_payloads="${zw_payloads}"
saved_payloads_abv="${payloads}"
payloads="${abv_payloads}"

echo "[mmtp_word0_integ] phase ABV: consumption message (message_id=16) + mmt_si_mpt_asset_id8_location_ipv4 (ZW ingress)"
run_phase "ABV" "${port_abv}" "${tmpdir}/abv.out" "${tmpdir}/gw_abv.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type 2 \
    --mmtp-packet-id 2 \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 16 \
    --mmtp-si-message-version 0 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id8-location-ipv4 \
"${probe_bin}" verify \
    --file "${tmpdir}/abv.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type 2 \
    --expect-mmtp-packet-id 2 \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-byte-length 35 \
    --expect-mmt-si-message-byte-length 35 \
    --expect-mmt-si-message-byte-length 35 \
    --expect-mmt-si-message-byte-length 35 \
    --expected-payloads "${abv_payloads}"

payloads="${saved_payloads_abv}"

abw_payloads="${zx_payloads}"
saved_payloads_abw="${payloads}"
payloads="${abw_payloads}"

echo "[mmtp_word0_integ] phase ABW: consumption message (message_id=128) + mmt_si_plt_package_entry_id8_location_ipv4 (ZX ingress)"
run_phase "ABW" "${port_abw}" "${tmpdir}/abw.out" "${tmpdir}/gw_abw.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type 2 \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 128 \
    --mmtp-si-message-version 0 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-package-entry-id8-location-ipv4 \
"${probe_bin}" verify \
    --file "${tmpdir}/abw.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type 2 \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-id 128 \
    --expect-mmt-si-message-id 128 \
    --expect-mmt-si-message-id 128 \
    --expect-mmt-si-message-id 128 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-byte-length 19 \
    --expect-mmt-si-message-byte-length 19 \
    --expect-mmt-si-message-byte-length 19 \
    --expect-mmt-si-message-byte-length 19 \
    --expected-payloads "${abw_payloads}"

payloads="${saved_payloads_abw}"

abx_payloads="${aaa_payloads}"
saved_payloads_abx="${payloads}"
payloads="${abx_payloads}"

echo "[mmtp_word0_integ] phase ABX: consumption message (message_id=16) + mmt_si_mpt_asset_id8_location_ipv6 (AAA ingress)"
run_phase "ABX" "${port_abx}" "${tmpdir}/abx.out" "${tmpdir}/gw_abx.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type 2 \
    --mmtp-packet-id 2 \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 16 \
    --mmtp-si-message-version 0 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id8-location-ipv6 \
"${probe_bin}" verify \
    --file "${tmpdir}/abx.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type 2 \
    --expect-mmtp-packet-id 2 \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-byte-length 59 \
    --expect-mmt-si-message-byte-length 59 \
    --expect-mmt-si-message-byte-length 59 \
    --expect-mmt-si-message-byte-length 59 \
    --expected-payloads "${abx_payloads}"

payloads="${saved_payloads_abx}"

aby_payloads="${aab_payloads}"
saved_payloads_aby="${payloads}"
payloads="${aby_payloads}"

echo "[mmtp_word0_integ] phase ABY: consumption message (message_id=128) + mmt_si_plt_package_entry_id8_location_ipv6 (AAB ingress)"
run_phase "ABY" "${port_aby}" "${tmpdir}/aby.out" "${tmpdir}/gw_aby.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type 2 \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 128 \
    --mmtp-si-message-version 0 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-package-entry-id8-location-ipv6 \
"${probe_bin}" verify \
    --file "${tmpdir}/aby.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type 2 \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-id 128 \
    --expect-mmt-si-message-id 128 \
    --expect-mmt-si-message-id 128 \
    --expect-mmt-si-message-id 128 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-byte-length 43 \
    --expect-mmt-si-message-byte-length 43 \
    --expect-mmt-si-message-byte-length 43 \
    --expect-mmt-si-message-byte-length 43 \
    --expected-payloads "${aby_payloads}"

payloads="${saved_payloads_aby}"

abz_payloads="${aah_payloads}"
saved_payloads_abz="${payloads}"
payloads="${abz_payloads}"

echo "[mmtp_word0_integ] phase ABZ: consumption message (message_id=16) + mmt_si_mpt_asset_location_ipv6_nz (AAH ingress)"
run_phase "ABZ" "${port_abz}" "${tmpdir}/abz.out" "${tmpdir}/gw_abz.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type 2 \
    --mmtp-packet-id 2 \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 16 \
    --mmtp-si-message-version 0 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-location-ipv6-nz \
"${probe_bin}" verify \
    --file "${tmpdir}/abz.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type 2 \
    --expect-mmtp-packet-id 2 \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-byte-length 58 \
    --expect-mmt-si-message-byte-length 58 \
    --expect-mmt-si-message-byte-length 58 \
    --expect-mmt-si-message-byte-length 58 \
    --expected-payloads "${abz_payloads}"

payloads="${saved_payloads_abz}"

aca_payloads="${aak_payloads}"
saved_payloads_aca="${payloads}"
payloads="${aca_payloads}"

echo "[mmtp_word0_integ] phase ACA: consumption message (message_id=128) + mmt_si_plt_package_entry_id8_location_ipv4_nz (AAK ingress)"
run_phase "ACA" "${port_aca}" "${tmpdir}/aca.out" "${tmpdir}/gw_aca.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type 2 \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 128 \
    --mmtp-si-message-version 0 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-package-entry-id8-location-ipv4-nz \
"${probe_bin}" verify \
    --file "${tmpdir}/aca.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type 2 \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-id 128 \
    --expect-mmt-si-message-id 128 \
    --expect-mmt-si-message-id 128 \
    --expect-mmt-si-message-id 128 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-byte-length 19 \
    --expect-mmt-si-message-byte-length 19 \
    --expect-mmt-si-message-byte-length 19 \
    --expect-mmt-si-message-byte-length 19 \
    --expected-payloads "${aca_payloads}"

payloads="${saved_payloads_aca}"

acb_payloads="${aal_payloads}"
saved_payloads_acb="${payloads}"
payloads="${acb_payloads}"

echo "[mmtp_word0_integ] phase ACB: consumption message (message_id=128) + mmt_si_plt_package_entry_id8_location_ipv6_nz (AAL ingress)"
run_phase "ACB" "${port_acb}" "${tmpdir}/acb.out" "${tmpdir}/gw_acb.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type 2 \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 128 \
    --mmtp-si-message-version 0 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-package-entry-id8-location-ipv6-nz \
"${probe_bin}" verify \
    --file "${tmpdir}/acb.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type 2 \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-id 128 \
    --expect-mmt-si-message-id 128 \
    --expect-mmt-si-message-id 128 \
    --expect-mmt-si-message-id 128 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-byte-length 43 \
    --expect-mmt-si-message-byte-length 43 \
    --expect-mmt-si-message-byte-length 43 \
    --expect-mmt-si-message-byte-length 43 \
    --expected-payloads "${acb_payloads}"

payloads="${saved_payloads_acb}"

acc_payloads="${aam_payloads}"
saved_payloads_acc="${payloads}"
payloads="${acc_payloads}"

echo "[mmtp_word0_integ] phase ACC: consumption message (message_id=16) + mmt_si_mpt_asset_id8_location_ipv4_nz (AAM ingress)"
run_phase "ACC" "${port_acc}" "${tmpdir}/acc.out" "${tmpdir}/gw_acc.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type 2 \
    --mmtp-packet-id 2 \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 16 \
    --mmtp-si-message-version 0 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id8-location-ipv4-nz \
"${probe_bin}" verify \
    --file "${tmpdir}/acc.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type 2 \
    --expect-mmtp-packet-id 2 \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-byte-length 35 \
    --expect-mmt-si-message-byte-length 35 \
    --expect-mmt-si-message-byte-length 35 \
    --expect-mmt-si-message-byte-length 35 \
    --expected-payloads "${acc_payloads}"

payloads="${saved_payloads_acc}"

acd_payloads="${aan_payloads}"
saved_payloads_acd="${payloads}"
payloads="${acd_payloads}"

echo "[mmtp_word0_integ] phase ACD: consumption message (message_id=16) + mmt_si_mpt_asset_id8_location_ipv6_nz (AAN ingress)"
run_phase "ACD" "${port_acd}" "${tmpdir}/acd.out" "${tmpdir}/gw_acd.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type 2 \
    --mmtp-packet-id 2 \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 16 \
    --mmtp-si-message-version 0 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id8-location-ipv6-nz \
"${probe_bin}" verify \
    --file "${tmpdir}/acd.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type 2 \
    --expect-mmtp-packet-id 2 \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-byte-length 59 \
    --expect-mmt-si-message-byte-length 59 \
    --expect-mmt-si-message-byte-length 59 \
    --expect-mmt-si-message-byte-length 59 \
    --expected-payloads "${acd_payloads}"

payloads="${saved_payloads_acd}"

ace_payloads="${aao_payloads}"
saved_payloads_ace="${payloads}"
payloads="${ace_payloads}"

echo "[mmtp_word0_integ] phase ACE: consumption message (message_id=16) + mmt_si_mpt_asset_id16_location_ipv4 (AAO ingress)"
run_phase "ACE" "${port_ace}" "${tmpdir}/ace.out" "${tmpdir}/gw_ace.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type 2 \
    --mmtp-packet-id 2 \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 16 \
    --mmtp-si-message-version 0 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id16-location-ipv4 \
"${probe_bin}" verify \
    --file "${tmpdir}/ace.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type 2 \
    --expect-mmtp-packet-id 2 \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-byte-length 36 \
    --expect-mmt-si-message-byte-length 36 \
    --expect-mmt-si-message-byte-length 36 \
    --expect-mmt-si-message-byte-length 36 \
    --expected-payloads "${ace_payloads}"

payloads="${saved_payloads_ace}"

acf_payloads="${aap_payloads}"
saved_payloads_acf="${payloads}"
payloads="${acf_payloads}"

echo "[mmtp_word0_integ] phase ACF: consumption message (message_id=16) + mmt_si_mpt_asset_id16_location_ipv4_nz (AAP ingress)"
run_phase "ACF" "${port_acf}" "${tmpdir}/acf.out" "${tmpdir}/gw_acf.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type 2 \
    --mmtp-packet-id 2 \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 16 \
    --mmtp-si-message-version 0 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id16-location-ipv4-nz \
"${probe_bin}" verify \
    --file "${tmpdir}/acf.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type 2 \
    --expect-mmtp-packet-id 2 \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-byte-length 36 \
    --expect-mmt-si-message-byte-length 36 \
    --expect-mmt-si-message-byte-length 36 \
    --expect-mmt-si-message-byte-length 36 \
    --expected-payloads "${acf_payloads}"

payloads="${saved_payloads_acf}"

acg_payloads="${aaq_payloads}"
saved_payloads_acg="${payloads}"
payloads="${acg_payloads}"

echo "[mmtp_word0_integ] phase ACG: consumption message (message_id=16) + mmt_si_mpt_asset_id16_location_ipv6 (AAQ ingress)"
run_phase "ACG" "${port_acg}" "${tmpdir}/acg.out" "${tmpdir}/gw_acg.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type 2 \
    --mmtp-packet-id 2 \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 16 \
    --mmtp-si-message-version 0 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id16-location-ipv6 \
"${probe_bin}" verify \
    --file "${tmpdir}/acg.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type 2 \
    --expect-mmtp-packet-id 2 \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-byte-length 59 \
    --expect-mmt-si-message-byte-length 59 \
    --expect-mmt-si-message-byte-length 59 \
    --expect-mmt-si-message-byte-length 59 \
    --expected-payloads "${acg_payloads}"

payloads="${saved_payloads_acg}"

ach_payloads="${aar_payloads}"
saved_payloads_ach="${payloads}"
payloads="${ach_payloads}"

echo "[mmtp_word0_integ] phase ACH: consumption message (message_id=16) + mmt_si_mpt_asset_id16_location_ipv6_nz (AAR ingress)"
run_phase "ACH" "${port_ach}" "${tmpdir}/ach.out" "${tmpdir}/gw_ach.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type 2 \
    --mmtp-packet-id 2 \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 16 \
    --mmtp-si-message-version 0 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id16-location-ipv6-nz \
"${probe_bin}" verify \
    --file "${tmpdir}/ach.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type 2 \
    --expect-mmtp-packet-id 2 \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-byte-length 60 \
    --expect-mmt-si-message-byte-length 60 \
    --expect-mmt-si-message-byte-length 60 \
    --expect-mmt-si-message-byte-length 60 \
    --expected-payloads "${ach_payloads}"

payloads="${saved_payloads_ach}"

aci_payloads="${aas_payloads}"
saved_payloads_aci="${payloads}"
payloads="${aci_payloads}"

echo "[mmtp_word0_integ] phase ACI: consumption message (message_id=16) + mmt_si_mpt_asset_id16_descriptors4 (AAS ingress)"
run_phase "ACI" "${port_aci}" "${tmpdir}/aci.out" "${tmpdir}/gw_aci.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type 2 \
    --mmtp-packet-id 2 \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 16 \
    --mmtp-si-message-version 0 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id16-descriptors4 \
"${probe_bin}" verify \
    --file "${tmpdir}/aci.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type 2 \
    --expect-mmtp-packet-id 2 \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-id 16 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-version 0 \
    --expect-mmt-si-message-byte-length 29 \
    --expect-mmt-si-message-byte-length 29 \
    --expect-mmt-si-message-byte-length 29 \
    --expect-mmt-si-message-byte-length 29 \
    --expected-payloads "${aci_payloads}"

payloads="${saved_payloads_aci}"

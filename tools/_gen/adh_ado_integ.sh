adh_payload="010004800000118000000d00010000000005036c61620000"
adh_payloads="${adh_payload},${adh_payload},${adh_payload},${adh_payload}"
saved_payloads_adh="${payloads}"
payloads="${adh_payloads}"

echo "[mmtp_word0_integ] phase ADH: consumption (message_id=0) + PA + PLT (ZQ ingress)"
run_phase "ADH" "${port_adh}" "${tmpdir}/adh.out" "${tmpdir}/gw_adh.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-delivery-info-url-3
"${probe_bin}" verify \
    --file "${tmpdir}/adh.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-version 1 \
    --expect-mmt-si-message-version 1 \
    --expect-mmt-si-message-version 1 \
    --expect-mmt-si-message-version 1 \
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

payloads="${saved_payloads_adh}"

adi_payload="010004800000138000000f010001010100000000000000000000"
adi_payloads="${adi_payload},${adi_payload},${adi_payload},${adi_payload}"
saved_payloads_adi="${payloads}"
payloads="${adi_payloads}"

echo "[mmtp_word0_integ] phase ADI: consumption (message_id=0) + PA + PLT (ZX ingress)"
run_phase "ADI" "${port_adi}" "${tmpdir}/adi.out" "${tmpdir}/gw_adi.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-package-entry-id8-location-ipv4
"${probe_bin}" verify \
    --file "${tmpdir}/adi.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-version 1 \
    --expect-mmt-si-message-version 1 \
    --expect-mmt-si-message-version 1 \
    --expect-mmt-si-message-version 1 \
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

payloads="${saved_payloads_adi}"

adj_payload="0100048000002a800000260100000200000000000000000000000000000000000000000000000000000000000000000000"
adj_payloads="${adj_payload},${adj_payload},${adj_payload},${adj_payload}"
saved_payloads_adj="${payloads}"
payloads="${adj_payloads}"

echo "[mmtp_word0_integ] phase ADJ: consumption (message_id=0) + PA + PLT (ZZ ingress)"
run_phase "ADJ" "${port_adj}" "${tmpdir}/adj.out" "${tmpdir}/gw_adj.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-package-entry-ipv6
"${probe_bin}" verify \
    --file "${tmpdir}/adj.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-version 1 \
    --expect-mmt-si-message-version 1 \
    --expect-mmt-si-message-version 1 \
    --expect-mmt-si-message-version 1 \
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

payloads="${saved_payloads_adj}"

adk_payload="0100048000002b80000027010001010200000000000000000000000000000000000000000000000000000000000000000000"
adk_payloads="${adk_payload},${adk_payload},${adk_payload},${adk_payload}"
saved_payloads_adk="${payloads}"
payloads="${adk_payloads}"

echo "[mmtp_word0_integ] phase ADK: consumption (message_id=0) + PA + PLT (AAB ingress)"
run_phase "ADK" "${port_adk}" "${tmpdir}/adk.out" "${tmpdir}/gw_adk.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-package-entry-id8-location-ipv6
"${probe_bin}" verify \
    --file "${tmpdir}/adk.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-version 1 \
    --expect-mmt-si-message-version 1 \
    --expect-mmt-si-message-version 1 \
    --expect-mmt-si-message-version 1 \
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

payloads="${saved_payloads_adk}"

adl_payload="010004800000128000000e0001000000000504687474700000"
adl_payloads="${adl_payload},${adl_payload},${adl_payload},${adl_payload}"
saved_payloads_adl="${payloads}"
payloads="${adl_payloads}"

echo "[mmtp_word0_integ] phase ADL: consumption (message_id=0) + PA + PLT (AAD ingress)"
run_phase "ADL" "${port_adl}" "${tmpdir}/adl.out" "${tmpdir}/gw_adl.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-delivery-info-url-4
"${probe_bin}" verify \
    --file "${tmpdir}/adl.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-version 1 \
    --expect-mmt-si-message-version 1 \
    --expect-mmt-si-message-version 1 \
    --expect-mmt-si-message-version 1 \
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

payloads="${saved_payloads_adl}"

adm_payload="010004800000128000000e010000010a000001e00000011388"
adm_payloads="${adm_payload},${adm_payload},${adm_payload},${adm_payload}"
saved_payloads_adm="${payloads}"
payloads="${adm_payloads}"

echo "[mmtp_word0_integ] phase ADM: consumption (message_id=0) + PA + PLT (AAI ingress)"
run_phase "ADM" "${port_adm}" "${tmpdir}/adm.out" "${tmpdir}/gw_adm.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-package-entry-ipv4-nz
"${probe_bin}" verify \
    --file "${tmpdir}/adm.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-version 1 \
    --expect-mmt-si-message-version 1 \
    --expect-mmt-si-message-version 1 \
    --expect-mmt-si-message-version 1 \
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

payloads="${saved_payloads_adm}"

adn_payload="010004800000138000000f01000101010a000001e00000011388"
adn_payloads="${adn_payload},${adn_payload},${adn_payload},${adn_payload}"
saved_payloads_adn="${payloads}"
payloads="${adn_payloads}"

echo "[mmtp_word0_integ] phase ADN: consumption (message_id=0) + PA + PLT (AAK ingress)"
run_phase "ADN" "${port_adn}" "${tmpdir}/adn.out" "${tmpdir}/gw_adn.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-package-entry-id8-location-ipv4-nz
"${probe_bin}" verify \
    --file "${tmpdir}/adn.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-version 1 \
    --expect-mmt-si-message-version 1 \
    --expect-mmt-si-message-version 1 \
    --expect-mmt-si-message-version 1 \
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

payloads="${saved_payloads_adn}"

ado_payload="0100048000002b80000027010001010200000000000000000000ffff0a00000100000000000000000000ffffe00000011388"
ado_payloads="${ado_payload},${ado_payload},${ado_payload},${ado_payload}"
saved_payloads_ado="${payloads}"
payloads="${ado_payloads}"

echo "[mmtp_word0_integ] phase ADO: consumption (message_id=0) + PA + PLT (AAL ingress)"
run_phase "ADO" "${port_ado}" "${tmpdir}/ado.out" "${tmpdir}/gw_ado.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-package-entry-id8-location-ipv6-nz
"${probe_bin}" verify \
    --file "${tmpdir}/ado.out.shard0" \
    --strip-mmtp-word0 \
    --expect-mmtp-payload-type "${mmtp_pt}" \
    --expect-mmtp-packet-id "${mmtp_pid}" \
    --strip-mmtp-signalling-prefix \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-fragmentation 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-reserved 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-length-extension 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-aggregation 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --expect-mmtp-signalling-fragment-counter 0 \
    --strip-mmt-si-message-header-len32 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-id 0 \
    --expect-mmt-si-message-version 1 \
    --expect-mmt-si-message-version 1 \
    --expect-mmt-si-message-version 1 \
    --expect-mmt-si-message-version 1 \
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

payloads="${saved_payloads_ado}"


adp_payload="010004200100232001001f00000000010000000000010100000000000101000000000000000000000000"
adp_payloads="${adp_payload},${adp_payload},${adp_payload},${adp_payload}"
saved_payloads_adp="${payloads}"
payloads="${adp_payloads}"

echo "[mmtp_word0_integ] phase ADP: consumption (message_id=0) + PA + MPT asset (ZW ingress)"
run_phase "ADP" "${port_adp}" "${tmpdir}/adp.out" "${tmpdir}/gw_adp.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id8-location-ipv4
"${probe_bin}" verify \
    --file "${tmpdir}/adp.out.shard0" \
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
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 0 \
    --expected-payloads "${zw_payloads}"

payloads="${saved_payloads_adp}"

adq_payload="0100042001003b2001003700000000010000000000010100000000000102000000000000000000000000000000000000000000000000000000000000000000000000"
adq_payloads="${adq_payload},${adq_payload},${adq_payload},${adq_payload}"
saved_payloads_adq="${payloads}"
payloads="${adq_payloads}"

echo "[mmtp_word0_integ] phase ADQ: consumption (message_id=0) + PA + MPT asset (AAA ingress)"
run_phase "ADQ" "${port_adq}" "${tmpdir}/adq.out" "${tmpdir}/gw_adq.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id8-location-ipv6
"${probe_bin}" verify \
    --file "${tmpdir}/adq.out.shard0" \
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
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 0 \
    --expected-payloads "${aaa_payloads}"

payloads="${saved_payloads_adq}"

adr_payload="0100042001003a2001003600000000010000000000000000000000010200000000000000000000ffff0a00000100000000000000000000ffffe000000113880000"
adr_payloads="${adr_payload},${adr_payload},${adr_payload},${adr_payload}"
saved_payloads_adr="${payloads}"
payloads="${adr_payloads}"

echo "[mmtp_word0_integ] phase ADR: consumption (message_id=0) + PA + MPT asset (AAH ingress)"
run_phase "ADR" "${port_adr}" "${tmpdir}/adr.out" "${tmpdir}/gw_adr.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-location-ipv6-nz
"${probe_bin}" verify \
    --file "${tmpdir}/adr.out.shard0" \
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
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
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
    --expected-payloads "${aah_payloads}"

payloads="${saved_payloads_adr}"

ads_payload="010004200100232001001f000000000100000000000101000000000001010a000001e000000113880000"
ads_payloads="${ads_payload},${ads_payload},${ads_payload},${ads_payload}"
saved_payloads_ads="${payloads}"
payloads="${ads_payloads}"

echo "[mmtp_word0_integ] phase ADS: consumption (message_id=0) + PA + MPT asset (AAM ingress)"
run_phase "ADS" "${port_ads}" "${tmpdir}/ads.out" "${tmpdir}/gw_ads.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id8-location-ipv4-nz
"${probe_bin}" verify \
    --file "${tmpdir}/ads.out.shard0" \
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
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
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
    --expected-payloads "${aam_payloads}"

payloads="${saved_payloads_ads}"

adt_payload="0100042001003b200100370000000001000000000001010000000000010200000000000000000000ffff0a00000100000000000000000000ffffe000000113880000"
adt_payloads="${adt_payload},${adt_payload},${adt_payload},${adt_payload}"
saved_payloads_adt="${payloads}"
payloads="${adt_payloads}"

echo "[mmtp_word0_integ] phase ADT: consumption (message_id=0) + PA + MPT asset (AAN ingress)"
run_phase "ADT" "${port_adt}" "${tmpdir}/adt.out" "${tmpdir}/gw_adt.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id8-location-ipv6-nz
"${probe_bin}" verify \
    --file "${tmpdir}/adt.out.shard0" \
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
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
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
    --expected-payloads "${aan_payloads}"

payloads="${saved_payloads_adt}"

adu_payload="01000420010024200100200000000001000000000002010200000000000101000000000000000000000000"
adu_payloads="${adu_payload},${adu_payload},${adu_payload},${adu_payload}"
saved_payloads_adu="${payloads}"
payloads="${adu_payloads}"

echo "[mmtp_word0_integ] phase ADU: consumption (message_id=0) + PA + MPT asset (AAO ingress)"
run_phase "ADU" "${port_adu}" "${tmpdir}/adu.out" "${tmpdir}/gw_adu.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id16-location-ipv4
"${probe_bin}" verify \
    --file "${tmpdir}/adu.out.shard0" \
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
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-location-type 1 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv4-dst-port 0 \
    --expected-payloads "${aao_payloads}"

payloads="${saved_payloads_adu}"

adv_payload="010004200100242001002000000000010000000000020102000000000001010a000001e000000113880000"
adv_payloads="${adv_payload},${adv_payload},${adv_payload},${adv_payload}"
saved_payloads_adv="${payloads}"
payloads="${adv_payloads}"

echo "[mmtp_word0_integ] phase ADV: consumption (message_id=0) + PA + MPT asset (AAP ingress)"
run_phase "ADV" "${port_adv}" "${tmpdir}/adv.out" "${tmpdir}/gw_adv.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id16-location-ipv4-nz
"${probe_bin}" verify \
    --file "${tmpdir}/adv.out.shard0" \
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
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
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
    --expected-payloads "${aap_payloads}"

payloads="${saved_payloads_adv}"

adw_payload="0100042001003b2001003700000000010000000000020102000000000001020000000000000000000000000000000000000000000000000000000000000000000000"
adw_payloads="${adw_payload},${adw_payload},${adw_payload},${adw_payload}"
saved_payloads_adw="${payloads}"
payloads="${adw_payloads}"

echo "[mmtp_word0_integ] phase ADW: consumption (message_id=0) + PA + MPT asset (AAQ ingress)"
run_phase "ADW" "${port_adw}" "${tmpdir}/adw.out" "${tmpdir}/gw_adw.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id16-location-ipv6
"${probe_bin}" verify \
    --file "${tmpdir}/adw.out.shard0" \
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
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-location-count 1 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-location-type 2 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 0 \
    --expected-payloads "${aaq_payloads}"

payloads="${saved_payloads_adw}"


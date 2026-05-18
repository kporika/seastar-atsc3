adx_payload="0100042001003c20010038000000000100000000000201020000000000010200000000000000000000ffff0a00000100000000000000000000ffffe000000113880000"
adx_payloads="${adx_payload},${adx_payload},${adx_payload},${adx_payload}"
saved_payloads_adx="${payloads}"
payloads="${adx_payloads}"

echo "[mmtp_word0_integ] phase ADX: consumption (message_id=0) + PA + MPT asset (AAR ingress)"
run_phase "ADX" "${port_adx}" "${tmpdir}/adx.out" "${tmpdir}/gw_adx.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id16-location-ipv6-nz
"${probe_bin}" verify \
    --file "${tmpdir}/adx.out.shard0" \
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
    --expected-payloads "${aar_payloads}"

payloads="${saved_payloads_adx}"

ady_payload="0100042001001d20010019000000000100000000000201020000000000000004deadbeef"
ady_payloads="${ady_payload},${ady_payload},${ady_payload},${ady_payload}"
saved_payloads_ady="${payloads}"
payloads="${ady_payloads}"

echo "[mmtp_word0_integ] phase ADY: consumption (message_id=0) + PA + MPT asset (AAS ingress)"
run_phase "ADY" "${port_ady}" "${tmpdir}/ady.out" "${tmpdir}/gw_ady.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id16-descriptors4
"${probe_bin}" verify \
    --file "${tmpdir}/ady.out.shard0" \
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
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 4 \
    --expect-mmt-si-mpt-asset-descriptors-length 4 \
    --expect-mmt-si-mpt-asset-descriptors-length 4 \
    --expect-mmt-si-mpt-asset-descriptors-length 4 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte0 1 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expect-mmt-si-mpt-asset-id16-byte1 2 \
    --expected-payloads "${aas_payloads}"

payloads="${saved_payloads_ady}"

adz_payload="0100042001001c200100180000000001000000000001010000000000000004deadbeef"
adz_payloads="${adz_payload},${adz_payload},${adz_payload},${adz_payload}"
saved_payloads_adz="${payloads}"
payloads="${adz_payloads}"

echo "[mmtp_word0_integ] phase ADZ: consumption (message_id=0) + PA + MPT asset (AAT ingress)"
run_phase "ADZ" "${port_adz}" "${tmpdir}/adz.out" "${tmpdir}/gw_adz.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id8-descriptors4
"${probe_bin}" verify \
    --file "${tmpdir}/adz.out.shard0" \
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

payloads="${saved_payloads_adz}"
aea_payload="0100048000002a800000260100000200000000000000000000ffff0a00000100000000000000000000ffffe00000011388"
aea_payloads="${aea_payload},${aea_payload},${aea_payload},${aea_payload}"
saved_payloads_aea="${payloads}"
payloads="${aea_payloads}"

echo "[mmtp_word0_integ] phase AEA: consumption (message_id=0) + PA + PLT (AAJ ingress)"
run_phase "AEA" "${port_aea}" "${tmpdir}/aea.out" "${tmpdir}/gw_aea.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-package-entry-ipv6-nz
"${probe_bin}" verify \
    --file "${tmpdir}/aea.out.shard0" \
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

payloads="${saved_payloads_aea}"


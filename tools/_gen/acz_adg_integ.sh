acz_payload="0100048000000d80000009000100000000000000"
acz_payloads="${acz_payload},${acz_payload},${acz_payload},${acz_payload}"
saved_payloads_acz="${payloads}"
payloads="${acz_payloads}"

echo "[mmtp_word0_integ] phase ACZ: consumption (message_id=0) + PA + PLT (ZL ingress)"
run_phase "ACZ" "${port_acz}" "${tmpdir}/acz.out" "${tmpdir}/gw_acz.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-delivery-info
"${probe_bin}" verify \
    --file "${tmpdir}/acz.out.shard0" \
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

payloads="${saved_payloads_acz}"

ada_payload="0100048000000a80000006010000000000"
ada_payloads="${ada_payload},${ada_payload},${ada_payload},${ada_payload}"
saved_payloads_ada="${payloads}"
payloads="${ada_payloads}"

echo "[mmtp_word0_integ] phase ADA: consumption (message_id=0) + PA + PLT (ZP ingress)"
run_phase "ADA" "${port_ada}" "${tmpdir}/ada.out" "${tmpdir}/gw_ada.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-package-entry
"${probe_bin}" verify \
    --file "${tmpdir}/ada.out.shard0" \
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

payloads="${saved_payloads_ada}"

adb_payload="010004800000178000001300010000000001000000000000000000000000"
adb_payloads="${adb_payload},${adb_payload},${adb_payload},${adb_payload}"
saved_payloads_adb="${payloads}"
payloads="${adb_payloads}"

echo "[mmtp_word0_integ] phase ADB: consumption (message_id=0) + PA + PLT (ZM ingress)"
run_phase "ADB" "${port_adb}" "${tmpdir}/adb.out" "${tmpdir}/gw_adb.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-delivery-info-ipv4
"${probe_bin}" verify \
    --file "${tmpdir}/adb.out.shard0" \
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
    --expected-payloads "${zm_payloads}"

payloads="${saved_payloads_adb}"

adc_payload="0100048000002f8000002b00010000000002000000000000000000000000000000000000000000000000000000000000000000000000"
adc_payloads="${adc_payload},${adc_payload},${adc_payload},${adc_payload}"
saved_payloads_adc="${payloads}"
payloads="${adc_payloads}"

echo "[mmtp_word0_integ] phase ADC: consumption (message_id=0) + PA + PLT (ZN ingress)"
run_phase "ADC" "${port_adc}" "${tmpdir}/adc.out" "${tmpdir}/gw_adc.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-delivery-info-ipv6
"${probe_bin}" verify \
    --file "${tmpdir}/adc.out.shard0" \
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
    --expected-payloads "${zn_payloads}"

payloads="${saved_payloads_adc}"

add_payload="0100048000000e8000000a00010000000005000000"
add_payloads="${add_payload},${add_payload},${add_payload},${add_payload}"
saved_payloads_add="${payloads}"
payloads="${add_payloads}"

echo "[mmtp_word0_integ] phase ADD: consumption (message_id=0) + PA + PLT (ZO ingress)"
run_phase "ADD" "${port_add}" "${tmpdir}/add.out" "${tmpdir}/gw_add.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-delivery-info-url
"${probe_bin}" verify \
    --file "${tmpdir}/add.out.shard0" \
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
    --expected-payloads "${zo_payloads}"

payloads="${saved_payloads_add}"

ade_payload="0100048000000b8000000701000101000000"
ade_payloads="${ade_payload},${ade_payload},${ade_payload},${ade_payload}"
saved_payloads_ade="${payloads}"
payloads="${ade_payloads}"

echo "[mmtp_word0_integ] phase ADE: consumption (message_id=0) + PA + PLT (ZR ingress)"
run_phase "ADE" "${port_ade}" "${tmpdir}/ade.out" "${tmpdir}/gw_ade.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-package-entry-id8
"${probe_bin}" verify \
    --file "${tmpdir}/ade.out.shard0" \
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

payloads="${saved_payloads_ade}"

adf_payload="010004800000128000000e0100000100000000000000000000"
adf_payloads="${adf_payload},${adf_payload},${adf_payload},${adf_payload}"
saved_payloads_adf="${payloads}"
payloads="${adf_payloads}"

echo "[mmtp_word0_integ] phase ADF: consumption (message_id=0) + PA + PLT (ZU ingress)"
run_phase "ADF" "${port_adf}" "${tmpdir}/adf.out" "${tmpdir}/gw_adf.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-package-entry-ipv4
"${probe_bin}" verify \
    --file "${tmpdir}/adf.out.shard0" \
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
    --expect-mmt-si-plt-package-packet-id 0 \
    --expect-mmt-si-plt-package-packet-id 0 \
    --expect-mmt-si-plt-package-packet-id 0 \
    --expect-mmt-si-plt-package-packet-id 0 \
    --expected-payloads "${zu_payloads}"

payloads="${saved_payloads_adf}"

adg_payload="0100048000001780000013000100000000010a000001e000000113880000"
adg_payloads="${adg_payload},${adg_payload},${adg_payload},${adg_payload}"
saved_payloads_adg="${payloads}"
payloads="${adg_payloads}"

echo "[mmtp_word0_integ] phase ADG: consumption (message_id=0) + PA + PLT (AAE ingress)"
run_phase "ADG" "${port_adg}" "${tmpdir}/adg.out" "${tmpdir}/gw_adg.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-plt-table-body \
    --validate-mmt-si-plt-delivery-info-ipv4-nz
"${probe_bin}" verify \
    --file "${tmpdir}/adg.out.shard0" \
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
    --expected-payloads "${aae_payloads}"

payloads="${saved_payloads_adg}"


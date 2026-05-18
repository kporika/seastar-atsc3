acr_payload="010004200100172001001300000000010000000000000000000000000000"
acr_payloads="${acr_payload},${acr_payload},${acr_payload},${acr_payload}"
saved_payloads_acr="${payloads}"
payloads="${acr_payloads}"

echo "[mmtp_word0_integ] phase ACR: consumption (message_id=0) + PA + MPT asset (ZK ingress)"
run_phase "ACR" "${port_acr}" "${tmpdir}/acr.out" "${tmpdir}/gw_acr.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset
"${probe_bin}" verify \
    --file "${tmpdir}/acr.out.shard0" \
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

payloads="${saved_payloads_acr}"

acs_payload="01000420010018200100140000000001000000000001010000000000000000"
acs_payloads="${acs_payload},${acs_payload},${acs_payload},${acs_payload}"
saved_payloads_acs="${payloads}"
payloads="${acs_payloads}"

echo "[mmtp_word0_integ] phase ACS: consumption (message_id=0) + PA + MPT asset (ZS ingress)"
run_phase "ACS" "${port_acs}" "${tmpdir}/acs.out" "${tmpdir}/gw_acs.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id8
"${probe_bin}" verify \
    --file "${tmpdir}/acs.out.shard0" \
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

payloads="${saved_payloads_acs}"

act_payload="0100042001001b2001001700000000010000000000000000000000000004DEADBEEF"
act_payloads="${act_payload},${act_payload},${act_payload},${act_payload}"
saved_payloads_act="${payloads}"
payloads="${act_payloads}"

echo "[mmtp_word0_integ] phase ACT: consumption (message_id=0) + PA + MPT asset (AAC ingress)"
run_phase "ACT" "${port_act}" "${tmpdir}/act.out" "${tmpdir}/gw_act.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-descriptors4
"${probe_bin}" verify \
    --file "${tmpdir}/act.out.shard0" \
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

payloads="${saved_payloads_act}"

acu_payload="0100042001001a2001001600000000010000000000000000000000010000000000"
acu_payloads="${acu_payload},${acu_payload},${acu_payload},${acu_payload}"
saved_payloads_acu="${payloads}"
payloads="${acu_payloads}"

echo "[mmtp_word0_integ] phase ACU: consumption (message_id=0) + PA + MPT asset (ZT ingress)"
run_phase "ACU" "${port_acu}" "${tmpdir}/acu.out" "${tmpdir}/gw_acu.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-location0
"${probe_bin}" verify \
    --file "${tmpdir}/acu.out.shard0" \
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
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-descriptors-length 0 \
    --expect-mmt-si-mpt-asset-location-type 0 \
    --expect-mmt-si-mpt-asset-location-type 0 \
    --expect-mmt-si-mpt-asset-location-type 0 \
    --expect-mmt-si-mpt-asset-location-type 0 \
    --expect-mmt-si-mpt-asset-packet-id 0 \
    --expect-mmt-si-mpt-asset-packet-id 0 \
    --expect-mmt-si-mpt-asset-packet-id 0 \
    --expect-mmt-si-mpt-asset-packet-id 0 \
    --expected-payloads "${zt_payloads}"

payloads="${saved_payloads_acu}"

acv_payload="010004200100222001001e000000000100000000000000000000000101000000000000000000000000"
acv_payloads="${acv_payload},${acv_payload},${acv_payload},${acv_payload}"
saved_payloads_acv="${payloads}"
payloads="${acv_payloads}"

echo "[mmtp_word0_integ] phase ACV: consumption (message_id=0) + PA + MPT asset (ZV ingress)"
run_phase "ACV" "${port_acv}" "${tmpdir}/acv.out" "${tmpdir}/gw_acv.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-location-ipv4
"${probe_bin}" verify \
    --file "${tmpdir}/acv.out.shard0" \
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
    --expected-payloads "${zv_payloads}"

payloads="${saved_payloads_acv}"

acw_payload="0100042001003a20010036000000000100000000000000000000000102000000000000000000000000000000000000000000000000000000000000000000000000"
acw_payloads="${acw_payload},${acw_payload},${acw_payload},${acw_payload}"
saved_payloads_acw="${payloads}"
payloads="${acw_payloads}"

echo "[mmtp_word0_integ] phase ACW: consumption (message_id=0) + PA + MPT asset (ZY ingress)"
run_phase "ACW" "${port_acw}" "${tmpdir}/acw.out" "${tmpdir}/gw_acw.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-location-ipv6
"${probe_bin}" verify \
    --file "${tmpdir}/acw.out.shard0" \
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
    --expect-mmt-si-mpt-asset-ipv6-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 0 \
    --expect-mmt-si-mpt-asset-ipv6-dst-port 0 \
    --expected-payloads "${zy_payloads}"

payloads="${saved_payloads_acw}"

acx_payload="0100042001001920010015000000000100000000000201020000000000000000"
acx_payloads="${acx_payload},${acx_payload},${acx_payload},${acx_payload}"
saved_payloads_acx="${payloads}"
payloads="${acx_payloads}"

echo "[mmtp_word0_integ] phase ACX: consumption (message_id=0) + PA + MPT asset (AAG ingress)"
run_phase "ACX" "${port_acx}" "${tmpdir}/acx.out" "${tmpdir}/gw_acx.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-id16
"${probe_bin}" verify \
    --file "${tmpdir}/acx.out.shard0" \
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
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-location-count 0 \
    --expect-mmt-si-mpt-asset-location-count 0 \
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
    --expected-payloads "${aag_payloads}"

payloads="${saved_payloads_acx}"

acy_payload="010004200100222001001e0000000001000000000000000000000001010a000001e000000113880000"
acy_payloads="${acy_payload},${acy_payload},${acy_payload},${acy_payload}"
saved_payloads_acy="${payloads}"
payloads="${acy_payloads}"

echo "[mmtp_word0_integ] phase ACY: consumption (message_id=0) + PA + MPT asset (AAF ingress)"
run_phase "ACY" "${port_acy}" "${tmpdir}/acy.out" "${tmpdir}/gw_acy.log" \
    --prepend-mmtp-word0 \
    --mmtp-payload-type "${mmtp_pt}" \
    --mmtp-packet-id "${mmtp_pid}" \
    --prepend-mmtp-signalling-prefix \
    --prepend-mmt-si-message-header-len32 \
    --mmtp-si-message-id 0 \
    --mmtp-si-message-version 1 \
    --validate-mmt-si-mpt-table-body \
    --validate-mmt-si-mpt-asset-location-ipv4-nz
"${probe_bin}" verify \
    --file "${tmpdir}/acy.out.shard0" \
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
    --expected-payloads "${aaf_payloads}"

payloads="${saved_payloads_acy}"


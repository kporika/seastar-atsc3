#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# RTCM-flavoured end-to-end integration test for atsc3_gw.
#
#   rtcm-gen ──► .rtcm file
#       │
#       ▼
#   atsc3_gw (file:// sink, encoder_pipeline)
#       ▲
#       │
#   mmt_probe send --rtcm-file
#       │
#       ▼
#   sink file (TLV-mux/ALP packets)
#       │
#       ▼
#   mmt_probe verify --file --validate-rtcm
#       │
#       ▼
#   PASS/FAIL
#
# Usage: scripts/rtcm_integration_test.sh [BUILD_DIR] [FRAMES] [PAYLOAD_BYTES]

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${script_dir}/_lib.sh"

repo_root="$(cd "${script_dir}/.." && pwd)"
build_dir="${1:-$(detect_default_build_dir "${repo_root}")}"
frames="${2:-32}"
payload_bytes="${3:-128}"

gw_bin="$(resolve_bin "${ATSC3_GW:-}"  "${build_dir}/gw/atsc3_gw"          atsc3_gw)"
probe_bin="$(resolve_bin "${MMT_PROBE:-}" "${build_dir}/mmt_probe/mmt_probe" mmt_probe)"

port=$(( ( RANDOM % 10000 ) + 19000 ))
addr="127.0.0.1:${port}"

tmpdir="$(mktemp -d -t atsc3_rtcm.XXXXXX)"
rtcm_file="${tmpdir}/test.rtcm"
sink_prefix="${tmpdir}/gw.out"
log_file="${tmpdir}/gw.log"

cleanup() {
    if [[ -n "${gw_pid:-}" ]] && kill -0 "${gw_pid}" 2>/dev/null; then
        kill "${gw_pid}" 2>/dev/null || true
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            kill -0 "${gw_pid}" 2>/dev/null || break
            sleep 0.1
        done
        kill -9 "${gw_pid}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "[rtcm-integ] generating ${frames} RTCM frames (${payload_bytes}B each) -> ${rtcm_file}"
"${probe_bin}" rtcm-gen \
    --out "${rtcm_file}" \
    --frames "${frames}" \
    --payload-bytes "${payload_bytes}" \
    --msg-type 1077 \
    --seed 0xC0FFEE

echo "[rtcm-integ] starting atsc3_gw on ${addr} (smp=1, sink=file://${sink_prefix})"
"${gw_bin}" --smp 1 \
    --ingress "${addr}" \
    --sink "file://${sink_prefix}" \
    >"${log_file}" 2>&1 &
gw_pid=$!

# Wait for the listener to bind.
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if (echo > /dev/tcp/127.0.0.1/${port}) >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
    if ! kill -0 "${gw_pid}" 2>/dev/null; then
        echo "[rtcm-integ] gw exited early; log:" >&2
        cat "${log_file}" >&2
        exit 1
    fi
done

echo "[rtcm-integ] sending RTCM frames"
"${probe_bin}" send \
    --target "${addr}" \
    --rtcm-file "${rtcm_file}"

# Stop the gw cleanly so the file sink flushes via at_exit().
echo "[rtcm-integ] stopping gw (pid=${gw_pid})"
kill "${gw_pid}" 2>/dev/null || true
wait "${gw_pid}" 2>/dev/null || true
unset gw_pid

sink_file="${sink_prefix}.shard0"

echo "[rtcm-integ] verifying ${sink_file} (CRC-validate inner RTCM frames)"
"${probe_bin}" verify \
    --file "${sink_file}" \
    --validate-rtcm

# Cross-check by also matching exact payload bytes. Build the
# --expected-payloads list by chunking the .rtcm file into its constituent
# frames in a single Python one-liner — no external tool dependencies.
echo "[rtcm-integ] verifying exact-byte equality vs source frames"
expected="$(python3 - "${rtcm_file}" <<'EOF'
import sys, pathlib
data = pathlib.Path(sys.argv[1]).read_bytes()
out = []
i = 0
while i < len(data):
    if data[i] != 0xD3:
        sys.exit(f"unexpected byte 0x{data[i]:02X} at offset {i}")
    plen = ((data[i+1] & 0x03) << 8) | data[i+2]
    total = 3 + plen + 3
    out.append(data[i:i+total].hex().upper())
    i += total
print(",".join(out))
EOF
)"

"${probe_bin}" verify \
    --file "${sink_file}" \
    --validate-rtcm \
    --expected-payloads "${expected}"

echo "[rtcm-integ] PASS"

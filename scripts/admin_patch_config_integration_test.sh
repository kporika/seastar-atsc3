#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Integration: atsc3_gw with --admin-http; POST /config/sink toggles sink_uri
# (file://… ↔ null://) and verifies JSON responses via Python urllib.
#
# Usage:
#   scripts/admin_patch_config_integration_test.sh [BUILD_DIR]

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${script_dir}/_lib.sh"

repo_root="$(cd "${script_dir}/.." && pwd)"
build_dir="${1:-${repo_root}/build}"

gw_bin="$(resolve_bin "${ATSC3_GW:-}" "${build_dir}/gw/atsc3_gw" atsc3_gw)"
echo "[integ-admin] gw=${gw_bin}"

ingress_port=$(( ( RANDOM % 10000 ) + 19000 ))
admin_port=$((ingress_port + 1))
while [[ "${admin_port}" -eq "${ingress_port}" ]]; do
    admin_port=$((admin_port + 1))
done

ingress_addr="127.0.0.1:${ingress_port}"
admin_addr="127.0.0.1:${admin_port}"

tmpdir="$(mktemp -d -t atsc3_admin_integ.XXXXXX)"
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

echo "[integ-admin] starting gw ingress=${ingress_addr} admin=${admin_addr}"
"${gw_bin}" --smp 1 \
    --ingress "${ingress_addr}" \
    --sink "file://${sink_prefix}" \
    --admin-http "${admin_addr}" \
    >"${log_file}" 2>&1 &
gw_pid=$!

wait_tcp() {
    local host="$1"
    local port="$2"
    local label="$3"
    local i
    for i in $(seq 1 80); do
        if (echo >"/dev/tcp/${host}/${port}") >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.05
        if ! kill -0 "${gw_pid}" 2>/dev/null; then
            echo "[integ-admin] gw exited early (${label}); log:" >&2
            cat "${log_file}" >&2
            exit 1
        fi
    done
    echo "[integ-admin] timeout waiting for ${label} ${host}:${port}" >&2
    exit 1
}

wait_tcp 127.0.0.1 "${ingress_port}" "ingress"
wait_tcp 127.0.0.1 "${admin_port}" "admin"

export ADMIN_HTTP_ADDR="${admin_addr}"
export ORIG_SINK_URI="file://${sink_prefix}"

python3 - <<'PY'
import http.client
import json
import os
import sys
from typing import Dict, Optional

orig = os.environ["ORIG_SINK_URI"]


def http_json(method: str, path: str, body: Optional[Dict[str, object]] = None):
    host, port_s = os.environ["ADMIN_HTTP_ADDR"].split(":", 1)
    port = int(port_s)
    conn = http.client.HTTPConnection(host, port, timeout=10)
    payload = None
    hdr = {}
    if body is not None:
        payload = json.dumps(body).encode("utf-8")
        hdr["Content-Type"] = "application/json"
        hdr["Content-Length"] = str(len(payload))
    conn.request(method, path, body=payload, headers=hdr)
    resp = conn.getresponse()
    raw = resp.read().decode("utf-8")
    conn.close()
    try:
        parsed = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        parsed = {"_raw": raw}
    return resp.status, parsed


st, cfg = http_json("GET", "/config")
if st != 200:
    print("GET /config failed", st, cfg, file=sys.stderr)
    sys.exit(1)
if cfg.get("sink_uri") != orig:
    print("unexpected initial sink_uri", cfg, file=sys.stderr)
    sys.exit(1)

st, cfg2 = http_json("POST", "/config/sink", {"sink_uri": "null://"})
if st != 200:
    print("POST /config/sink null failed", st, cfg2, file=sys.stderr)
    sys.exit(1)
if cfg2.get("sink_uri") != "null://":
    print("expected null:// after POST /config/sink", cfg2, file=sys.stderr)
    sys.exit(1)

st, bad = http_json("POST", "/config/sink", {"sink_uri": "null://", "ingress": "x"})
if st != 400:
    print("expected 400 for extra keys", st, bad, file=sys.stderr)
    sys.exit(1)

st, cfg3 = http_json("POST", "/config/sink", {"sink_uri": orig})
if st != 200:
    print("POST /config/sink restore failed", st, cfg3, file=sys.stderr)
    sys.exit(1)
if cfg3.get("sink_uri") != orig:
    print("restore mismatch", cfg3, file=sys.stderr)
    sys.exit(1)

print("[integ-admin] POST /config/sink hot-swap: OK")
PY

echo "[integ-admin] PASS"

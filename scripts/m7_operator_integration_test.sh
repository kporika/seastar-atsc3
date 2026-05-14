#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# M7: per-service sink routing, schema v2 persistence, optional bearer auth.
#
# Usage:
#   scripts/m7_operator_integration_test.sh [BUILD_DIR]

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${script_dir}/_lib.sh"

repo_root="$(cd "${script_dir}/.." && pwd)"
build_dir="${1:-$(detect_default_build_dir "${repo_root}")}"

gw_bin="$(resolve_bin "${ATSC3_GW:-}" "${build_dir}/gw/atsc3_gw" atsc3_gw)"
echo "[m7] gw=${gw_bin}"

ingress_port=$(( ( RANDOM % 10000 ) + 20000 ))
admin_port=$((ingress_port + 1))
svc_state="$(mktemp -t atsc3_m7_services.XXXXXX)"
main_out="$(mktemp -t atsc3_m7_main.XXXXXX)"
svc_out="$(mktemp -t atsc3_m7_svc.XXXXXX)"
log_file="$(mktemp -t atsc3_m7_gw.XXXXXX)"
cleanup() {
    if [[ -n "${gw_pid:-}" ]] && kill -0 "${gw_pid}" 2>/dev/null; then
        kill "${gw_pid}" 2>/dev/null || true
        sleep 0.2
        kill -9 "${gw_pid}" 2>/dev/null || true
    fi
    rm -f "${svc_state}" "${main_out}" "${svc_out}" "${log_file}"
}
trap cleanup EXIT

ingress_addr="127.0.0.1:${ingress_port}"
admin_addr="127.0.0.1:${admin_port}"

echo "[m7] start gw ingress=${ingress_addr} admin=${admin_addr}"
"${gw_bin}" --smp 1 \
    --ingress "${ingress_addr}" \
    --sink "file://${main_out}" \
    --services-state-file "${svc_state}" \
    --admin-http "${admin_addr}" \
    --admin-bearer-token "integ-token" \
    >"${log_file}" 2>&1 &
gw_pid=$!

wait_tcp() {
    local host="$1" port="$2" label="$3"
    local i
    for i in $(seq 1 80); do
        if (echo >"/dev/tcp/${host}/${port}") >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.05
        if ! kill -0 "${gw_pid}" 2>/dev/null; then
            echo "[m7] gw exited (${label}); log:" >&2
            cat "${log_file}" >&2
            exit 1
        fi
    done
    echo "[m7] timeout ${label}" >&2
    exit 1
}

wait_tcp 127.0.0.1 "${ingress_port}" "ingress"
wait_tcp 127.0.0.1 "${admin_port}" "admin"

export ADMIN_HTTP_ADDR="${admin_addr}"
export M7_MAIN_OUT="${main_out}"
export M7_SVC_OUT="${svc_out}"
export M7_SVC_STATE="${svc_state}"
export GW_PID="${gw_pid}"

python3 - <<'PY'
import http.client
import json
import os
import signal
import time
from typing import Any, Dict, Optional, Tuple

addr = os.environ["ADMIN_HTTP_ADDR"]
host, port_s = addr.split(":", 1)
port = int(port_s)


def req(
    method: str, path: str, body: Optional[Dict[str, Any]], auth: bool
) -> Tuple[int, Dict[str, Any]]:
    c = http.client.HTTPConnection(host, port, timeout=15)
    h = {}
    if body is not None:
        blob = json.dumps(body).encode("utf-8")
        h["Content-Type"] = "application/json"
        h["Content-Length"] = str(len(blob))
        payload = blob
    else:
        payload = None
        if method in ("PATCH", "POST", "DELETE", "PUT"):
            h["Content-Length"] = "0"
    if auth:
        h["Authorization"] = "Bearer integ-token"
    c.request(method, path, body=payload, headers=h)
    r = c.getresponse()
    raw = r.read().decode("utf-8")
    c.close()
    try:
        j = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        j = {"_raw": raw}
    return r.status, j


def file_shard_path(prefix: str) -> str:
    # file:// sinks use <path>.shardN per shard (see make_file_sink); --smp 1 ⇒ .shard0.
    return prefix + ".shard0"


svc_out = os.environ["M7_SVC_OUT"]
main_out = os.environ["M7_MAIN_OUT"]
svc_file = file_shard_path(svc_out)
main_file = file_shard_path(main_out)

code, js = req("POST", "/services", {"name": "m7-route", "sink_uri": "file://" + svc_out}, False)
assert code == 401, (code, js)

code, js = req("POST", "/services", {"name": "m7-route", "sink_uri": "file://" + svc_out}, True)
assert code == 201, (code, js)
sid = int(js["id"])
assert sid >= 1

code, cfg = req("GET", "/config", None, False)
assert code == 200
assert cfg.get("admin", {}).get("bearer_auth_required") is True

payload = {"service_id": sid, "type": "raw", "payload_b64": "AABb"}
code, jr = req("POST", "/ingest", payload, True)
assert code == 202, (code, jr)

code, jr = req("PATCH", f"/services?id={sid}", {"sink_uri": None}, True)
assert code == 200, (code, jr)

code, jr = req("POST", "/ingest", payload, True)
assert code == 202, (code, jr)

gw_pid = int(os.environ["GW_PID"])
try:
    os.kill(gw_pid, signal.SIGTERM)
except ProcessLookupError:
    pass
for _ in range(200):
    try:
        os.kill(gw_pid, 0)
    except ProcessLookupError:
        break
    time.sleep(0.05)
else:
    raise RuntimeError("gw did not exit after SIGTERM")

with open(svc_file, "rb") as f:
    svc_blob = f.read()
assert len(svc_blob) > 0, "per-service sink should receive TLV-mux output"

with open(main_file, "rb") as f:
    main_blob = f.read()
assert len(main_blob) > 0, "default sink should receive TLV-mux after clearing per-service routing"

with open(os.environ["M7_SVC_STATE"]) as sf:
    st = json.load(sf)
assert st.get("schema_version") == 2
svc_row = next(x for x in st["services"] if x["id"] == sid)
assert not svc_row.get("sink_uri")

print("[m7] operator routing + auth + persistence: OK")

PY

echo "[m7] PASS"

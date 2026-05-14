#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# Minimal operator CLI for atsc3_gw --admin-http (M7 control plane).
# Python 3.9+ stdlib only: http.client + json.
#
#   export ATSC3_ADMIN=http://127.0.0.1:8080   # optional; else pass --base
#   ./tools/atsc3ctl.py config get
#   ./tools/atsc3ctl.py config set-sink null://
#   ./tools/atsc3ctl.py services list
#   ./tools/atsc3ctl.py services add demo-svc
#   ./tools/atsc3ctl.py services delete 1
#   ./tools/atsc3ctl.py health
#   ./tools/atsc3ctl.py metrics
#   ./tools/atsc3ctl.py ingest raw --file payload.bin
#   ./tools/atsc3ctl.py ingest raw --b64 aGk=

from __future__ import annotations

import argparse
import base64
import binascii
import http.client
import json
import os
import sys
import urllib.parse
from typing import Any, Dict, Optional, Tuple


def normalize_base(url: str) -> str:
    u = url.strip().rstrip("/")
    if not u:
        raise SystemExit("admin base URL is empty (set ATSC3_ADMIN or use --base)")
    if "://" not in u:
        u = "http://" + u
    return u


def http_request(
    base: str,
    method: str,
    path: str,
    body: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[int, bytes]:
    b = normalize_base(base)
    p = urllib.parse.urlparse(b)
    if p.scheme not in ("http", "https"):
        raise SystemExit(f"unsupported URL scheme: {p.scheme!r}")
    host = p.hostname
    if not host:
        raise SystemExit(f"invalid admin URL: {b!r}")
    port = p.port or (443 if p.scheme == "https" else 80)
    conn_cls = (
        http.client.HTTPSConnection
        if p.scheme == "https"
        else http.client.HTTPConnection
    )
    h = dict(headers or {})
    if body is not None:
        h.setdefault("Content-Type", "application/json")
        h["Content-Length"] = str(len(body))
    conn = conn_cls(host, port, timeout=30)
    try:
        conn.request(method, path, body=body, headers=h)
        resp = conn.getresponse()
        raw = resp.read()
        code = resp.status
    finally:
        conn.close()
    return code, raw


def print_json(raw: bytes) -> None:
    if not raw:
        print("{}")
        return
    try:
        obj = json.loads(raw.decode("utf-8"))
        print(json.dumps(obj, indent=2, sort_keys=True))
    except json.JSONDecodeError:
        sys.stdout.buffer.write(raw)
        if not raw.endswith(b"\n"):
            print()


def cmd_config_get(ns: argparse.Namespace) -> int:
    code, raw = http_request(ns.base, "GET", "/config")
    print_json(raw)
    return 0 if code == 200 else code


def cmd_config_set_sink(ns: argparse.Namespace) -> int:
    payload = json.dumps({"sink_uri": ns.uri}).encode("utf-8")
    code, raw = http_request(ns.base, "POST", "/config/sink", body=payload)
    print_json(raw)
    return 0 if code == 200 else code


def cmd_services_list(ns: argparse.Namespace) -> int:
    code, raw = http_request(ns.base, "GET", "/services")
    print_json(raw)
    return 0 if code == 200 else code


def cmd_services_add(ns: argparse.Namespace) -> int:
    payload = json.dumps({"name": ns.name}).encode("utf-8")
    code, raw = http_request(ns.base, "POST", "/services", body=payload)
    print_json(raw)
    return 0 if code in (200, 201) else code


def cmd_services_delete(ns: argparse.Namespace) -> int:
    path = f"/services?id={ns.id}"
    code, raw = http_request(ns.base, "DELETE", path)
    print_json(raw)
    return 0 if code == 200 else code


def cmd_health(ns: argparse.Namespace) -> int:
    for path in ("/healthz", "/readyz"):
        code, raw = http_request(ns.base, "GET", path, headers={"Accept": "text/plain"})
        print(f"=== {path} ({code}) ===")
        sys.stdout.buffer.write(raw)
        if raw and not raw.endswith(b"\n"):
            print()
    return 0


def cmd_metrics(ns: argparse.Namespace) -> int:
    code, raw = http_request(
        ns.base, "GET", "/metrics", headers={"Accept": "text/plain"}
    )
    sys.stdout.buffer.write(raw)
    if raw and not raw.endswith(b"\n"):
        print()
    return 0 if code == 200 else code


def cmd_ingest_raw(ns: argparse.Namespace) -> int:
    if ns.file is not None:
        with open(ns.file, "rb") as f:
            blob = f.read()
    elif ns.b64 is not None:
        try:
            blob = base64.b64decode(ns.b64, validate=True)
        except (binascii.Error, ValueError) as e:
            raise SystemExit(f"invalid base64: {e}") from e
    else:
        blob = sys.stdin.buffer.read()
    doc: Dict[str, Any] = {
        "type": "raw",
        "payload_b64": base64.b64encode(blob).decode("ascii"),
    }
    if ns.service_id is not None:
        doc["service_id"] = int(ns.service_id)
    payload = json.dumps(doc).encode("utf-8")
    code, raw = http_request(ns.base, "POST", "/ingest", body=payload)
    print_json(raw)
    return 0 if code in (200, 202) else code


def main() -> int:
    p = argparse.ArgumentParser(
        prog="atsc3ctl",
        description="Operator CLI for atsc3_gw --admin-http (stdlib HTTP).",
    )
    p.add_argument(
        "--base",
        default=os.environ.get("ATSC3_ADMIN", "http://127.0.0.1:8080"),
        help="Admin base URL (or set ATSC3_ADMIN)",
    )
    sp = p.add_subparsers(dest="cmd", required=True)

    sp_c = sp.add_parser("config", help="GET /config or POST /config/sink")
    sp_c_sub = sp_c.add_subparsers(dest="config_cmd", required=True)
    p_get = sp_c_sub.add_parser("get", help="GET /config")
    p_get.set_defaults(func=cmd_config_get)
    p_set = sp_c_sub.add_parser("set-sink", help="POST /config/sink {\"sink_uri\":...}")
    p_set.add_argument("uri", help="new sink URI, e.g. null:// or file:///tmp/out")
    p_set.set_defaults(func=cmd_config_set_sink)

    sp_s = sp.add_parser("services", help="/services registry")
    sp_s_sub = sp_s.add_subparsers(dest="svc_cmd", required=True)
    p_sl = sp_s_sub.add_parser("list", help="GET /services")
    p_sl.set_defaults(func=cmd_services_list)
    p_sa = sp_s_sub.add_parser("add", help="POST /services")
    p_sa.add_argument("name")
    p_sa.set_defaults(func=cmd_services_add)
    p_sd = sp_s_sub.add_parser("delete", help="DELETE /services?id=")
    p_sd.add_argument("id", help="numeric service id")
    p_sd.set_defaults(func=cmd_services_delete)

    p_h = sp.add_parser("health", help="GET /healthz and /readyz")
    p_h.set_defaults(func=cmd_health)

    p_m = sp.add_parser("metrics", help="GET /metrics (Prometheus text)")
    p_m.set_defaults(func=cmd_metrics)

    p_ing = sp.add_parser("ingest", help="POST /ingest")
    ing_sub = p_ing.add_subparsers(dest="ingest_cmd", required=True)
    p_ir = ing_sub.add_parser(
        "raw",
        help="type=raw: payload from --file, --b64, or stdin (default)",
    )
    p_ir.add_argument("--file", metavar="PATH", help="read raw bytes from file")
    p_ir.add_argument("--b64", metavar="STRING", help="inline base64 payload")
    p_ir.add_argument(
        "--service-id",
        dest="service_id",
        help="optional registry id (must exist in /services)",
    )
    p_ir.set_defaults(func=cmd_ingest_raw)

    ns = p.parse_args()
    code = int(ns.func(ns))
    if code != 0:
        print(f"atsc3ctl: HTTP or exit status {code}", file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())

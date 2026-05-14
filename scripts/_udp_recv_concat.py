#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# Lab helper: receive exactly N UDP datagrams, concatenate payloads to one
# file (same byte layout as gw file:// sink for TLV-mux chains).
#
# Usage:
#   _udp_recv_concat.py HOST PORT OUT_PATH EXPECTED_COUNT [PER_RECV_TIMEOUT_SEC]
#
# Exit 0 only if exactly EXPECTED_COUNT datagrams were received.

from __future__ import annotations

import socket
import sys


def main() -> None:
    if len(sys.argv) < 6 or len(sys.argv) > 7:
        print(
            "usage: _udp_recv_concat.py HOST PORT OUT_PATH EXPECTED_COUNT "
            "[PER_RECV_TIMEOUT_SEC]",
            file=sys.stderr,
        )
        sys.exit(2)
    host = sys.argv[1]
    port = int(sys.argv[2])
    out_path = sys.argv[3]
    n = int(sys.argv[4])
    per_timeout = float(sys.argv[5]) if len(sys.argv) > 5 else 5.0

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        pkts: list[bytes] = []
        s.settimeout(per_timeout)
        while len(pkts) < n:
            try:
                d, _addr = s.recvfrom(65536)
                pkts.append(d)
            except socket.timeout:
                break
    finally:
        s.close()

    with open(out_path, "wb") as f:
        f.write(b"".join(pkts))

    if len(pkts) != n:
        print(
            f"udp_recv: expected {n} datagrams, got {len(pkts)}",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()

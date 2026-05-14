#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# Lab helper for lls:// integration: bind UDP, recv one datagram, validate
# A/331 Table 6.1 four-byte prefix (defaults table=1 group=1 gcm1=0) and
# RFC 1952 gzip body matches expected cleartext bytes.
#
# Usage:
#   _lls_lab_integ_recv.py HOST PORT PER_RECV_TIMEOUT_SEC EXPECTED_CLEARTEXT_PATH

from __future__ import annotations

import gzip
import socket
import sys


def main() -> None:
    if len(sys.argv) != 5:
        print(
            "usage: _lls_lab_integ_recv.py HOST PORT PER_RECV_TIMEOUT_SEC "
            "EXPECTED_CLEARTEXT_PATH",
            file=sys.stderr,
        )
        sys.exit(2)
    host = sys.argv[1]
    port = int(sys.argv[2])
    per_timeout = float(sys.argv[3])
    exp_path = sys.argv[4]

    with open(exp_path, "rb") as f:
        expected = f.read()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.settimeout(per_timeout)
        wire, _addr = s.recvfrom(65536)
    except socket.timeout:
        print("lls_lab_recv: timeout waiting for UDP", file=sys.stderr)
        sys.exit(1)
    finally:
        s.close()

    if len(wire) < 6:
        print(f"lls_lab_recv: datagram too short ({len(wire)})", file=sys.stderr)
        sys.exit(1)
    # Defaults from make_lls_sink when query omits table/group/gcm1
    if wire[0] != 0x01 or wire[1] != 0x01 or wire[2] != 0x00:
        print(f"lls_lab_recv: bad Table6.1 prefix {wire[:4].hex()}", file=sys.stderr)
        sys.exit(1)
    if wire[4] != 0x1F or wire[5] != 0x8B:
        print("lls_lab_recv: expected gzip at offset 4", file=sys.stderr)
        sys.exit(1)
    try:
        body = gzip.decompress(wire[4:])
    except OSError as e:
        print(f"lls_lab_recv: gzip: {e}", file=sys.stderr)
        sys.exit(1)
    if body != expected:
        print(
            f"lls_lab_recv: cleartext mismatch\n  want: {expected!r}\n  got:  {body!r}",
            file=sys.stderr,
        )
        sys.exit(1)
    print("lls_lab_recv: OK", file=sys.stderr)


if __name__ == "__main__":
    main()

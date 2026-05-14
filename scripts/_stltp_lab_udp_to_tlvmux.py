#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# Receive N UDP datagrams from gw --sink stltp:// (lab layout in gw/sink.cc),
# strip the fixed STLTP lab prefix (including the synthetic 0xA5A5 + u16 TLV len),
# and concatenate inner TLV-mux bytes (same layout as file:// sink).
#
# Constants MUST stay in sync with gw/sink.cc:
#   k_stltp_overhead = 12 + 25 + 64 + 8 + 4   (RTP + stubs + time + BBP type/len)
#   Payload after that offset is raw TLV-mux only.
#
# Usage:
#   _stltp_lab_udp_to_tlvmux.py HOST PORT OUT_PATH EXPECTED_COUNT [PER_RECV_TIMEOUT_SEC]

from __future__ import annotations

import socket
import sys

# gw/sink.cc lab STLTP layout (before synthetic BBP type + tlv length + TLV-mux)
_STLTP_LAB_OVERHEAD = 12 + 25 + 64 + 8 + 4
_LAB_BBP_MUX_TYPE = 0xA5A5


def strip_stltp_lab_udp_payload(dgram: bytes) -> bytes:
    if len(dgram) < _STLTP_LAB_OVERHEAD:
        raise ValueError(f"STLTP datagram too short: {len(dgram)}")
    hdr = dgram[_STLTP_LAB_OVERHEAD - 4 : _STLTP_LAB_OVERHEAD]
    mux_type = (hdr[0] << 8) | hdr[1]
    tlv_len = (hdr[2] << 8) | hdr[3]
    if mux_type != _LAB_BBP_MUX_TYPE:
        raise ValueError(
            f"unexpected lab mux_type {mux_type:#06x} (want {_LAB_BBP_MUX_TYPE:#06x})"
        )
    inner = dgram[_STLTP_LAB_OVERHEAD :]
    if len(inner) != tlv_len:
        raise ValueError(
            f"TLV length field {tlv_len} vs trailing {len(inner)} bytes in datagram"
        )
    return inner


def main() -> None:
    if len(sys.argv) < 6 or len(sys.argv) > 7:
        print(
            "usage: _stltp_lab_udp_to_tlvmux.py HOST PORT OUT_PATH EXPECTED_COUNT "
            "[PER_RECV_TIMEOUT_SEC]",
            file=sys.stderr,
        )
        sys.exit(2)
    host = sys.argv[1]
    port = int(sys.argv[2])
    out_path = sys.argv[3]
    n = int(sys.argv[4])
    per_timeout = float(sys.argv[5]) if len(sys.argv) > 6 else 8.0

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        chunks: list[bytes] = []
        s.settimeout(per_timeout)
        while len(chunks) < n:
            try:
                d, _addr = s.recvfrom(65536)
                chunks.append(strip_stltp_lab_udp_payload(d))
            except socket.timeout:
                break
    finally:
        s.close()

    with open(out_path, "wb") as f:
        f.write(b"".join(chunks))

    if len(chunks) != n:
        print(
            f"stltp_recv: expected {n} datagrams, got {len(chunks)}",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()

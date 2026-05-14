#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# Convert a concatenation of IPv4 datagrams (e.g. output from
#   atsc3_gw --sink 'ipv4udp-file:///path?src=…&dst=…&…'
# one append per TLV-mux frame) into a classic libpcap file (DLT_IPV4=228)
# for Wireshark / tcpdump -r.
#
# Usage:
#   python3 tools/m8_bin_to_pcap.py < raw.bin > out.pcap
#   python3 tools/m8_bin_to_pcap.py -i raw.bin -o out.pcap
#   python3 tools/m8_bin_to_pcap.py -i raw.shard0 --extract-tlvmux tlv.bin
#   python3 tools/m8_bin_to_pcap.py --self-test

from __future__ import annotations

import argparse
import struct
import sys
from typing import BinaryIO

# tcpdump / libpcap: LINKTYPE_IPV4 — raw IPv4, begins with IPv4 header.
DLT_IPV4 = 228
PCAP_MAGIC_LE = 0xA1B2C3D4


def be16(b: bytes, off: int) -> int:
    return (b[off] << 8) | b[off + 1]


def split_ipv4_chain(data: bytes) -> list[bytes]:
    i = 0
    out: list[bytes] = []
    while i + 20 <= len(data):
        vihl = data[i]
        if (vihl >> 4) != 4:
            raise ValueError(f"not IPv4 at offset {i}: first byte {vihl:#04x}")
        ihl = (vihl & 0x0F) * 4
        if ihl < 20:
            raise ValueError(f"bad IPv4 IHL at offset {i}: {ihl}")
        total = be16(data, i + 2)
        if total < ihl or i + total > len(data):
            raise ValueError(
                f"bad IPv4 total_length {total} at offset {i} "
                f"(remaining {len(data) - i} bytes)"
            )
        out.append(data[i : i + total])
        i += total
    if i != len(data):
        raise ValueError(f"{len(data) - i} trailing bytes after last IPv4 packet")
    return out


def concat_udp_payloads(pkts: list[bytes]) -> bytes:
    """UDP payload bytes per IPv4 datagram (gw ipv4udp-file sink: one TLV-mux per datagram)."""
    parts: list[bytes] = []
    for pkt in pkts:
        vihl = pkt[0]
        ihl = (vihl & 0x0F) * 4
        if len(pkt) < ihl + 8:
            raise ValueError("IPv4 packet too short for UDP header")
        if pkt[9] != 17:
            raise ValueError(f"expected IPv4 proto UDP (17), got {pkt[9]}")
        ip_total = be16(pkt, 2)
        ip_payload = ip_total - ihl
        if ip_payload < 8:
            raise ValueError("UDP length field would exceed IP payload")
        udp_len = be16(pkt, ihl + 4)
        if udp_len != ip_payload:
            raise ValueError(
                f"UDP length {udp_len} != IPv4 payload length {ip_payload}"
            )
        udl = udp_len - 8
        pl_start = ihl + 8
        if pl_start + udl != len(pkt):
            raise ValueError("IPv4 total_length vs UDP payload mismatch")
        parts.append(pkt[pl_start : pl_start + udl])
    return b"".join(parts)


def write_pcap(pkts: list[bytes], fp: BinaryIO) -> None:
    fp.write(
        struct.pack(
            "<IHHIIII",
            PCAP_MAGIC_LE,
            2,
            4,
            0,
            0,
            65535,
            DLT_IPV4,
        )
    )
    usec = 0
    for p in pkts:
        hdr = struct.pack("<IIII", 0, usec, len(p), len(p))
        fp.write(hdr)
        fp.write(p)
        usec += 1


def self_test() -> None:
    # Two minimal IPv4 packets: v4 IHL5, total 20, id 0, no frag, TTL 1,
    # proto 59 (no next header noop), hdr csum 0 (invalid on wire but parses).
    pkt20 = bytes(
        [
            0x45,
            0x00,
            0x00,
            0x14,
            0x00,
            0x00,
            0x40,
            0x00,
            0x01,
            0x3B,
            0x00,
            0x00,
            0x0A,
            0x00,
            0x00,
            0x01,
            0x0A,
            0x00,
            0x00,
            0x02,
        ]
    )
    blob = pkt20 + pkt20
    pkts = split_ipv4_chain(blob)
    assert len(pkts) == 2 and pkts[0] == pkt20
    import io

    buf = io.BytesIO()
    write_pcap(pkts, buf)
    raw = buf.getvalue()
    assert len(raw) == 24 + 2 * (16 + 20)  # global + 2*(rec_hdr+pkt)
    # One IPv4+UDP datagram: UDP len 12, payload ABCD (matches gw M8 layout).
    udp_pkt = bytes.fromhex(
        "4500002000004000401100000101010102020202"
        "03e807d8000c000041424344"
    )
    blob2 = udp_pkt + udp_pkt
    assert concat_udp_payloads(split_ipv4_chain(blob2)) == b"ABCD" * 2
    print("m8_bin_to_pcap: self-test OK", file=sys.stderr)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="IPv4 concatenation → pcap (DLT_IPV4) or TLV-mux strip"
    )
    ap.add_argument("-i", "--in", dest="in_path", help="input bin (default: stdin)")
    ap.add_argument(
        "-o",
        "--out",
        dest="out_path",
        help="output pcap (default: stdout when not using --extract-tlvmux alone)",
    )
    ap.add_argument(
        "--extract-tlvmux",
        metavar="PATH",
        help="write concatenated UDP payloads (TLV-mux per gw frame) to PATH",
    )
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="run built-in parse+pcap sanity check and exit",
    )
    args = ap.parse_args()
    if args.self_test:
        self_test()
        return 0

    if args.in_path:
        with open(args.in_path, "rb") as f:
            data = f.read()
    else:
        data = sys.stdin.buffer.read()

    pkts = split_ipv4_chain(data)

    if args.out_path:
        with open(args.out_path, "wb") as f:
            write_pcap(pkts, f)
        print(f"m8_bin_to_pcap: wrote {len(pkts)} packet(s) to pcap", file=sys.stderr)
    elif not args.extract_tlvmux:
        write_pcap(pkts, sys.stdout.buffer)
        print(f"m8_bin_to_pcap: wrote {len(pkts)} packet(s) to stdout pcap", file=sys.stderr)

    if args.extract_tlvmux:
        tlv = concat_udp_payloads(pkts)
        with open(args.extract_tlvmux, "wb") as f:
            f.write(tlv)
        print(
            f"m8_bin_to_pcap: wrote {len(tlv)} TLV-mux byte(s) to {args.extract_tlvmux}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError) as e:
        print(f"m8_bin_to_pcap: {e}", file=sys.stderr)
        raise SystemExit(1)

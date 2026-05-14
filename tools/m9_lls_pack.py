#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""M9 lab helper: cleartext LLS XML (e.g. SLT) -> A/331 Table 6.1 wire (4-byte prefix + gzip).

Writes binary to stdout. Pipe into mmt_probe / nc / a file, or POST /ingest with base64.

Example:
  python3 tools/m9_lls_pack.py --table 1 fixtures/lls/minimal_slt.xml > /tmp/lls.bin
"""

from __future__ import annotations

import argparse
import gzip
import sys


def parse_u8(s: str) -> int:
    s = s.strip()
    if s.startswith(("0x", "0X")):
        return int(s, 16) & 0xFF
    return int(s, 10) & 0xFF


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("xml_file", help="Input XML (UTF-8)")
    ap.add_argument("--table", default="1", help="LLS_table_id (decimal or 0x hex)")
    ap.add_argument("--group", default="0", help="group_id byte")
    ap.add_argument("--gcm1", default="0", help="group_count_minus1 byte")
    ap.add_argument("--version", default="0", help="LLS_table_version byte (usually 0)")
    args = ap.parse_args()

    table_id = parse_u8(args.table)
    group_id = parse_u8(args.group)
    gcm1 = parse_u8(args.gcm1)
    version = parse_u8(args.version)

    with open(args.xml_file, "rb") as f:
        body = f.read()

    gz = gzip.compress(body, compresslevel=9, mtime=0)
    prefix = bytes((table_id, group_id, gcm1, version))
    sys.stdout.buffer.write(prefix + gz)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

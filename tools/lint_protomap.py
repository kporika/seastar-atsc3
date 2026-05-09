#!/usr/bin/env python3
"""Validate atsc3_proto YAML protocol-map files.

Catches:
  - missing required keys (protocol.{name,proto_id,spec})
  - duplicate proto_id across files
  - duplicate enum value within a group
  - bit-field overlap or out-of-range vs header.total_bits
  - field references to undefined enums
  - payload.length_field referencing an unknown header field
  - fixture raw_hex parsing
  - duplicate field names within a header

Exit code 0 == clean, non-zero == errors (count printed).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml


def _err(errs: list[str], msg: str) -> None:
    errs.append(msg)


def _validate_header(h: dict, enums: dict, errs: list[str]) -> None:
    if "total_bits" not in h or "fields" not in h:
        _err(errs, "header: must define both 'total_bits' and 'fields'")
        return

    total_bits = int(h["total_bits"])
    if total_bits <= 0 or total_bits % 8 != 0:
        _err(errs, f"header.total_bits={total_bits} must be a positive multiple of 8")

    seen_names: set[str] = set()
    bit_coverage: list[bool] = [False] * total_bits

    for f in h["fields"]:
        for k in ("name", "bit_offset", "bit_width", "type"):
            if k not in f:
                _err(errs, f"header.fields: entry missing required key '{k}': {f}")
                return

        name = f["name"]
        if name in seen_names:
            _err(errs, f"header.fields: duplicate field name '{name}'")
        seen_names.add(name)

        off, width = int(f["bit_offset"]), int(f["bit_width"])
        if off < 0 or width <= 0 or off + width > total_bits:
            _err(
                errs,
                f"header.fields['{name}']: bit_offset={off} + bit_width={width} "
                f"out of range [0, {total_bits})",
            )
            continue

        for b in range(off, off + width):
            if bit_coverage[b]:
                _err(errs, f"header.fields['{name}']: overlaps bit {b}")
            bit_coverage[b] = True

        ftype = f["type"]
        if ftype not in ("enum", "uint", "bool"):
            _err(errs, f"header.fields['{name}']: unknown type '{ftype}'")
        if ftype == "enum":
            ename = f.get("enum")
            if not ename or ename not in enums:
                _err(
                    errs,
                    f"header.fields['{name}']: enum '{ename}' not defined in 'enums:' "
                    f"(known: {sorted(enums)})",
                )
        if ftype == "bool" and width != 1:
            _err(errs, f"header.fields['{name}']: bool requires bit_width=1, got {width}")


def _validate_payload(p: dict, header_field_names: set[str], errs: list[str]) -> None:
    lf = p.get("length_field")
    if not lf:
        _err(errs, "payload: 'length_field' is required")
        return
    if lf not in header_field_names:
        _err(errs, f"payload.length_field='{lf}' is not a header field")
    if p.get("kind") not in ("opaque", None):
        _err(errs, f"payload.kind='{p.get('kind')}' unsupported (M2 supports 'opaque')")


def _validate_repeated(
    r: dict,
    header_field_names: set[str],
    known_protocols: set[str] | None,
    errs: list[str],
) -> None:
    lf = r.get("length_field")
    if not lf:
        _err(errs, "repeated: 'length_field' is required")
    elif lf not in header_field_names:
        _err(errs, f"repeated.length_field='{lf}' is not a header field")

    elem = r.get("element")
    if not elem:
        _err(errs, "repeated: 'element' is required (name of another protocol)")
    elif known_protocols is not None and elem not in known_protocols:
        _err(
            errs,
            f"repeated.element='{elem}' references unknown protocol "
            f"(known: {sorted(known_protocols)})",
        )


def _validate_enums(enums: dict, errs: list[str]) -> None:
    for ename, vals in enums.items():
        if not isinstance(vals, dict):
            _err(errs, f"enums.{ename}: must be a mapping of NAME -> integer")
            continue
        seen_vals: dict[int, str] = {}
        for k, v in vals.items():
            if not isinstance(v, int):
                _err(errs, f"enums.{ename}.{k}: value must be integer, got {type(v).__name__}")
                continue
            if v in seen_vals:
                _err(errs, f"enums.{ename}: duplicate value {v} ({seen_vals[v]} and {k})")
            seen_vals[v] = k


def _validate_fixtures(fixtures: list[dict], errs: list[str]) -> None:
    for fx in fixtures:
        if "name" not in fx or "raw_hex" not in fx or "expected" not in fx:
            _err(errs, f"fixture missing 'name', 'raw_hex' or 'expected': {fx}")
            continue
        try:
            bytes.fromhex(fx["raw_hex"].replace(" ", "").replace("\n", ""))
        except ValueError as exc:
            _err(errs, f"fixture '{fx['name']}': raw_hex not valid hex ({exc})")


def lint_doc(doc: dict, known_protocols: set[str] | None = None) -> list[str]:
    errs: list[str] = []
    if not isinstance(doc, dict) or "protocol" not in doc:
        return ["top-level: missing 'protocol' section"]

    proto = doc["protocol"]
    for k in ("name", "proto_id", "spec"):
        if k not in proto:
            _err(errs, f"protocol.{k} is required")

    name = proto.get("name", "")
    if name and not name.replace("_", "").isalnum():
        _err(errs, f"protocol.name='{name}' must be alphanumeric/underscore")

    enums = doc.get("enums", {}) or {}
    _validate_enums(enums, errs)

    header = doc.get("header")
    header_field_names: set[str] = set()
    if header:
        _validate_header(header, enums, errs)
        header_field_names = {f["name"] for f in header.get("fields", []) if "name" in f}

    payload = doc.get("payload")
    repeated = doc.get("repeated")
    if payload and repeated:
        _err(
            errs,
            "protocol declares both 'payload' and 'repeated'; pick exactly one",
        )
    if payload:
        _validate_payload(payload, header_field_names, errs)
    if repeated:
        _validate_repeated(repeated, header_field_names, known_protocols, errs)

    fixtures = doc.get("fixtures", []) or []
    _validate_fixtures(fixtures, errs)

    return errs


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: lint_protomap.py <protocol_dir>", file=sys.stderr)
        return 2

    indir = Path(sys.argv[1])
    if not indir.is_dir():
        print(f"not a directory: {indir}", file=sys.stderr)
        return 2

    files = sorted(indir.glob("*.yaml"))
    if not files:
        print(f"no .yaml files under {indir}", file=sys.stderr)
        return 0

    # First pass: collect protocol names for cross-file `repeated.element`
    # resolution. We also keep the parsed docs to avoid re-reading.
    parsed: list[tuple[Path, Any]] = []
    known_protocols: set[str] = set()
    for f in files:
        try:
            doc = yaml.safe_load(f.read_text())
        except yaml.YAMLError as exc:
            parsed.append((f, exc))
            continue
        parsed.append((f, doc))
        try:
            known_protocols.add(doc["protocol"]["name"])
        except (KeyError, TypeError):
            pass  # missing/invalid name reported in the lint pass below

    seen_proto_ids: dict[int, str] = {}
    failures = 0

    for f, doc in parsed:
        if isinstance(doc, yaml.YAMLError):
            print(f"{f.name}: FAIL")
            print(f"  - YAML parse error: {doc}")
            failures += 1
            continue

        errs = lint_doc(doc, known_protocols=known_protocols)

        try:
            pid = int(doc["protocol"]["proto_id"])
            if pid in seen_proto_ids and seen_proto_ids[pid] != f.name:
                errs.append(
                    f"protocol.proto_id={pid} duplicates {seen_proto_ids[pid]}"
                )
            else:
                seen_proto_ids[pid] = f.name
        except (KeyError, TypeError, ValueError):
            pass  # already reported above

        if errs:
            failures += 1
            print(f"{f.name}: FAIL")
            for e in errs:
                print(f"  - {e}")
        else:
            print(f"{f.name}: OK")

    if failures:
        print(f"\n{failures} file(s) failed lint", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

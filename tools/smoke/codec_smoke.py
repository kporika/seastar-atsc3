#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Pure-python re-implementation of the codegen-emitted decoder/encoder.

Used to verify YAML fixtures round-trip BEFORE the C++ build is available.
Mirrors lib/runtime/bit_reader.h::msb_bit_reader and bit_writer.h::msb_bit_writer
plus the per-protocol decode/encode logic that codegen.py emits.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml


# ---------------------------------------------------------------------------
# bit-level primitives — must match lib/runtime/bit_reader.h / bit_writer.h
# ---------------------------------------------------------------------------

def read_msb_bits(buf: bytes, off: int, width: int) -> int:
    v = 0
    for i in range(width):
        bit = off + i
        b = (buf[bit // 8] >> (7 - (bit % 8))) & 1
        v = (v << 1) | b
    return v


def write_msb_bits(buf: bytearray, off: int, width: int, value: int) -> None:
    for i in range(width):
        bit = off + i
        b = (value >> (width - 1 - i)) & 1
        buf[bit // 8] |= b << (7 - (bit % 8))


def normalize_hex(s: str) -> str:
    return "".join(c for c in s.upper() if c in "0123456789ABCDEF")


# ---------------------------------------------------------------------------
# generic TLV codec driven by a YAML protocol map
#
# `decode()` and `encode()` both take a `protocols` dict keyed by name so
# that a doc with `repeated.element: <other>` can resolve cross-file. For
# leaf protocols (just `payload:`) the dict is unused.
# ---------------------------------------------------------------------------

def _read_header(doc: dict, raw: bytes) -> dict:
    h = doc["header"]
    enums = doc.get("enums", {}) or {}
    out: dict = {}
    for f in h["fields"]:
        v = read_msb_bits(raw, f["bit_offset"], f["bit_width"])
        if f["type"] == "enum":
            inv = {iv: k for k, iv in enums[f["enum"]].items()}
            out[f["name"]] = inv.get(v, f"<unknown:{v}>")
        elif f["type"] == "bool":
            out[f["name"]] = bool(v)
        else:
            out[f["name"]] = v
    return out


def _write_header(doc: dict, fields: dict, buf: bytearray,
                  override: dict | None = None) -> None:
    h = doc["header"]
    enums = doc.get("enums", {}) or {}
    overrides = override or {}
    for f in h["fields"]:
        if f["name"] in overrides:
            v = int(overrides[f["name"]])
        else:
            v_in = fields[f["name"]]
            if f["type"] == "enum":
                v = enums[f["enum"]][v_in]
            elif f["type"] == "bool":
                v = 1 if v_in else 0
            else:
                v = int(v_in)
        write_msb_bits(buf, f["bit_offset"], f["bit_width"], v)


def decode(doc: dict, raw: bytes,
           protocols: dict[str, dict] | None = None) -> dict:
    h = doc["header"]
    header_bytes = (h["total_bits"] + 7) // 8
    out = _read_header(doc, raw)

    if "payload" in doc:
        plen = out[doc["payload"]["length_field"]]
        out["payload_hex"] = raw[header_bytes : header_bytes + plen].hex().upper()
    elif "repeated" in doc:
        if protocols is None:
            raise ValueError(
                "decode: 'repeated' requires a `protocols` dict for "
                "cross-protocol resolution")
        rep = doc["repeated"]
        inner_doc = protocols.get(rep["element"])
        if inner_doc is None:
            raise ValueError(
                f"decode: 'repeated.element={rep['element']}' not in "
                f"loaded protocols ({sorted(protocols)})")
        budget = out[rep["length_field"]]
        cur = raw[header_bytes : header_bytes + budget]
        elements = []
        while cur:
            elem = decode(inner_doc, cur, protocols)
            elem_size = _encoded_size(inner_doc, elem)
            if elem_size == 0:
                raise ValueError(
                    "decode: inner element consumed 0 bytes (loop forever)")
            elements.append(elem)
            cur = cur[elem_size:]
        if cur:
            raise ValueError(
                f"decode: element loop overran by {len(cur)} bytes")
        out["elements"] = elements
    return out


def _encoded_size(doc: dict, fields: dict) -> int:
    h = doc["header"]
    header_bytes = (h["total_bits"] + 7) // 8
    if "payload" in doc:
        return header_bytes + (len(fields.get("payload_hex", "")) // 2)
    if "repeated" in doc:
        return header_bytes + sum(
            _encoded_size_of(doc["repeated"]["element"], el)
            for el in fields.get("elements", []) or []
        )
    return header_bytes


# Late binding: real lookup happens via the `protocols` dict in encode().
# This module-level shim is set by the smoke runner before encoding.
_protocols_for_size: dict[str, dict] = {}


def _encoded_size_of(name: str, fields: dict) -> int:
    return _encoded_size(_protocols_for_size[name], fields)


def encode(doc: dict, fields: dict,
           protocols: dict[str, dict] | None = None) -> bytes:
    """Inverse of decode(); accepts the dict shape that decode() returns."""
    global _protocols_for_size
    if protocols is not None:
        _protocols_for_size = protocols

    h = doc["header"]
    header_bytes = (h["total_bits"] + 7) // 8

    if "payload" in doc:
        payload_hex = fields.get("payload_hex", "")
        payload = bytes.fromhex(normalize_hex(payload_hex)) if payload_hex else b""
        buf = bytearray(header_bytes + len(payload))
        _write_header(doc, fields, buf)
        if payload:
            buf[header_bytes:] = payload
        return bytes(buf)

    if "repeated" in doc:
        if protocols is None:
            raise ValueError(
                "encode: 'repeated' requires a `protocols` dict for "
                "cross-protocol resolution")
        rep = doc["repeated"]
        inner_doc = protocols[rep["element"]]
        body = b"".join(
            encode(inner_doc, el, protocols)
            for el in fields.get("elements", []) or []
        )
        # Force the length_field to match the actual encoded body, mirroring
        # the C++ encoder's auto-derivation behavior.
        buf = bytearray(header_bytes + len(body))
        _write_header(doc, fields, buf,
                      override={rep["length_field"]: len(body)})
        if body:
            buf[header_bytes:] = body
        return bytes(buf)

    # No payload / repeated → header-only.
    buf = bytearray(header_bytes)
    _write_header(doc, fields, buf)
    return bytes(buf)


# ---------------------------------------------------------------------------
# fixture round-trip — decode(raw) must match expected; encode(expected) must
# match raw bytes byte-for-byte.
# ---------------------------------------------------------------------------

def _normalize_expected(obj):
    """Recursively uppercase+strip every payload_hex string in-place."""
    if isinstance(obj, dict):
        return {
            k: (normalize_hex(v) if k == "payload_hex" and isinstance(v, str)
                else _normalize_expected(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_normalize_expected(x) for x in obj]
    return obj


def load_protocols(proto_dir: Path) -> dict[str, dict]:
    """Load every protocol/*.yaml into a name-keyed dict."""
    out: dict[str, dict] = {}
    for f in sorted(proto_dir.glob("*.yaml")):
        doc = yaml.safe_load(f.read_text())
        try:
            name = doc["protocol"]["name"]
        except (KeyError, TypeError) as e:
            raise SystemExit(f"smoke: {f.name}: bad/missing protocol.name: {e}")
        if name in out:
            raise SystemExit(
                f"smoke: duplicate protocol name '{name}' in {f.name}")
        doc["__source"] = f.name
        out[name] = doc
    return out


def fixture_round_trip(protocols: dict[str, dict]) -> int:
    failed = 0
    for name in sorted(protocols):
        doc = protocols[name]
        for fx in doc.get("fixtures", []) or []:
            raw = bytes.fromhex(normalize_hex(fx["raw_hex"]))
            try:
                got = decode(doc, raw, protocols)
            except Exception as exc:
                failed += 1
                print(f"FAIL decode {doc['__source']} :: {fx['name']}: {exc}")
                continue
            exp = _normalize_expected(fx["expected"])
            if got != exp:
                failed += 1
                print(
                    f"FAIL decode {doc['__source']} :: {fx['name']}\n"
                    f"  got = {json.dumps(got)}\n"
                    f"  exp = {json.dumps(exp)}"
                )
                continue

            try:
                re = encode(doc, exp, protocols)
            except Exception as exc:
                failed += 1
                print(f"FAIL encode {doc['__source']} :: {fx['name']}: {exc}")
                continue
            if re != raw:
                failed += 1
                print(
                    f"FAIL encode {doc['__source']} :: {fx['name']}\n"
                    f"  raw = {raw.hex().upper()}\n"
                    f"  enc = {re.hex().upper()}"
                )
                continue
            print(f"PASS {doc['__source']} :: {fx['name']}  "
                  f"(decode + encode round-trip)")
    return failed


# ---------------------------------------------------------------------------
# M4: validate the gw/encoder_pipeline composition end-to-end (payload →
# ALP encode → TLV-mux encode → wire; then wire → TLV-mux decode → ALP
# decode → payload). This is the python mirror of gw/encoder_pipeline.cc.
# ---------------------------------------------------------------------------

def pipeline_round_trip(protocols: dict[str, dict]) -> int:
    alp = protocols["alp"]
    tlv = protocols["tlv_mux"]

    cases = [
        ("DEADBEEF",        bytes.fromhex("DEADBEEF")),
        ("empty",           b""),
        ("single-byte",     bytes.fromhex("42")),
        ("256-byte",        bytes(range(256))),
        ("alp-max-2047",    b"\xA5" * 2047),
    ]

    failed = 0
    for label, payload in cases:
        # -------- forward: payload -> ALP -> TLV-mux ------------------------
        if len(payload) > (1 << 11) - 1:
            print(f"FAIL pipeline {label}: payload exceeds ALP 11-bit limit")
            failed += 1
            continue

        alp_fields = {
            "packet_type":   "PACKET_TYPE_EXTENSION",
            "payload_config": False,
            "header_mode":    False,
            "payload_length": len(payload),
            "payload_hex":    payload.hex().upper(),
        }
        alp_bytes = encode(alp, alp_fields)

        if len(alp_bytes) > (1 << 16) - 1:
            print(
                f"FAIL pipeline {label}: alp packet exceeds TLV-mux 16-bit limit")
            failed += 1
            continue

        tlv_fields = {
            "packet_type":   "SIGNALING",
            "packet_length": len(alp_bytes),
            "payload_hex":   alp_bytes.hex().upper(),
        }
        wire = encode(tlv, tlv_fields)

        # -------- reverse: wire -> TLV-mux -> ALP -> payload ----------------
        tlv_decoded = decode(tlv, wire)
        if tlv_decoded["packet_type"] != "SIGNALING":
            print(
                f"FAIL pipeline {label}: tlv_mux packet_type "
                f"{tlv_decoded['packet_type']} != SIGNALING")
            failed += 1
            continue

        inner = bytes.fromhex(tlv_decoded["payload_hex"])
        alp_decoded = decode(alp, inner)
        if alp_decoded["packet_type"] != "PACKET_TYPE_EXTENSION":
            print(
                f"FAIL pipeline {label}: alp packet_type "
                f"{alp_decoded['packet_type']} != PACKET_TYPE_EXTENSION")
            failed += 1
            continue

        recovered = bytes.fromhex(alp_decoded["payload_hex"]) \
            if alp_decoded["payload_hex"] else b""
        if recovered != payload:
            print(
                f"FAIL pipeline {label}: payload mismatch\n"
                f"  got  = {recovered.hex().upper()}\n"
                f"  want = {payload.hex().upper()}")
            failed += 1
            continue

        print(
            f"PASS pipeline {label}  "
            f"(payload={len(payload)}B → wire={len(wire)}B → payload)")
    return failed


# ---------------------------------------------------------------------------
# M5: RTCM v3 frame round-trip through the gw composition. Mirrors
# mmt_probe/rtcm_v3.cc and confirms a CRC-valid RTCM frame survives a full
# encode/decode trip and remains CRC-valid on the other side.
# ---------------------------------------------------------------------------

RTCM_PREAMBLE = 0xD3
CRC24Q_POLY = 0x1864CFB


def crc24q(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= CRC24Q_POLY
    return crc & 0xFFFFFF


def build_rtcm_frame(message_type: int, tail: bytes) -> bytes:
    payload_len = 2 + len(tail)
    if payload_len > 1023:
        raise ValueError("rtcm payload exceeds 10-bit length field")
    hdr = bytes([
        RTCM_PREAMBLE,
        (payload_len >> 8) & 0x03,
        payload_len & 0xFF,
    ])
    payload = bytes([
        (message_type >> 4) & 0xFF,
        (message_type & 0x0F) << 4,
    ]) + tail
    crc = crc24q(hdr + payload)
    crc_b = bytes([(crc >> 16) & 0xFF, (crc >> 8) & 0xFF, crc & 0xFF])
    return hdr + payload + crc_b


def parse_rtcm_frame(data: bytes) -> tuple[int, bytes, int]:
    if len(data) < 7 or data[0] != RTCM_PREAMBLE:
        raise ValueError("rtcm: bad preamble")
    plen = ((data[1] & 0x03) << 8) | data[2]
    if plen == 0 or plen > 1023:
        raise ValueError(f"rtcm: bad length {plen}")
    total = 3 + plen + 3
    if len(data) < total:
        raise ValueError("rtcm: truncated frame")
    crc_got = (data[3 + plen] << 16) | (data[3 + plen + 1] << 8) | data[3 + plen + 2]
    crc_want = crc24q(data[: 3 + plen])
    if crc_got != crc_want:
        raise ValueError(
            f"rtcm: CRC mismatch (got 0x{crc_got:06X}, want 0x{crc_want:06X})")
    msg_type = (data[3] << 4) | (data[4] >> 4)
    return msg_type, data[3 : 3 + plen], total


def rtcm_pipeline_round_trip(protocols: dict[str, dict]) -> int:
    alp = protocols["alp"]
    tlv = protocols["tlv_mux"]

    cases = [
        # (label, msg_type, tail_bytes)
        ("rtcm-1005-min",   1005, b""),                       # 7-byte total
        ("rtcm-1077-128B",  1077, bytes(range(126))),         # mid-size
        ("rtcm-1077-1021B", 1077, b"\x5A" * 1019),            # max RTCM payload
    ]

    failed = 0
    for label, msg_type, tail in cases:
        rtcm_frame = build_rtcm_frame(msg_type, tail)
        if len(rtcm_frame) > (1 << 11) - 1:
            print(f"FAIL rtcm-pipeline {label}: rtcm frame "
                  f"{len(rtcm_frame)}B exceeds ALP 11-bit limit")
            failed += 1
            continue

        # ---- forward: rtcm -> ALP -> TLV-mux -------------------------------
        alp_bytes = encode(alp, {
            "packet_type":   "PACKET_TYPE_EXTENSION",
            "payload_config": False,
            "header_mode":    False,
            "payload_length": len(rtcm_frame),
            "payload_hex":    rtcm_frame.hex().upper(),
        })
        wire = encode(tlv, {
            "packet_type":   "SIGNALING",
            "packet_length": len(alp_bytes),
            "payload_hex":   alp_bytes.hex().upper(),
        })

        # ---- reverse: TLV-mux -> ALP -> rtcm; CRC must still validate ------
        tlv_d = decode(tlv, wire)
        alp_d = decode(alp, bytes.fromhex(tlv_d["payload_hex"]))
        recovered = bytes.fromhex(alp_d["payload_hex"]) \
            if alp_d["payload_hex"] else b""
        if recovered != rtcm_frame:
            print(f"FAIL rtcm-pipeline {label}: byte mismatch after round-trip")
            failed += 1
            continue
        try:
            mt, _payload, n = parse_rtcm_frame(recovered)
        except ValueError as e:
            print(f"FAIL rtcm-pipeline {label}: recovered bytes failed RTCM "
                  f"parse: {e}")
            failed += 1
            continue
        if mt != msg_type or n != len(recovered):
            print(f"FAIL rtcm-pipeline {label}: msg_type/total mismatch "
                  f"(got mt={mt}, n={n})")
            failed += 1
            continue

        print(f"PASS rtcm-pipeline {label}  "
              f"(rtcm={len(rtcm_frame)}B → wire={len(wire)}B, "
              f"CRC verified after round-trip)")
    return failed


def tlv_mux_frame_pipeline(protocols: dict[str, dict]) -> int:
    """M6 composition: build a multi-packet tlv_mux_frame, push it through
    the gw's payload→ALP→TLV-mux pipeline, then unwrap and confirm the
    inner frame still parses as N tlv_mux packets identical to the source.
    """
    alp = protocols["alp"]
    tlv = protocols["tlv_mux"]
    tmf = protocols["tlv_mux_frame"]

    # Build a 3-element frame from scratch using the smoke encoder.
    frame_dict = {
        "version": 7,
        "reserved": 0,
        "body_length": 0,  # auto-derived by the encoder
        "elements": [
            {"packet_type": "IPV4",      "packet_length": 4, "payload_hex": "DEADBEEF"},
            {"packet_type": "SIGNALING", "packet_length": 2, "payload_hex": "BBCC"},
            {"packet_type": "NULL_PKT",  "packet_length": 0, "payload_hex": ""},
        ],
    }

    failed = 0
    try:
        frame_bytes = encode(tmf, frame_dict, protocols)
    except Exception as exc:
        print(f"FAIL tmf-pipeline build-frame: {exc}")
        return 1

    if len(frame_bytes) > (1 << 11) - 1:
        print(f"FAIL tmf-pipeline: frame {len(frame_bytes)}B "
              f"exceeds ALP 11-bit limit")
        return 1

    # Forward: frame → ALP → TLV-mux
    alp_bytes = encode(alp, {
        "packet_type":   "PACKET_TYPE_EXTENSION",
        "payload_config": False,
        "header_mode":    False,
        "payload_length": len(frame_bytes),
        "payload_hex":    frame_bytes.hex().upper(),
    })
    wire = encode(tlv, {
        "packet_type":   "SIGNALING",
        "packet_length": len(alp_bytes),
        "payload_hex":   alp_bytes.hex().upper(),
    })

    # Reverse + re-decode the inner frame.
    tlv_d = decode(tlv, wire)
    alp_d = decode(alp, bytes.fromhex(tlv_d["payload_hex"]))
    inner_bytes = bytes.fromhex(alp_d["payload_hex"]) if alp_d["payload_hex"] else b""
    if inner_bytes != frame_bytes:
        print("FAIL tmf-pipeline: inner frame bytes drifted through pipeline")
        return 1

    try:
        recovered = decode(tmf, inner_bytes, protocols)
    except Exception as exc:
        print(f"FAIL tmf-pipeline: re-decode failed: {exc}")
        return 1

    expected = dict(frame_dict, body_length=len(frame_bytes) - 4)  # 4-byte header
    expected_norm = _normalize_expected(expected)
    if recovered != expected_norm:
        print("FAIL tmf-pipeline: recovered != expected\n"
              f"  got = {json.dumps(recovered)}\n"
              f"  exp = {json.dumps(expected_norm)}")
        return 1

    print(f"PASS tmf-pipeline frame={len(frame_bytes)}B → wire={len(wire)}B "
          f"→ frame ({len(recovered['elements'])} inner packets verified)")
    return failed


def main() -> int:
    proto_dir = Path(__file__).resolve().parents[2] / "protocol"
    if not proto_dir.is_dir():
        print(f"ERR: protocol dir not found at {proto_dir}", file=sys.stderr)
        return 2
    protocols = load_protocols(proto_dir)

    print("--- fixture round-trip ---")
    failed = fixture_round_trip(protocols)
    print()
    print("--- gw/encoder_pipeline composition (M4) ---")
    failed += pipeline_round_trip(protocols)
    print()
    print("--- RTCM v3 → ALP → TLV-mux composition (M5) ---")
    failed += rtcm_pipeline_round_trip(protocols)
    print()
    print("--- tlv_mux_frame (nested repeated:) → gw pipeline (M6) ---")
    failed += tlv_mux_frame_pipeline(protocols)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

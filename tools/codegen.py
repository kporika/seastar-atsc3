#!/usr/bin/env python3
"""atsc3_proto codegen — YAML protomap → C++.

Reads every protocol/*.yaml file and renders the per-protocol set:

    lib/generated/<name>_types.h
    lib/generated/<name>_decoder.h
    lib/generated/<name>_decoder.cc
    lib/generated/<name>_tojson.h
    lib/generated/<name>_tojson.cc
    lib/generated/<name>_fixtures_test.cc

The companion lint pass lives in tools/lint_protomap.py and is invoked
implicitly here too — codegen refuses to run if any YAML fails lint.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined

# Reuse the linter to refuse generation on bad input.
sys.path.insert(0, str(Path(__file__).parent))
from lint_protomap import lint_doc  # noqa: E402


# ---------------------------------------------------------------------------
# Jinja filters / helpers
# ---------------------------------------------------------------------------
def c_int_literal(v: Any) -> str:
    if isinstance(v, int):
        return f"0x{v:X}"
    return str(v)


def c_uint_type(bits: int) -> str:
    if bits <= 8:
        return "std::uint8_t"
    if bits <= 16:
        return "std::uint16_t"
    if bits <= 32:
        return "std::uint32_t"
    return "std::uint64_t"


def normalize_hex(s: str) -> str:
    """Strip whitespace + uppercase hex string. Empty stays empty."""
    return "".join(ch for ch in s.upper() if ch in "0123456789ABCDEF")


def _normalize_payload_hex_recursive(obj: Any) -> Any:
    """Walk an `expected` blob and uppercase+strip every payload_hex string.

    Handles the M6 nested-element layout where the parent fixture's
    `expected.elements[i].payload_hex` is several levels deep.
    """
    if isinstance(obj, dict):
        return {
            k: (normalize_hex(v) if k == "payload_hex" and isinstance(v, str)
                else _normalize_payload_hex_recursive(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_normalize_payload_hex_recursive(x) for x in obj]
    return obj


def normalize_fixture(fx: dict, header_fields: list[dict]) -> dict:
    """Return a fixture with .raw_hex stripped + .expected_json baked.

    `expected_json` is the JSON serialization of `expected` with all
    payload_hex values (at any nesting depth) uppercased+whitespace-
    stripped, ready to be embedded in a C++ raw string literal.
    """
    out = dict(fx)
    out["raw_hex"] = normalize_hex(fx["raw_hex"])
    expected = _normalize_payload_hex_recursive(fx.get("expected", {}))
    out["expected_json"] = json.dumps(expected, separators=(",", ":"))
    return out


# ---------------------------------------------------------------------------
# Load + render
# ---------------------------------------------------------------------------
def load_protocols(in_dir: Path) -> list[dict]:
    files = sorted(in_dir.glob("*.yaml"))
    if not files:
        raise SystemExit(f"codegen: no .yaml files under {in_dir}")

    # Two-pass parse: first collect protocol names so cross-file lint
    # checks (e.g., `repeated.element` references) can resolve.
    parsed: list[tuple[Path, dict]] = []
    known_protocols: set[str] = set()
    for f in files:
        try:
            doc = yaml.safe_load(f.read_text())
        except yaml.YAMLError as exc:
            raise SystemExit(f"codegen: YAML parse error in {f}: {exc}") from exc
        parsed.append((f, doc))
        try:
            known_protocols.add(doc["protocol"]["name"])
        except (KeyError, TypeError):
            pass  # missing/invalid name will be reported by lint

    docs = []
    for f, doc in parsed:
        errs = lint_doc(doc, known_protocols=known_protocols)
        if errs:
            print(f"codegen: refusing to generate from {f.name}:", file=sys.stderr)
            for e in errs:
                print(f"  - {e}", file=sys.stderr)
            raise SystemExit(2)

        doc["__source"] = f.name
        docs.append(doc)
    return docs


def make_env() -> Environment:
    template_dir = Path(__file__).parent / "codegen_templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["c_int_literal"] = c_int_literal
    env.filters["c_uint_type"] = c_uint_type
    return env


PROTO_OUTPUTS: list[tuple[str, str]] = [
    ("types.h.j2", "{name}_types.h"),
    ("decoder.h.j2", "{name}_decoder.h"),
    ("decoder.cc.j2", "{name}_decoder.cc"),
    ("encoder.h.j2", "{name}_encoder.h"),
    ("encoder.cc.j2", "{name}_encoder.cc"),
    ("tojson.h.j2", "{name}_tojson.h"),
    ("tojson.cc.j2", "{name}_tojson.cc"),
    ("fromjson.h.j2", "{name}_fromjson.h"),
    ("fromjson.cc.j2", "{name}_fromjson.cc"),
    ("fixtures_test.cc.j2", "{name}_fixtures_test.cc"),
]


def render_protocol(env: Environment, doc: dict, out_dir: Path) -> list[Path]:
    p = doc["protocol"]
    header = doc.get("header") or {}
    payload = doc.get("payload")
    repeated = doc.get("repeated")
    enums = doc.get("enums") or {}
    raw_fixtures = doc.get("fixtures") or []
    fixtures = [
        normalize_fixture(fx, header.get("fields", [])) for fx in raw_fixtures
    ]

    ctx = dict(
        p=p,
        enums=enums,
        header=header,
        payload=payload,
        repeated=repeated,
        fixtures=fixtures,
        source=doc.get("__source", ""),
    )

    written: list[Path] = []
    for tmpl_name, out_pattern in PROTO_OUTPUTS:
        tmpl = env.get_template(tmpl_name)
        out_path = out_dir / out_pattern.format(name=p["name"])
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(tmpl.render(**ctx))
        written.append(out_path)
    return written


# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="atsc3_proto YAML → C++ codegen")
    ap.add_argument("--in", dest="indir", required=True,
                    help="protocol/ directory containing *.yaml")
    ap.add_argument("--out", dest="outdir", required=True,
                    help="lib/generated/ directory to write into")
    ap.add_argument("--list-outputs", action="store_true",
                    help="print files that would be written and exit 0")
    args = ap.parse_args()

    in_dir = Path(args.indir).resolve()
    out_dir = Path(args.outdir).resolve()

    docs = load_protocols(in_dir)
    if not docs:
        return 0

    env = make_env()

    if args.list_outputs:
        for d in docs:
            for _, pattern in PROTO_OUTPUTS:
                print(out_dir / pattern.format(name=d["protocol"]["name"]))
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)

    total_files = 0
    for d in docs:
        files = render_protocol(env, d, out_dir)
        total_files += len(files)
        print(f"codegen: {d['__source']:>20s} -> {len(files)} files")

    print(f"codegen: wrote {total_files} files into {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

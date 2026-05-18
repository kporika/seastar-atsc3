#!/usr/bin/env python3
"""Generate ACR–ACY integration phases (PA + MPT asset in §10.3 consumption message)."""

from __future__ import annotations

PHASES = [
    {
        "phase": "ACR",
        "port_off": 702000,
        "src": "ZK",
        "table_hex": "2001001300000000010000000000000000000000000000",
        "body_var": "zk_payloads",
        "validate": ["--validate-mmt-si-mpt-table-body", "--validate-mmt-si-mpt-asset"],
        "table_length": 19,
        "assets": 1,
        "asset_id_len": 0,
        "asset_id": None,
        "loc_count": 0,
        "desc_len": 0,
    },
    {
        "phase": "ACS",
        "port_off": 703000,
        "src": "ZS",
        "table_hex": "200100140000000001000000000001010000000000000000",
        "body_var": "zs_payloads",
        "validate": ["--validate-mmt-si-mpt-table-body", "--validate-mmt-si-mpt-asset-id8"],
        "table_length": 20,
        "assets": 1,
        "asset_id_len": 1,
        "asset_id": 1,
        "loc_count": 0,
        "desc_len": 0,
    },
    {
        "phase": "ACT",
        "port_off": 704000,
        "src": "AAC",
        "table_hex": "2001001700000000010000000000000000000000000004DEADBEEF",
        "body_var": "aac_payloads",
        "validate": [
            "--validate-mmt-si-mpt-table-body",
            "--validate-mmt-si-mpt-asset-descriptors4",
        ],
        "table_length": 23,
        "assets": 1,
        "asset_id_len": 0,
        "asset_id": None,
        "loc_count": 0,
        "desc_len": 4,
    },
    {
        "phase": "ACU",
        "port_off": 705000,
        "src": "ZT",
        "table_hex": "2001001600000000010000000000000000000000010000000000",
        "body_var": "zt_payloads",
        "validate": [
            "--validate-mmt-si-mpt-table-body",
            "--validate-mmt-si-mpt-asset-location0",
        ],
        "table_length": 22,
        "assets": 1,
        "asset_id_len": 0,
        "asset_id": None,
        "loc_count": 1,
        "desc_len": 0,
        "extra_probe": [
            "--expect-mmt-si-mpt-asset-location-type 0",
            "--expect-mmt-si-mpt-asset-packet-id 0",
        ],
    },
    {
        "phase": "ACV",
        "port_off": 706000,
        "src": "ZV",
        "table_hex": "2001001e000000000100000000000000000000000101000000000000000000000000",
        "body_var": "zv_payloads",
        "validate": [
            "--validate-mmt-si-mpt-table-body",
            "--validate-mmt-si-mpt-asset-location-ipv4",
        ],
        "table_length": 30,
        "assets": 1,
        "asset_id_len": 0,
        "asset_id": None,
        "loc_count": 1,
        "desc_len": 0,
        "extra_probe": [
            "--expect-mmt-si-mpt-asset-location-type 1",
            "--expect-mmt-si-mpt-asset-ipv4-dst-port 0",
        ],
    },
    {
        "phase": "ACW",
        "port_off": 707000,
        "src": "ZY",
        "table_hex": (
            "200100360000000001000000000000000000000001020000000000000000"
            "000000000000000000000000000000000000000000000000000000000000"
        ),
        "body_var": "zy_payloads",
        "validate": [
            "--validate-mmt-si-mpt-table-body",
            "--validate-mmt-si-mpt-asset-location-ipv6",
        ],
        "table_length": 54,
        "assets": 1,
        "asset_id_len": 0,
        "asset_id": None,
        "loc_count": 1,
        "desc_len": 0,
        "extra_probe": [
            "--expect-mmt-si-mpt-asset-location-type 2",
            "--expect-mmt-si-mpt-asset-ipv6-dst-port 0",
        ],
    },
    {
        "phase": "ACX",
        "port_off": 708000,
        "src": "AAG",
        "table_hex": "20010015000000000100000000000201020000000000000000",
        "body_var": "aag_payloads",
        "validate": ["--validate-mmt-si-mpt-table-body", "--validate-mmt-si-mpt-asset-id16"],
        "table_length": 21,
        "assets": 1,
        "asset_id_len": 2,
        "asset_id": None,
        "loc_count": 0,
        "desc_len": 0,
        "extra_probe": [
            "--expect-mmt-si-mpt-asset-id16-byte0 1",
            "--expect-mmt-si-mpt-asset-id16-byte1 2",
        ],
    },
    {
        "phase": "ACY",
        "port_off": 709000,
        "src": "AAF",
        "table_hex": (
            "2001001e0000000001000000000000000000000001010a000001e000000113880000"
        ),
        "body_var": "aaf_payloads",
        "validate": [
            "--validate-mmt-si-mpt-table-body",
            "--validate-mmt-si-mpt-asset-location-ipv4-nz",
        ],
        "table_length": 30,
        "assets": 1,
        "asset_id_len": 0,
        "asset_id": None,
        "loc_count": 1,
        "desc_len": 0,
        "extra_probe": [
            "--expect-mmt-si-mpt-asset-location-type 1",
            "--expect-mmt-si-mpt-asset-ipv4-src-addr 167772161",
            "--expect-mmt-si-mpt-asset-ipv4-dst-addr 3758096385",
            "--expect-mmt-si-mpt-asset-ipv4-dst-port 5000",
        ],
    },
]


def pa_prefix(table_hex: str) -> tuple[str, int]:
    n = len(bytes.fromhex(table_hex))
    pa = f"0100042001{n:04x}"
    assert len(bytes.fromhex(pa)) == 7
    combo = pa + table_hex
    assert len(bytes.fromhex(combo)) == 7 + n
    return combo, 7 + n


def rep4(flag: str, val: str) -> list[str]:
    return [f"    {flag} {val} \\" for _ in range(4)]


def emit_phase(p: dict) -> str:
    phase = p["phase"]
    port = p["port_off"]
    combo, msg_len = pa_prefix(p["table_hex"])
    low = phase.lower()
    lines: list[str] = []
    lines.append(f'{low}_payload="{combo}"')
    pl = "${" + low + "_payload}"
    lines.append(f'{low}_payloads="{pl},{pl},{pl},{pl}"')
    lines.append(f'saved_payloads_{low}="${{payloads}}"')
    lines.append('payloads="${' + low + '_payloads}"')
    lines.append("")
    val_flags = " \\\n    ".join(p["validate"])
    lines.append(
        f'echo "[mmtp_word0_integ] phase {phase}: consumption (message_id=0) + PA + MPT asset ({p["src"]} ingress)"'
    )
    lines.append(
        f'run_phase "{phase}" "${{port_{low}}}" "${{tmpdir}}/{low}.out" "${{tmpdir}}/gw_{low}.log" \\'
    )
    lines.append("    --prepend-mmtp-word0 \\")
    lines.append('    --mmtp-payload-type "${mmtp_pt}" \\')
    lines.append('    --mmtp-packet-id "${mmtp_pid}" \\')
    lines.append("    --prepend-mmtp-signalling-prefix \\")
    lines.append("    --prepend-mmt-si-message-header-len32 \\")
    lines.append("    --mmtp-si-message-id 0 \\")
    lines.append("    --mmtp-si-message-version 1 \\")
    lines.append(f"    {val_flags}")
    lines.append('"${probe_bin}" verify \\')
    lines.append(f'    --file "${{tmpdir}}/{low}.out.shard0" \\')
    lines.append("    --strip-mmtp-word0 \\")
    lines.append('    --expect-mmtp-payload-type "${mmtp_pt}" \\')
    lines.append('    --expect-mmtp-packet-id "${mmtp_pid}" \\')
    lines.append("    --strip-mmtp-signalling-prefix \\")
    for flag in rep4("--expect-mmtp-signalling-fragmentation", "0"):
        lines.append(flag)
    for flag in rep4("--expect-mmtp-signalling-reserved", "0"):
        lines.append(flag)
    for flag in rep4("--expect-mmtp-signalling-length-extension", "0"):
        lines.append(flag)
    for flag in rep4("--expect-mmtp-signalling-aggregation", "0"):
        lines.append(flag)
    for flag in rep4("--expect-mmtp-signalling-fragment-counter", "0"):
        lines.append(flag)
    lines.append("    --strip-mmt-si-message-header-len32 \\")
    for flag in rep4("--expect-mmt-si-message-id", "0"):
        lines.append(flag)
    for flag in rep4("--expect-mmt-si-message-version", "1"):
        lines.append(flag)
    for flag in rep4("--expect-mmt-si-message-byte-length", str(msg_len)):
        lines.append(flag)
    lines.append("    --strip-mmt-si-pa-table-headers \\")
    for flag in rep4("--expect-mmt-si-pa-number-of-tables", "1"):
        lines.append(flag)
    for flag in rep4("--expect-mmt-si-mpt-table-id", "32"):
        lines.append(flag)
    for flag in rep4("--expect-mmt-si-mpt-table-length", str(p["table_length"])):
        lines.append(flag)
    for flag in rep4("--expect-mmt-si-mpt-table-body-num-assets", str(p["assets"])):
        lines.append(flag)
    for flag in rep4("--expect-mmt-si-mpt-asset-id-length", str(p["asset_id_len"])):
        lines.append(flag)
    if p["asset_id"] is not None:
        for flag in rep4("--expect-mmt-si-mpt-asset-asset-id", str(p["asset_id"])):
            lines.append(flag)
    for flag in rep4("--expect-mmt-si-mpt-asset-location-count", str(p["loc_count"])):
        lines.append(flag)
    for flag in rep4(
        "--expect-mmt-si-mpt-asset-descriptors-length", str(p["desc_len"])
    ):
        lines.append(flag)
    for extra in p.get("extra_probe", []):
        flag, val = extra.rsplit(" ", 1)
        for line in rep4(flag, val):
            lines.append(line)
    lines.append(f'    --expected-payloads "${{{p["body_var"]}}}"')
    lines.append("")
    lines.append(f'payloads="${{saved_payloads_{low}}}"')
    lines.append("")
    return "\n".join(lines)


def emit_ports() -> str:
    lines = []
    for p in PHASES:
        low = p["phase"].lower()
        lines.append(f'port_{low}=$(( ( RANDOM % 10000 ) + {p["port_off"]} ))')
    return "\n".join(lines)


def load_table_hex_from_script() -> None:
    import pathlib
    import re

    script = (
        pathlib.Path(__file__).resolve().parent.parent
        / "scripts"
        / "mmtp_word0_integration_test.sh"
    ).read_text()
    src_to_var = {
        "ZK": "zk",
        "ZS": "zs",
        "AAC": "aac",
        "ZT": "zt",
        "ZV": "zv",
        "ZY": "zy",
        "AAG": "aag",
        "AAF": "aaf",
    }
    for p in PHASES:
        var = src_to_var[p["src"]]
        m = re.search(rf'{var}_payload="([0-9a-fA-F]+)"', script)
        if not m:
            m = re.search(rf'{var}_payloads="([0-9a-fA-F]+)', script)
        if not m:
            raise SystemExit(f"missing {var}_payload in integration script")
        p["table_hex"] = m.group(1)
        wire = len(bytes.fromhex(p["table_hex"]))
        p["table_length"] = wire - 4


def main() -> None:
    import pathlib

    load_table_hex_from_script()
    for p in PHASES:
        h = p["table_hex"]
        n = len(bytes.fromhex(h))
        _, msg = pa_prefix(h)
        if p["table_length"] + 4 != n:
            raise SystemExit(
                f"{p['phase']}: table wire {n} != 4+table_length {p['table_length'] + 4}"
            )
        print(f"{p['phase']}: table={n} msg={msg}")

    out = pathlib.Path(__file__).resolve().parent / "_gen" / "acr_acy_integ.sh"
    out.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(emit_phase(p) for p in PHASES)
    out.write_text(body + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(body)} bytes)")
    print("\n# ports:")
    print(emit_ports())


if __name__ == "__main__":
    main()

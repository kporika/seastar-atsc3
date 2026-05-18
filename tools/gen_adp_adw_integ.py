#!/usr/bin/env python3
"""Generate ADP–ADW integration phases (PA + MPT asset location matrix in §10.3 consumption)."""

from __future__ import annotations

PHASES = [
    {
        "phase": "ADP",
        "port_off": 726000,
        "src": "ZW",
        "table_hex": "2001001f00000000010000000000010100000000000101000000000000000000000000",
        "body_var": "zw_payloads",
        "validate": [
            "--validate-mmt-si-mpt-table-body",
            "--validate-mmt-si-mpt-asset-id8-location-ipv4",
        ],
        "table_length": 31,
        "assets": 1,
        "asset_id_len": 1,
        "asset_id": 1,
        "loc_count": 1,
        "desc_len": 0,
        "extra_probe": [
            "--expect-mmt-si-mpt-asset-location-type 1",
            "--expect-mmt-si-mpt-asset-ipv4-dst-port 0",
        ],
    },
    {
        "phase": "ADQ",
        "port_off": 727000,
        "src": "AAA",
        "table_hex": (
            "200100370000000001000000000001010000000000010200000000000000"
            "00000000000000000000000000000000000000000000000000000000000000"
        ),
        "body_var": "aaa_payloads",
        "validate": [
            "--validate-mmt-si-mpt-table-body",
            "--validate-mmt-si-mpt-asset-id8-location-ipv6",
        ],
        "table_length": 55,
        "assets": 1,
        "asset_id_len": 1,
        "asset_id": 1,
        "loc_count": 1,
        "desc_len": 0,
        "extra_probe": [
            "--expect-mmt-si-mpt-asset-location-type 2",
            "--expect-mmt-si-mpt-asset-ipv6-dst-port 0",
        ],
    },
    {
        "phase": "ADR",
        "port_off": 728000,
        "src": "AAH",
        "table_hex": (
            "200100360000000001000000000000000000000001020000000000000000"
            "0000ffff0a00000100000000000000000000ffffe000000113880000"
        ),
        "body_var": "aah_payloads",
        "validate": [
            "--validate-mmt-si-mpt-table-body",
            "--validate-mmt-si-mpt-asset-location-ipv6-nz",
        ],
        "table_length": 54,
        "assets": 1,
        "asset_id_len": 0,
        "asset_id": None,
        "loc_count": 1,
        "desc_len": 0,
        "extra_probe": [
            "--expect-mmt-si-mpt-asset-location-type 2",
            "--expect-mmt-si-mpt-asset-ipv6-src-addr-3 167772161",
            "--expect-mmt-si-mpt-asset-ipv6-dst-addr-3 3758096385",
            "--expect-mmt-si-mpt-asset-ipv6-dst-port 5000",
        ],
    },
    {
        "phase": "ADS",
        "port_off": 729000,
        "src": "AAM",
        "table_hex": (
            "2001001f000000000100000000000101000000000001010a000001e000000113880000"
        ),
        "body_var": "aam_payloads",
        "validate": [
            "--validate-mmt-si-mpt-table-body",
            "--validate-mmt-si-mpt-asset-id8-location-ipv4-nz",
        ],
        "table_length": 31,
        "assets": 1,
        "asset_id_len": 1,
        "asset_id": 1,
        "loc_count": 1,
        "desc_len": 0,
        "extra_probe": [
            "--expect-mmt-si-mpt-asset-location-type 1",
            "--expect-mmt-si-mpt-asset-ipv4-src-addr 167772161",
            "--expect-mmt-si-mpt-asset-ipv4-dst-addr 3758096385",
            "--expect-mmt-si-mpt-asset-ipv4-dst-port 5000",
        ],
    },
    {
        "phase": "ADT",
        "port_off": 730000,
        "src": "AAN",
        "table_hex": (
            "200100370000000001000000000001010000000000010200000000000000"
            "000000ffff0a00000100000000000000000000ffffe000000113880000"
        ),
        "body_var": "aan_payloads",
        "validate": [
            "--validate-mmt-si-mpt-table-body",
            "--validate-mmt-si-mpt-asset-id8-location-ipv6-nz",
        ],
        "table_length": 55,
        "assets": 1,
        "asset_id_len": 1,
        "asset_id": 1,
        "loc_count": 1,
        "desc_len": 0,
        "extra_probe": [
            "--expect-mmt-si-mpt-asset-location-type 2",
            "--expect-mmt-si-mpt-asset-ipv6-src-addr-3 167772161",
            "--expect-mmt-si-mpt-asset-ipv6-dst-addr-3 3758096385",
            "--expect-mmt-si-mpt-asset-ipv6-dst-port 5000",
        ],
    },
    {
        "phase": "ADU",
        "port_off": 731000,
        "src": "AAO",
        "table_hex": (
            "200100200000000001000000000002010200000000000101000000000000000000000000"
        ),
        "body_var": "aao_payloads",
        "validate": [
            "--validate-mmt-si-mpt-table-body",
            "--validate-mmt-si-mpt-asset-id16-location-ipv4",
        ],
        "table_length": 32,
        "assets": 1,
        "asset_id_len": 2,
        "asset_id": None,
        "loc_count": 1,
        "desc_len": 0,
        "extra_probe": [
            "--expect-mmt-si-mpt-asset-id16-byte0 1",
            "--expect-mmt-si-mpt-asset-id16-byte1 2",
            "--expect-mmt-si-mpt-asset-location-type 1",
            "--expect-mmt-si-mpt-asset-ipv4-dst-port 0",
        ],
    },
    {
        "phase": "ADV",
        "port_off": 732000,
        "src": "AAP",
        "table_hex": (
            "2001002000000000010000000000020102000000000001010a000001e000000113880000"
        ),
        "body_var": "aap_payloads",
        "validate": [
            "--validate-mmt-si-mpt-table-body",
            "--validate-mmt-si-mpt-asset-id16-location-ipv4-nz",
        ],
        "table_length": 32,
        "assets": 1,
        "asset_id_len": 2,
        "asset_id": None,
        "loc_count": 1,
        "desc_len": 0,
        "extra_probe": [
            "--expect-mmt-si-mpt-asset-id16-byte0 1",
            "--expect-mmt-si-mpt-asset-id16-byte1 2",
            "--expect-mmt-si-mpt-asset-location-type 1",
            "--expect-mmt-si-mpt-asset-ipv4-src-addr 167772161",
            "--expect-mmt-si-mpt-asset-ipv4-dst-addr 3758096385",
            "--expect-mmt-si-mpt-asset-ipv4-dst-port 5000",
        ],
    },
    {
        "phase": "ADW",
        "port_off": 733000,
        "src": "AAQ",
        "table_hex": (
            "200100370000000001000000000002010200000000000102000000000000"
            "000000000000000000000000000000000000000000000000000000000000"
        ),
        "body_var": "aaq_payloads",
        "validate": [
            "--validate-mmt-si-mpt-table-body",
            "--validate-mmt-si-mpt-asset-id16-location-ipv6",
        ],
        "table_length": 55,
        "assets": 1,
        "asset_id_len": 2,
        "asset_id": None,
        "loc_count": 1,
        "desc_len": 0,
        "extra_probe": [
            "--expect-mmt-si-mpt-asset-id16-byte0 1",
            "--expect-mmt-si-mpt-asset-id16-byte1 2",
            "--expect-mmt-si-mpt-asset-location-type 2",
            "--expect-mmt-si-mpt-asset-ipv6-dst-port 0",
        ],
    },
]


def pa_prefix(table_hex: str) -> tuple[str, int]:
    n = len(bytes.fromhex(table_hex))
    pa = f"0100042001{n:04x}"
    combo = pa + table_hex
    return combo, 7 + n


def rep4(flag: str, val: str) -> list[str]:
    return [f"    {flag} {val} \\" for _ in range(4)]


def emit_phase(p: dict) -> str:
    phase = p["phase"]
    combo, msg_len = pa_prefix(p["table_hex"])
    low = phase.lower()
    val_flags = " \\\n    ".join(p["validate"])
    lines: list[str] = []
    lines.append(f'{low}_payload="{combo}"')
    pl = "${" + low + "_payload}"
    lines.append(f'{low}_payloads="{pl},{pl},{pl},{pl}"')
    lines.append(f'saved_payloads_{low}="${{payloads}}"')
    lines.append('payloads="${' + low + '_payloads}"')
    lines.append("")
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
    for flag in rep4("--expect-mmt-si-mpt-asset-descriptors-length", str(p["desc_len"])):
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


def load_table_hex_from_script() -> None:
    import pathlib
    import re

    script = (
        pathlib.Path(__file__).resolve().parent.parent
        / "scripts"
        / "mmtp_word0_integration_test.sh"
    ).read_text()
    src_to_var = {
        "ZW": "zw",
        "AAA": "aaa",
        "AAH": "aah",
        "AAM": "aam",
        "AAN": "aan",
        "AAO": "aao",
        "AAP": "aap",
        "AAQ": "aaq",
    }
    for p in PHASES:
        var = src_to_var[p["src"]]
        m = re.search(rf'{var}_payload="([0-9a-f]+)"', script)
        if not m:
            raise SystemExit(f"missing {var}_payload in integration script")
        p["table_hex"] = m.group(1)


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

    out = pathlib.Path(__file__).resolve().parent / "_gen" / "adp_adw_integ.sh"
    out.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(emit_phase(p) for p in PHASES)
    out.write_text(body + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(body)} bytes)")


if __name__ == "__main__":
    main()

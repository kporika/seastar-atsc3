#!/usr/bin/env python3
"""Generate ADX–AEA integration phases (PA inline in §10.3 consumption message_id=0)."""

from __future__ import annotations

MPT_PHASES = [
    {
        "phase": "ADX",
        "port_off": 734000,
        "src": "AAR",
        "body_var": "aar_payloads",
        "validate": [
            "--validate-mmt-si-mpt-table-body",
            "--validate-mmt-si-mpt-asset-id16-location-ipv6-nz",
        ],
        "table_length": 56,
        "assets": 1,
        "asset_id_len": 2,
        "loc_count": 1,
        "desc_len": 0,
        "extra_probe": [
            "--expect-mmt-si-mpt-asset-id16-byte0 1",
            "--expect-mmt-si-mpt-asset-id16-byte1 2",
            "--expect-mmt-si-mpt-asset-location-type 2",
            "--expect-mmt-si-mpt-asset-ipv6-src-addr-3 167772161",
            "--expect-mmt-si-mpt-asset-ipv6-dst-addr-3 3758096385",
            "--expect-mmt-si-mpt-asset-ipv6-dst-port 5000",
        ],
    },
    {
        "phase": "ADY",
        "port_off": 735000,
        "src": "AAS",
        "body_var": "aas_payloads",
        "validate": [
            "--validate-mmt-si-mpt-table-body",
            "--validate-mmt-si-mpt-asset-id16-descriptors4",
        ],
        "table_length": 25,
        "assets": 1,
        "asset_id_len": 2,
        "loc_count": 0,
        "desc_len": 4,
        "extra_probe": [
            "--expect-mmt-si-mpt-asset-id16-byte0 1",
            "--expect-mmt-si-mpt-asset-id16-byte1 2",
        ],
    },
    {
        "phase": "ADZ",
        "port_off": 736000,
        "src": "AAT",
        "body_var": "aat_payloads",
        "validate": [
            "--validate-mmt-si-mpt-table-body",
            "--validate-mmt-si-mpt-asset-id8-descriptors4",
        ],
        "table_length": 24,
        "assets": 1,
        "asset_id_len": 1,
        "asset_id": 1,
        "loc_count": 0,
        "desc_len": 4,
        "extra_probe": [],
    },
]

PLT_PHASES = [
    {
        "phase": "AEA",
        "port_off": 737000,
        "src": "AAJ",
        "body_var": "aaj_payloads",
        "validate": [
            "--validate-mmt-si-plt-table-body",
            "--validate-mmt-si-plt-package-entry-ipv6-nz",
        ],
        "table_length": 38,
        "extra_probe": [
            "--expect-mmt-si-plt-table-body-num-packages 1",
            "--expect-mmt-si-plt-table-body-num-ip-delivery 0",
            "--expect-mmt-si-plt-package-id-length 0",
            "--expect-mmt-si-plt-package-location-type 2",
            "--expect-mmt-si-plt-package-ipv6-src-addr-3 167772161",
            "--expect-mmt-si-plt-package-ipv6-dst-addr-3 3758096385",
            "--expect-mmt-si-plt-package-ipv6-dst-port 5000",
        ],
    },
]


def pa_prefix_mpt(table_hex: str) -> tuple[str, int]:
    n = len(bytes.fromhex(table_hex))
    pa = f"0100042001{n:04x}"
    combo = pa + table_hex
    return combo, 7 + n


def pa_prefix_plt(table_hex: str) -> tuple[str, int]:
    n = len(bytes.fromhex(table_hex))
    pa = f"0100048000{n:04x}"
    combo = pa + table_hex
    return combo, 7 + n


def rep4(flag: str, val: str) -> list[str]:
    return [f"    {flag} {val} \\" for _ in range(4)]


def emit_mpt_phase(p: dict) -> str:
    phase = p["phase"]
    combo, msg_len = pa_prefix_mpt(p["table_hex"])
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
    if p.get("asset_id") is not None:
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


def emit_plt_phase(p: dict) -> str:
    phase = p["phase"]
    combo, msg_len = pa_prefix_plt(p["table_hex"])
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
        f'echo "[mmtp_word0_integ] phase {phase}: consumption (message_id=0) + PA + PLT ({p["src"]} ingress)"'
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
    for flag in rep4("--expect-mmt-si-plt-table-id", "128"):
        lines.append(flag)
    for flag in rep4("--expect-mmt-si-plt-table-length", str(p["table_length"])):
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
    src_to_var = {"AAR": "aar", "AAS": "aas", "AAT": "aat", "AAJ": "aaj"}
    for phases in (MPT_PHASES, PLT_PHASES):
        for p in phases:
            var = src_to_var[p["src"]]
            m = re.search(rf'{var}_payload="([0-9a-f]+)"', script)
            if not m:
                raise SystemExit(f"missing {var}_payload in integration script")
            p["table_hex"] = m.group(1)


def main() -> None:
    import pathlib

    load_table_hex_from_script()
    for p in MPT_PHASES:
        h = p["table_hex"]
        n = len(bytes.fromhex(h))
        if p["table_length"] + 4 != n:
            raise SystemExit(
                f"{p['phase']}: table wire {n} != 4+table_length {p['table_length'] + 4}"
            )
        _, msg = pa_prefix_mpt(h)
        print(f"{p['phase']}: table={n} msg={msg}")
    for p in PLT_PHASES:
        h = p["table_hex"]
        n = len(bytes.fromhex(h))
        if p["table_length"] + 4 != n:
            raise SystemExit(
                f"{p['phase']}: table wire {n} != 4+table_length {p['table_length'] + 4}"
            )
        _, msg = pa_prefix_plt(h)
        print(f"{p['phase']}: table={n} msg={msg}")

    out = pathlib.Path(__file__).resolve().parent / "_gen" / "adx_aea_integ.sh"
    out.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(emit_mpt_phase(p) for p in MPT_PHASES) + "\n".join(
        emit_plt_phase(p) for p in PLT_PHASES
    )
    out.write_text(body + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(body)} bytes)")


if __name__ == "__main__":
    main()

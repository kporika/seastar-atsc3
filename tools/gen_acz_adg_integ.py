#!/usr/bin/env python3
"""Generate ACZ–ADG integration phases (PA + PLT delivery/package in §10.3 consumption)."""

from __future__ import annotations

PHASES = [
    {
        "phase": "ACZ",
        "port_off": 710000,
        "src": "ZL",
        "table_hex": "80000009000100000000000000",
        "body_var": "zl_payloads",
        "validate": [
            "--validate-mmt-si-plt-table-body",
            "--validate-mmt-si-plt-delivery-info",
        ],
        "table_length": 9,
        "extra_probe": [
            "--expect-mmt-si-plt-table-body-num-packages 0",
            "--expect-mmt-si-plt-table-body-num-ip-delivery 1",
            "--expect-mmt-si-plt-delivery-info-location-type 0",
            "--expect-mmt-si-plt-delivery-info-descriptor-loop-length 0",
        ],
    },
    {
        "phase": "ADA",
        "port_off": 711000,
        "src": "ZP",
        "table_hex": "80000006010000000000",
        "body_var": "zp_payloads",
        "validate": [
            "--validate-mmt-si-plt-table-body",
            "--validate-mmt-si-plt-package-entry",
        ],
        "table_length": 6,
        "extra_probe": [
            "--expect-mmt-si-plt-table-body-num-packages 1",
            "--expect-mmt-si-plt-table-body-num-ip-delivery 0",
            "--expect-mmt-si-plt-package-id-length 0",
            "--expect-mmt-si-plt-package-location-type 0",
            "--expect-mmt-si-plt-package-packet-id 0",
        ],
    },
    {
        "phase": "ADB",
        "port_off": 712000,
        "src": "ZM",
        "table_hex": "8000001300010000000001000000000000000000000000",
        "body_var": "zm_payloads",
        "validate": [
            "--validate-mmt-si-plt-table-body",
            "--validate-mmt-si-plt-delivery-info-ipv4",
        ],
        "table_length": 19,
        "extra_probe": [
            "--expect-mmt-si-plt-table-body-num-packages 0",
            "--expect-mmt-si-plt-table-body-num-ip-delivery 1",
            "--expect-mmt-si-plt-delivery-info-location-type 1",
        ],
    },
    {
        "phase": "ADC",
        "port_off": 713000,
        "src": "ZN",
        "table_hex": (
            "8000002b000100000000020000000000000000000000000000000000"
            "00000000000000000000000000000000000000"
        ),
        "body_var": "zn_payloads",
        "validate": [
            "--validate-mmt-si-plt-table-body",
            "--validate-mmt-si-plt-delivery-info-ipv6",
        ],
        "table_length": 43,
        "extra_probe": [
            "--expect-mmt-si-plt-table-body-num-packages 0",
            "--expect-mmt-si-plt-table-body-num-ip-delivery 1",
            "--expect-mmt-si-plt-delivery-info-location-type 2",
        ],
    },
    {
        "phase": "ADD",
        "port_off": 714000,
        "src": "ZO",
        "table_hex": "8000000a00010000000005000000",
        "body_var": "zo_payloads",
        "validate": [
            "--validate-mmt-si-plt-table-body",
            "--validate-mmt-si-plt-delivery-info-url",
        ],
        "table_length": 10,
        "extra_probe": [
            "--expect-mmt-si-plt-table-body-num-packages 0",
            "--expect-mmt-si-plt-table-body-num-ip-delivery 1",
            "--expect-mmt-si-plt-delivery-info-location-type 5",
        ],
    },
    {
        "phase": "ADE",
        "port_off": 715000,
        "src": "ZR",
        "table_hex": "8000000701000101000000",
        "body_var": "zr_payloads",
        "validate": [
            "--validate-mmt-si-plt-table-body",
            "--validate-mmt-si-plt-package-entry-id8",
        ],
        "table_length": 7,
        "extra_probe": [
            "--expect-mmt-si-plt-table-body-num-packages 1",
            "--expect-mmt-si-plt-table-body-num-ip-delivery 0",
            "--expect-mmt-si-plt-package-id-length 1",
            "--expect-mmt-si-plt-package-mmt-package-id 1",
            "--expect-mmt-si-plt-package-location-type 0",
            "--expect-mmt-si-plt-package-packet-id 0",
        ],
    },
    {
        "phase": "ADF",
        "port_off": 716000,
        "src": "ZU",
        "table_hex": "8000000e0100000100000000000000000000",
        "body_var": "zu_payloads",
        "validate": [
            "--validate-mmt-si-plt-table-body",
            "--validate-mmt-si-plt-package-entry-ipv4",
        ],
        "table_length": 14,
        "extra_probe": [
            "--expect-mmt-si-plt-table-body-num-packages 1",
            "--expect-mmt-si-plt-table-body-num-ip-delivery 0",
            "--expect-mmt-si-plt-package-id-length 0",
            "--expect-mmt-si-plt-package-location-type 1",
            "--expect-mmt-si-plt-package-packet-id 0",
        ],
    },
    {
        "phase": "ADG",
        "port_off": 717000,
        "src": "AAE",
        "table_hex": "80000013000100000000010a000001e000000113880000",
        "body_var": "aae_payloads",
        "validate": [
            "--validate-mmt-si-plt-table-body",
            "--validate-mmt-si-plt-delivery-info-ipv4-nz",
        ],
        "table_length": 19,
        "extra_probe": [
            "--expect-mmt-si-plt-table-body-num-packages 0",
            "--expect-mmt-si-plt-table-body-num-ip-delivery 1",
            "--expect-mmt-si-plt-delivery-info-location-type 1",
            "--expect-mmt-si-plt-delivery-info-ipv4-src-addr 167772161",
            "--expect-mmt-si-plt-delivery-info-ipv4-dst-addr 3758096385",
            "--expect-mmt-si-plt-delivery-info-ipv4-dst-port 5000",
        ],
    },
]


def pa_prefix_plt(table_hex: str) -> tuple[str, int]:
    n = len(bytes.fromhex(table_hex))
    pa = f"0100048000{n:04x}"
    assert len(bytes.fromhex(pa)) == 7
    combo = pa + table_hex
    assert len(bytes.fromhex(combo)) == 7 + n
    return combo, 7 + n


def rep4(flag: str, val: str) -> list[str]:
    return [f"    {flag} {val} \\" for _ in range(4)]


def emit_phase(p: dict) -> str:
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


def main() -> None:
    import pathlib

    out = pathlib.Path(__file__).resolve().parent / "_gen" / "acz_adg_integ.sh"
    out.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(emit_phase(p) for p in PHASES)
    out.write_text(body + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(body)} bytes)")


if __name__ == "__main__":
    main()

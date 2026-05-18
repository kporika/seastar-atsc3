#!/usr/bin/env python3
"""Generate ADH–ADO integration phases (PA + PLT URL/location in §10.3 consumption)."""

from __future__ import annotations

PHASES = [
    {
        "phase": "ADH",
        "port_off": 718000,
        "src": "ZQ",
        "table_hex": "8000000d00010000000005036c61620000",
        "body_var": "zq_payloads",
        "validate": [
            "--validate-mmt-si-plt-table-body",
            "--validate-mmt-si-plt-delivery-info-url-3",
        ],
        "table_length": 13,
        "extra_probe": [
            "--expect-mmt-si-plt-table-body-num-packages 0",
            "--expect-mmt-si-plt-table-body-num-ip-delivery 1",
            "--expect-mmt-si-plt-delivery-info-location-type 5",
            "--expect-mmt-si-plt-delivery-info-url-length 3",
            "--expect-mmt-si-plt-delivery-info-url-3-byte0 108",
            "--expect-mmt-si-plt-delivery-info-url-3-byte1 97",
            "--expect-mmt-si-plt-delivery-info-url-3-byte2 98",
            "--expect-mmt-si-plt-delivery-info-descriptor-loop-length 0",
        ],
    },
    {
        "phase": "ADI",
        "port_off": 719000,
        "src": "ZX",
        "table_hex": "8000000f010001010100000000000000000000",
        "body_var": "zx_payloads",
        "validate": [
            "--validate-mmt-si-plt-table-body",
            "--validate-mmt-si-plt-package-entry-id8-location-ipv4",
        ],
        "table_length": 15,
        "extra_probe": [
            "--expect-mmt-si-plt-table-body-num-packages 1",
            "--expect-mmt-si-plt-table-body-num-ip-delivery 0",
            "--expect-mmt-si-plt-package-id-length 1",
            "--expect-mmt-si-plt-package-mmt-package-id 1",
            "--expect-mmt-si-plt-package-location-type 1",
            "--expect-mmt-si-plt-package-ipv4-dst-port 0",
        ],
    },
    {
        "phase": "ADJ",
        "port_off": 720000,
        "src": "ZZ",
        "table_hex": (
            "8000002601000002000000000000000000000000000000000000"
            "00000000000000000000000000000000"
        ),
        "body_var": "zz_payloads",
        "validate": [
            "--validate-mmt-si-plt-table-body",
            "--validate-mmt-si-plt-package-entry-ipv6",
        ],
        "table_length": 38,
        "extra_probe": [
            "--expect-mmt-si-plt-table-body-num-packages 1",
            "--expect-mmt-si-plt-table-body-num-ip-delivery 0",
            "--expect-mmt-si-plt-package-id-length 0",
            "--expect-mmt-si-plt-package-location-type 2",
            "--expect-mmt-si-plt-package-ipv6-dst-port 0",
        ],
    },
    {
        "phase": "ADK",
        "port_off": 721000,
        "src": "AAB",
        "table_hex": (
            "8000002701000101020000000000000000000000000000000000"
            "0000000000000000000000000000000000"
        ),
        "body_var": "aab_payloads",
        "validate": [
            "--validate-mmt-si-plt-table-body",
            "--validate-mmt-si-plt-package-entry-id8-location-ipv6",
        ],
        "table_length": 39,
        "extra_probe": [
            "--expect-mmt-si-plt-table-body-num-packages 1",
            "--expect-mmt-si-plt-table-body-num-ip-delivery 0",
            "--expect-mmt-si-plt-package-id-length 1",
            "--expect-mmt-si-plt-package-mmt-package-id 1",
            "--expect-mmt-si-plt-package-location-type 2",
            "--expect-mmt-si-plt-package-ipv6-dst-port 0",
        ],
    },
    {
        "phase": "ADL",
        "port_off": 722000,
        "src": "AAD",
        "table_hex": "8000000e0001000000000504687474700000",
        "body_var": "aad_payloads",
        "validate": [
            "--validate-mmt-si-plt-table-body",
            "--validate-mmt-si-plt-delivery-info-url-4",
        ],
        "table_length": 14,
        "extra_probe": [
            "--expect-mmt-si-plt-table-body-num-packages 0",
            "--expect-mmt-si-plt-table-body-num-ip-delivery 1",
            "--expect-mmt-si-plt-delivery-info-location-type 5",
            "--expect-mmt-si-plt-delivery-info-url-length 4",
            "--expect-mmt-si-plt-delivery-info-url-4-byte0 104",
            "--expect-mmt-si-plt-delivery-info-url-4-byte1 116",
            "--expect-mmt-si-plt-delivery-info-url-4-byte2 116",
            "--expect-mmt-si-plt-delivery-info-url-4-byte3 112",
            "--expect-mmt-si-plt-delivery-info-descriptor-loop-length 0",
        ],
    },
    {
        "phase": "ADM",
        "port_off": 723000,
        "src": "AAI",
        "table_hex": "8000000e010000010a000001e00000011388",
        "body_var": "aai_payloads",
        "validate": [
            "--validate-mmt-si-plt-table-body",
            "--validate-mmt-si-plt-package-entry-ipv4-nz",
        ],
        "table_length": 14,
        "extra_probe": [
            "--expect-mmt-si-plt-table-body-num-packages 1",
            "--expect-mmt-si-plt-table-body-num-ip-delivery 0",
            "--expect-mmt-si-plt-package-id-length 0",
            "--expect-mmt-si-plt-package-location-type 1",
            "--expect-mmt-si-plt-package-ipv4-src-addr 167772161",
            "--expect-mmt-si-plt-package-ipv4-dst-addr 3758096385",
            "--expect-mmt-si-plt-package-ipv4-dst-port 5000",
        ],
    },
    {
        "phase": "ADN",
        "port_off": 724000,
        "src": "AAK",
        "table_hex": "8000000f01000101010a000001e00000011388",
        "body_var": "aak_payloads",
        "validate": [
            "--validate-mmt-si-plt-table-body",
            "--validate-mmt-si-plt-package-entry-id8-location-ipv4-nz",
        ],
        "table_length": 15,
        "extra_probe": [
            "--expect-mmt-si-plt-table-body-num-packages 1",
            "--expect-mmt-si-plt-table-body-num-ip-delivery 0",
            "--expect-mmt-si-plt-package-id-length 1",
            "--expect-mmt-si-plt-package-mmt-package-id 1",
            "--expect-mmt-si-plt-package-location-type 1",
            "--expect-mmt-si-plt-package-ipv4-src-addr 167772161",
            "--expect-mmt-si-plt-package-ipv4-dst-addr 3758096385",
            "--expect-mmt-si-plt-package-ipv4-dst-port 5000",
        ],
    },
    {
        "phase": "ADO",
        "port_off": 725000,
        "src": "AAL",
        "table_hex": (
            "80000027010001010200000000000000000000ffff0a000001"
            "00000000000000000000ffffe00000011388"
        ),
        "body_var": "aal_payloads",
        "validate": [
            "--validate-mmt-si-plt-table-body",
            "--validate-mmt-si-plt-package-entry-id8-location-ipv6-nz",
        ],
        "table_length": 39,
        "extra_probe": [
            "--expect-mmt-si-plt-table-body-num-packages 1",
            "--expect-mmt-si-plt-table-body-num-ip-delivery 0",
            "--expect-mmt-si-plt-package-id-length 1",
            "--expect-mmt-si-plt-package-mmt-package-id 1",
            "--expect-mmt-si-plt-package-location-type 2",
            "--expect-mmt-si-plt-package-ipv6-src-addr-3 167772161",
            "--expect-mmt-si-plt-package-ipv6-dst-addr-3 3758096385",
            "--expect-mmt-si-plt-package-ipv6-dst-port 5000",
        ],
    },
]


def pa_prefix_plt(table_hex: str) -> tuple[str, int]:
    n = len(bytes.fromhex(table_hex))
    pa = f"0100048000{n:04x}"
    combo = pa + table_hex
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

    for p in PHASES:
        h = p["table_hex"]
        n = len(bytes.fromhex(h))
        _, msg = pa_prefix_plt(h)
        if p["table_length"] + 4 != n:
            raise SystemExit(f"{p['phase']}: table wire {n} != 4+table_length {p['table_length']+4}")
        print(f"{p['phase']}: table={n} msg={msg}")

    out = pathlib.Path(__file__).resolve().parent / "_gen" / "adh_ado_integ.sh"
    out.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(emit_phase(p) for p in PHASES)
    out.write_text(body + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(body)} bytes)")


if __name__ == "__main__":
    main()

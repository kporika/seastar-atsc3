#!/usr/bin/env python3
"""Generate ABU–ACI consumption helpers and integration phases."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST_CC = ROOT / "tests/encoder_pipeline_test.cc"
INTEG_SH = ROOT / "scripts/mmtp_word0_integration_test.sh"

SPECS = [
    ("ABU", "zt", "ZT", "mpt_asset_location0", 16, 2,
     ["validate-mmt-si-mpt-table-body", "validate-mmt-si-mpt-asset-location0"]),
    ("ABV", "zw", "ZW", "mpt_asset_id8_location_ipv4", 16, 2,
     ["validate-mmt-si-mpt-table-body", "validate-mmt-si-mpt-asset-id8-location-ipv4"]),
    ("ABW", "zx", "ZX", "plt_package_entry_id8_location_ipv4", 128, None,
     ["validate-mmt-si-plt-table-body", "validate-mmt-si-plt-package-entry-id8-location-ipv4"]),
    ("ABX", "aaa", "AAA", "mpt_asset_id8_location_ipv6", 16, 2,
     ["validate-mmt-si-mpt-table-body", "validate-mmt-si-mpt-asset-id8-location-ipv6"]),
    ("ABY", "aab", "AAB", "plt_package_entry_id8_location_ipv6", 128, None,
     ["validate-mmt-si-plt-table-body", "validate-mmt-si-plt-package-entry-id8-location-ipv6"]),
    ("ABZ", "aah", "AAH", "mpt_asset_location_ipv6_nz", 16, 2,
     ["validate-mmt-si-mpt-table-body", "validate-mmt-si-mpt-asset-location-ipv6-nz"]),
    ("ACA", "aak", "AAK", "plt_package_entry_id8_location_ipv4_nz", 128, None,
     ["validate-mmt-si-plt-table-body", "validate-mmt-si-plt-package-entry-id8-location-ipv4-nz"]),
    ("ACB", "aal", "AAL", "plt_package_entry_id8_location_ipv6_nz", 128, None,
     ["validate-mmt-si-plt-table-body", "validate-mmt-si-plt-package-entry-id8-location-ipv6-nz"]),
    ("ACC", "aam", "AAM", "mpt_asset_id8_location_ipv4_nz", 16, 2,
     ["validate-mmt-si-mpt-table-body", "validate-mmt-si-mpt-asset-id8-location-ipv4-nz"]),
    ("ACD", "aan", "AAN", "mpt_asset_id8_location_ipv6_nz", 16, 2,
     ["validate-mmt-si-mpt-table-body", "validate-mmt-si-mpt-asset-id8-location-ipv6-nz"]),
    ("ACE", "aao", "AAO", "mpt_asset_id16_location_ipv4", 16, 2,
     ["validate-mmt-si-mpt-table-body", "validate-mmt-si-mpt-asset-id16-location-ipv4"]),
    ("ACF", "aap", "AAP", "mpt_asset_id16_location_ipv4_nz", 16, 2,
     ["validate-mmt-si-mpt-table-body", "validate-mmt-si-mpt-asset-id16-location-ipv4-nz"]),
    ("ACG", "aaq", "AAQ", "mpt_asset_id16_location_ipv6", 16, 2,
     ["validate-mmt-si-mpt-table-body", "validate-mmt-si-mpt-asset-id16-location-ipv6"]),
    ("ACH", "aar", "AAR", "mpt_asset_id16_location_ipv6_nz", 16, 2,
     ["validate-mmt-si-mpt-table-body", "validate-mmt-si-mpt-asset-id16-location-ipv6-nz"]),
    ("ACI", "aas", "AAS", "mpt_asset_id16_descriptors4", 16, 2,
     ["validate-mmt-si-mpt-table-body", "validate-mmt-si-mpt-asset-id16-descriptors4"]),
]


def extract_in_message_func(func: str) -> str:
    text = TEST_CC.read_text()
    pat = rf"(int run_mmtp_signalling_prefix_with_{re.escape(func)}_in_message\([\s\S]*?\n\}}\n)"
    m = re.search(pat, text)
    if not m:
        raise SystemExit(f"missing: {func}")
    return m.group(1)


def to_consumption_func(body: str, mid: int) -> str:
    lines = body.splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if (
            "using row_t" in line
            or "mmt_si_pa_table_header_rows" in line
            or "row_t{" in line
        ):
            i += 1
            continue
        if "cfg.prepend_mmt_si_pa_table_headers" in line:
            i += 1
            continue
        if "cfg.mmt_si_message_id" in line:
            out.append(f"    cfg.mmt_si_message_id                   = {mid};")
            out.append("    cfg.mmt_si_message_version              = 0;")
            i += 1
            continue
        out.append(line.replace("_in_message(", "_in_consumption_message("))
        i += 1
    return "\n".join(out) + "\n"


def parse_source_phase(src: str) -> tuple[str, list[tuple[str, str]]]:
    text = INTEG_SH.read_text()
    pay_var = f"{src.lower()}_payloads"
    pat = (
        rf'echo "\[mmtp_word0_integ\] phase {src}:.*?\n'
        rf'run_phase "{src}"[\s\S]*?'
        r'"\$\{probe_bin\}" verify \\\n'
        rf'([\s\S]*?)'
        rf'--expected-payloads "\$\{{{pay_var}\}}"'
    )
    m = re.search(pat, text)
    if not m:
        raise SystemExit(f"parse failed: {src}")
    verify = m.group(1)
    expects: list[tuple[str, str]] = []
    for line in verify.splitlines():
        line = line.strip().rstrip("\\").strip()
        em = re.match(r"--expect-mmt-si-([^\s]+)\s+(\S+)", line)
        if not em:
            continue
        key, val = em.group(1), em.group(2)
        if key.startswith("pa-") or key == "message-byte-length":
            continue
        expects.append((key, val))
    # collapse to unique keys (source repeats each expect 4×)
    seen: dict[str, str] = {}
    for k, v in expects:
        seen.setdefault(k, v)
    expects = list(seen.items())
    pm = re.search(rf'{src.lower()}_payload="([0-9a-f]+)"', text)
    if not pm:
        raise SystemExit(f"payload hex: {src}")
    return pm.group(1), expects


def gen_integ_block(
    cons: str, pay: str, src: str, func: str, mid: int, pid: int | None,
    valflags: list[str], hex_payload: str, expects: list[tuple[str, str]],
) -> str:
    mbl = len(bytes.fromhex(hex_payload))
    pid_arg = "2" if pid == 2 else '"${mmtp_pid}"'
    cl = cons.lower()
    lines = [
        f'{cl}_payloads="${{{pay}_payloads}}"',
        f'saved_payloads_{cl}="${{payloads}}"',
        f'payloads="${{{cl}_payloads}}"',
        "",
        f'echo "[mmtp_word0_integ] phase {cons}: consumption (message_id={mid}) + mmt_si_{func} ({src} ingress)"',
        f'run_phase "{cons}" "${{port_{cl}}}" "${{tmpdir}}/{cl}.out" "${{tmpdir}}/gw_{cl}.log" \\',
        "    --prepend-mmtp-word0 \\",
        "    --mmtp-payload-type 2 \\",
        f"    --mmtp-packet-id {pid_arg} \\",
        "    --prepend-mmtp-signalling-prefix \\",
        "    --prepend-mmt-si-message-header-len32 \\",
        f"    --mmtp-si-message-id {mid} \\",
        "    --mmtp-si-message-version 0 \\",
    ]
    for vf in valflags:
        lines.append(f"    --{vf} \\")
    lines += [
        '"${probe_bin}" verify \\',
        f'    --file "${{tmpdir}}/{cl}.out.shard0" \\',
        "    --strip-mmtp-word0 \\",
        "    --expect-mmtp-payload-type 2 \\",
        f"    --expect-mmtp-packet-id {pid_arg} \\",
        "    --strip-mmtp-signalling-prefix \\",
        "    --expect-mmtp-signalling-fragmentation 0 \\",
        "    --expect-mmtp-signalling-reserved 0 \\",
        "    --expect-mmtp-signalling-length-extension 0 \\",
        "    --expect-mmtp-signalling-aggregation 0 \\",
        "    --expect-mmtp-signalling-fragment-counter 0 \\",
        "    --strip-mmt-si-message-header-len32 \\",
    ]
    for _ in range(4):
        lines.append(f"    --expect-mmt-si-message-id {mid} \\")
    for _ in range(4):
        lines.append("    --expect-mmt-si-message-version 0 \\")
    for _ in range(4):
        lines.append(f"    --expect-mmt-si-message-byte-length {mbl} \\")
    for k, v in expects:
        for _ in range(4):
            lines.append(f"    --expect-mmt-si-{k} {v} \\")  # 4 CSV shards
    lines.append(f'    --expected-payloads "${{{cl}_payloads}}"')
    lines.append("")
    lines.append(f'payloads="${{saved_payloads_{cl}}}"')
    lines.append("")
    return "\n".join(lines)


def hex_to_cpp_vec(hex_payload: str, var: str) -> str:
    b = bytes.fromhex(hex_payload)
    if len(b) > 40:
        return ""
    items = ", ".join(f"std::byte{{0x{x:02x}}}" for x in b)
    return (
        f"            failures +=\n"
        f"                run_mmtp_signalling_prefix_with_{var}_in_consumption_message(\n"
        f'                    "mmtp-signalling-si-{var.replace("_", "-")}-consumption-msg", 2,\n'
        f"                    {'2u' if 'mpt' in var and 'plt' not in var[:3] else '0x10u'}, sig_e,\n"
        f"                    std::vector<std::byte>{{{items}}});"
    )


def main() -> None:
    helpers: list[str] = []
    integ_parts: list[str] = []
    comments: list[str] = []
    ports: list[str] = []
    tests: list[str] = []

    for i, (cons, pay, src, func, mid, pid, valflags) in enumerate(SPECS):
        body = extract_in_message_func(func)
        helpers.append(to_consumption_func(body, mid))
        hex_payload, expects = parse_source_phase(src)
        port = 679000 + i * 1000
        ports.append(f"port_{cons.lower()}=$(( ( RANDOM % 10000 ) + {port} ))")
        pid_note = ", **packet_id** **2**" if pid == 2 else ""
        comments.append(
            f"# (**{cons}**) **§10.3 consumption + {func} lab:** **message_id** **{mid}**"
            f" + **`mmt_si_{func}`** (**{src}** ingress{pid_note})."
        )
        integ_parts.append(
            gen_integ_block(cons, pay, src, func, mid, pid, valflags, hex_payload, expects)
        )
        t = hex_to_cpp_vec(hex_payload, func)
        if t:
            tests.append(t)

    out = ROOT / "tools" / "_gen"
    out.mkdir(exist_ok=True)
    (out / "helpers.cc").write_text("\n\n".join(helpers))
    (out / "integ.sh").write_text(
        "\n".join(comments) + "\n\n" + "\n".join(ports) + "\n\n" + "\n".join(integ_parts)
    )
    (out / "tests.cc").write_text("\n".join(tests))
    print("ok", len(SPECS), "phases")


if __name__ == "__main__":
    main()

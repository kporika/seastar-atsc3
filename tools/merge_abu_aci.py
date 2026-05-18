#!/usr/bin/env python3
"""Merge ABU–ACI generated artifacts into integration script and unit tests."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INTEG = ROOT / "scripts/mmtp_word0_integration_test.sh"
TEST_CC = ROOT / "tests/encoder_pipeline_test.cc"
GEN = ROOT / "tools/_gen"

LARGE_HEX: dict[str, tuple[str, str, str]] = {
    "mpt_asset_id8_location_ipv6": (
        "2u",
        "abu_id8_ipv6_ingress",
        "2001003700000000010000000000010100000000000102000000000000000000000000000000000000000000000000000000000000000000000000",
    ),
    "plt_package_entry_id8_location_ipv6": (
        "0x10u",
        "abu_plt_id8_ipv6_ingress",
        "80000027010001010200000000000000000000000000000000000000000000000000000000000000000000",
    ),
    "mpt_asset_location_ipv6_nz": (
        "2u",
        "abu_mpt_loc_ipv6_nz_ingress",
        "2001003600000000010000000000000000000000010200000000000000000000ffff0a00000100000000000000000000ffffe000000113880000",
    ),
    "plt_package_entry_id8_location_ipv6_nz": (
        "0x10u",
        "abu_plt_id8_ipv6_nz_ingress",
        "80000027010001010200000000000000000000ffff0a00000100000000000000000000ffffe00000011388",
    ),
    "mpt_asset_id8_location_ipv6_nz": (
        "2u",
        "abu_id8_ipv6_nz_ingress",
        "200100370000000001000000000001010000000000010200000000000000000000ffff0a00000100000000000000000000ffffe000000113880000",
    ),
    "mpt_asset_id16_location_ipv6": (
        "2u",
        "abu_id16_ipv6_ingress",
        "2001003700000000010000000000020102000000000001020000000000000000000000000000000000000000000000000000000000000000000000",
    ),
    "mpt_asset_id16_location_ipv6_nz": (
        "2u",
        "abu_id16_ipv6_nz_ingress",
        "20010038000000000100000000000201020000000000010200000000000000000000ffff0a00000100000000000000000000ffffe000000113880000",
    ),
}


def hex_block(var: str, hex_payload: str) -> str:
    n = len(bytes.fromhex(hex_payload))
    return f"""            {{
                static const char *hx =
                    "{hex_payload}";
                std::vector<std::byte> {var};
                {var}.reserve({n}u);
                for (std::size_t i = 0; hx[i] != '\\0'; i += 2) {{
                    const auto nyb = [](char c) -> unsigned {{
                        if (c >= '0' && c <= '9') {{
                            return static_cast<unsigned>(c - '0');
                        }}
                        return static_cast<unsigned>(c - 'a' + 10);
                    }};
                    {var}.push_back(static_cast<std::byte>(
                        (nyb(hx[i]) << 4) | nyb(hx[i + 1])));
                }}"""


def large_call(func: str, pid: str, var: str) -> str:
    slug = func.replace("_", "-")
    return f"""            failures +=
                run_mmtp_signalling_prefix_with_{func}_in_consumption_message(
                    "mmtp-signalling-si-{slug}-consumption-msg", 2, {pid}, sig_e,
                    {var});"""


def merge_integ() -> None:
    sh = INTEG.read_text()
    gen = (GEN / "integ.sh").read_text()
    ports = []
    body_lines = []
    in_body = False
    for line in gen.splitlines():
        if line.startswith("port_abu"):
            ports.append(line)
        if line.startswith("abu_payloads"):
            in_body = True
        if in_body:
            body_lines.append(line)
    body = "\n".join(body_lines)
    if "phase ABU:" in sh:
        print("integ: ABU phases already present")
        return
    if "port_abv" not in sh:
        sh = sh.replace(
            "port_abt=$(( ( RANDOM % 10000 ) + 678000 ))\nport_abu=$(( ( RANDOM % 10000 ) + 679000 ))\n\nmmtp_gfd_toi",
            "port_abt=$(( ( RANDOM % 10000 ) + 678000 ))\n"
            + "\n".join(ports)
            + "\n\nmmtp_gfd_toi",
            1,
        )
    sh = sh.replace(
        'payloads="${saved_payloads_abt}"\n\n\necho "[mmtp_word0_integ] PASS"',
        'payloads="${saved_payloads_abt}"\n\n' + body + '\necho "[mmtp_word0_integ] PASS"',
        1,
    )
    INTEG.write_text(sh)
    print("integ: inserted", len(body_lines), "lines")


def merge_unit_tests() -> None:
    cc = TEST_CC.read_text()
    small = (GEN / "tests.cc").read_text().strip()
    if "mpt-asset-location0-consumption-msg" in cc:
        print("tests: ABU small cases already present")
    else:
        insert_before = (
            "            failures +=\n"
            "                run_mmtp_signalling_prefix_with_mpt_asset_id8_descriptors4_in_consumption_message("
        )
        if insert_before not in cc:
            raise SystemExit("tests: anchor not found")
        cc = cc.replace(insert_before, small + "\n" + insert_before, 1)
        print("tests: inserted small cases")

    large_parts: list[str] = []
    for func, (pid, var, hx) in LARGE_HEX.items():
        slug = func.replace("_", "-")
        if f"mmtp-signalling-si-{slug}-consumption-msg" in cc:
            continue
        large_parts.append(
            hex_block(var, hx) + "\n" + large_call(func, pid, var) + "\n            }"
        )

    if large_parts:
        ins_anchor = (
            "            failures +=\n"
            "                run_mmtp_signalling_prefix_with_mpt_asset_id8_descriptors4_in_consumption_message("
        )
        cc = cc.replace(ins_anchor, "\n\n".join(large_parts) + "\n" + ins_anchor, 1)
        print("tests: inserted", len(large_parts), "large cases")

    TEST_CC.write_text(cc)


def fix_makefile() -> None:
    mk = (ROOT / "Makefile").read_text()
    mk2 = mk.replace("E–AAU", "E–ACI").replace("E-AAU", "E-ACI")
    if mk2 != mk:
        (ROOT / "Makefile").write_text(mk2)
        print("Makefile: E–ACI")


def main() -> None:
    merge_integ()
    merge_unit_tests()
    fix_makefile()


if __name__ == "__main__":
    main()

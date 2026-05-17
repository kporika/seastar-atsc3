<!--
  Keep in sync with end_to_end_gaps.canvas.tsx. The hero summary stats mirror
  the `GAPS` array (DONE / partial+missing open / EXTERNAL / pct done), not the
  separate STACK overview table. Markdown is what GitHub / non-Cursor readers see.
-->

# ATSC 3.0 end-to-end: from `atsc3_proto` to RF

ATSC 3.0 ("NextGen TV") is the IP-native next-generation digital terrestrial
broadcast standard from the Advanced Television Systems Committee, replacing
the MPEG-TS pipeline of ATSC 1.0. The stack is split across half a dozen
specs: an OFDM/LDPC physical layer (A/321 bootstrap + A/322 PHY), a
studio-to-transmitter scheduler and tunnel (A/324 STLTP), a link layer that
carries IP packets over the air (**A/330 — ALP + TLV multiplex**), and
service signaling plus content delivery (A/331 LLS/SLS, ROUTE/DASH, MMTP).
This project takes **A/330 as its reference scope** and implements it as a
YAML-driven C++ codec generator plus a Seastar gateway. Below is the full
inventory of every protocol-level component between an operator's "broadcast
this" and the RF exciter, grouped by layer, with the recommended build order
at the bottom.

| | |
|---|---|
| **Gap rows marked DONE** | 3 |
| **Gap rows PARTIAL + MISSING (in scope)** | 27 |
| **Out of scope (exciter / RF)** | 6 |
| **In-scope coverage (DONE ÷ in-scope rows)** | 10 % |
| **Declared repo roadmap (A/330 lab link layer)** | **3** rows with `roadmap: true` in `end_to_end_gaps.canvas.tsx` — **3 DONE**, **0 open**, **100%** |

The roadmap line is a **declared subset** of the full inventory (ALP base header, TLV single packet, TLV-mux frame composition). It does not remove or rewrite the operator→RF table below; expand `roadmap: true` when the repo takes on new committed items.

### What “closing all gaps” cannot mean

This table lists the **entire** operator→RF surface for ATSC 3.0, including
MPEG-DASH, ROUTE/LCT, full A/331 LLS/SLS, A/324 to a commercial exciter, and
the OFDM PHY. **`atsc3_proto` does not aim to drive every row to DONE** in
one codebase; many rows are **multi-year** industry scope or **EXTERNAL**
(exciter vendor) by design. The inventory stays open so progress is visible;
shipping features updates a handful of cells at a time. Treat **M7–M12** in
the build-order section as the staged roadmap for what *might* land here.

## Reality check: “all the gaps”

Closing **every** row below is **multi-year** engineering (roughly milestones **M7–M12**): DASH/MMT packaging, full A/331 signaling and SLS, ROUTE/MMTP, a production **A/324** STLTP feed to a commercial exciter, and more. This inventory exists so the **whole** operator→RF surface is visible while `atsc3_proto` advances **incrementally**—each change typically updates a few status cells, not the entire stack at once.

> The interactive version of this document lives at
> [`end_to_end_gaps.canvas.tsx`](./end_to_end_gaps.canvas.tsx) and renders
> as a Cursor canvas with sortable tables and styled status pills.

---

## What `atsc3_proto` ships today

**Inputs the gateway accepts**
- TCP length-prefix ingress: `[u32 BE length] [payload]`
- Per-shard `SO_REUSEPORT` load balancing on the listen socket
- RTCM v3 frames as a special-case payload via `mmt_probe --rtcm-file`
- **`--prepend-lct-word0`** (**`--lct-codepoint`**), optionally **`--lct-include-tsi --lct-tsi`** and/or **`--lct-include-toi --lct-toi`** (both flags ⇒ RFC order **TSI** then **TOI**, **`header_length_words` = 3**, max **2035** inline user octets vs **2039**/ **2043** for smaller prefixes): RFC 5651 LCT lab prefix **inside** ALP; **`--prepend-mmtp-word0`** (**`--mmtp-payload-type`**, **`--mmtp-packet-id`**) prepends **MMTP** packet header word‑0 before optional LCT; optional **`--prepend-mmtp-ts-psn`** (**`--mmtp-timestamp`**, **`--mmtp-psn`**) appends **`mmtp_header_ts_psn`** (8 B) after word‑0 (requires word‑0); optional **`--prepend-mmtp-packet-counter`** (**`--mmtp-packet-counter`**, requires **ts_psn**) appends **`mmtp_header_counter32`** (4 B); optional **`--prepend-mmtp-extension`**: legacy **`--mmtp-extension-type`** / **`--mmtp-extension-hex`** for one **`mmtp_header_extension`**, or repeat **`--mmtp-extension` TYPE:HEX** (multitoken) for a chained **X** list after **ts_psn** / optional counter; optional **`--prepend-mmtp-signalling-prefix`** plus **`--mmtp-signalling-fragmentation`** (0–3), **`--mmtp-signalling-reserved`** (0–15), **`--mmtp-signalling-length-extension`**, **`--mmtp-signalling-aggregation`**, **`--mmtp-signalling-fragment-counter`** (0–255) appends **`mmtp_payload_signalling_prefix`** (2 B, **ISO/IEC 23008-1** **9.3.4**) after optional extension; with **`--mmtp-signalling-aggregation`**, repeat **`--mmtp-signalling-aggregate-hex`** (multitoken even-length hex per aggregated message body; on-wire **`length`** = body octet count as **16**- or **32**-bit BE per **`--mmtp-signalling-length-extension`**); optional **`--prepend-mmtp-isobmff-prefix`** plus **`--mmtp-isobmff-fragment-type`** (0–15), **`--mmtp-isobmff-timed`**, **`--mmtp-isobmff-fragmentation`** (0–3), **`--mmtp-isobmff-aggregation`** (with **`--mmtp-isobmff-aggregate-hex`** per **DU** when **A**=**1**), **`--mmtp-isobmff-fragment-counter`**, **`--mmtp-isobmff-sequence-number`** appends **`mmtp_payload_isobmff_prefix`** (8 B, **payload_type** **0**; lab **`length`** = **6** + optional **DU_header** (**ISO/IEC 23008-1** Figures 4–5 when **`--prepend-mmtp-isobmff-du-header`** and **FT**=**2**) + ingress or aggregate **DU** octets; mutually exclusive with **`--prepend-mmtp-signalling-prefix`**); optional **`--prepend-mmtp-isobmff-du-header`** with **`--mmtp-isobmff-du-item-id`** (**T**=**0**) or **`--mmtp-isobmff-du-mf-seq`** / **`--mmtp-isobmff-du-sample`** / **`--mmtp-isobmff-du-offset`** / **`--mmtp-isobmff-du-priority`** / **`--mmtp-isobmff-du-dep-counter`** (**T**=**1**); optional **`--alp-payload-config`** / **`--alp-header-mode`** set **A/330** §5.2 ALP base **pc**/**hm** (lab: still **16**‑bit base + opaque body only); **`GET /config`** echoes **`lct_include_*`** / **`lct_tsi`** / **`lct_toi`** / **`alp_payload_config`** / **`alp_header_mode`** and **`prepend_mmtp_word0`** / **`mmtp_payload_type`** / **`mmtp_packet_id`** / **`prepend_mmtp_ts_psn`** / **`mmtp_timestamp`** / **`mmtp_psn`** / **`prepend_mmtp_packet_counter`** / **`mmtp_packet_counter`** / **`prepend_mmtp_extension`** / **`mmtp_extension_type`** / **`mmtp_extension_hex`** / **`mmtp_extensions`** / **`prepend_mmtp_signalling_prefix`** / **`mmtp_signalling_fragmentation`** / **`mmtp_signalling_reserved`** / **`mmtp_signalling_length_extension`** / **`mmtp_signalling_aggregation`** / **`mmtp_signalling_fragment_counter`** / **`mmtp_signalling_aggregate_hex`** / **`prepend_mmtp_isobmff_prefix`** / **`mmtp_isobmff_fragment_type`** / **`mmtp_isobmff_timed`** / **`mmtp_isobmff_fragmentation`** / **`mmtp_isobmff_aggregation`** / **`mmtp_isobmff_fragment_counter`** / **`mmtp_isobmff_sequence_number`** / **`prepend_mmtp_isobmff_du_header`** / **`mmtp_isobmff_du_item_id`** / **`mmtp_isobmff_du_movie_fragment_sequence_number`** / **`mmtp_isobmff_du_sample_number`** / **`mmtp_isobmff_du_offset`** / **`mmtp_isobmff_du_subsample_priority`** / **`mmtp_isobmff_du_dependency_counter`**
- Optional HTTP admin (**`--admin-http host:port`**): **`POST /ingest`**, **`GET /config`**, **`POST /config/sink`** plus **`PATCH` / `PUT` /config** (mutators accept **`sink_uri`** only — hot-swaps **`--sink` on every shard**), **`GET /services`** / **`POST /services`** / **`PATCH /services?id=`** (**`sink_uri`** or **`null`** for per-row HTTP ingest routing) / **`DELETE /services?id=`**, **`GET /healthz`**, **`GET /readyz`**, **`GET /metrics`**; optional **`--admin-bearer-token`** (Bearer auth on **`POST/PATCH/PUT/DELETE`** and **`POST /ingest`**); optional PEM **`--admin-tls-cert`** + **`--admin-tls-key`** (HTTPS listener); optional **`--services-state-file`** — JSON (**`schema_version` 2**) load/save on shard 0 using reactor **`open_file_dma`/`dma_read`** read path and streamed write + **`rename_file`** (**no** `fstream`/`seastar::async` mixing). Thin **Operator** tab in **`webapp/`** (**`npm run dev`**) via Vite **`/__atsc3_admin`** → **`ATSC3_ADMIN_URL`**. **`tools/atsc3ctl.py`**. **`examples/gw.operator.example.json`**.

**What it produces on the wire**
- ALP packet: 16-bit base header + opaque payload (≤ 2047 B); optional **pc**/**hm** bits via **`--alp-payload-config`** / **`--alp-header-mode`** (no segmentation/concatenation additional headers on this lab path)
- TLV-mux packet: 24-bit header + ALP payload (≤ 65 535 B)
- Sinks: `stdout://`, `file:///path`, `null://`, **`udp://host:port`** (TLV-mux as UDP payload; MTU guard), **`ipv4udp-file:///path?src=&dst=&srcport=&dstport=[&ttl=]`** (append M8 IPv4+UDP wire per frame; per-shard `*.shardN`), **`stltp://host:port`** (lab STLTP/UDP), **`lls://`** / **`lls://host:port`** (A/331 LLS Table 6.1 + gzip on UDP; default multicast 224.0.23.60:4937; optional `?table=&group=&gcm1=`)

**Codec generator**
- `tools/codegen.py` reads `protocol/*.yaml` → C++ types/decoder/encoder/JSON
- Recursive nested support via `repeated:` (M6) — see `tlv_mux_frame.yaml`
- MSB-first bit reader/writer in `lib/runtime/`

**M8 / M9 (lab transport & LLS helpers)**
- `lib/runtime/ipv4_udp.{hh,cc}` — **M8** IPv4 + UDP encapsulation with IPv4/UDP checksums (`encapsulate_ipv4_udp`); used by **`ipv4udp-file://`** sink in `gw/sink.cc` (append wire to file); **`udp://`** uses kernel UDP (no user-space IP header). **`protocol/lct_rfc5651_word0.yaml`** — RFC 5651 first LCT header word (codegen); gateway **`--prepend-lct-word0`** prefixes that word (**optional** **`--lct-include-tsi`**, **`--lct-include-toi`**, or **both**) inside ALP (lab stitch). **`--prepend-mmtp-word0`** (**`--mmtp-payload-type`**, **`--mmtp-packet-id`**) prepends **ISO/IEC 23008-1** MMTP packet header **word‑0** before optional LCT prefix; optional **`--prepend-mmtp-ts-psn`** (**`--mmtp-timestamp`**, **`--mmtp-psn`**) appends **`mmtp_header_ts_psn`** after word‑0; optional **`--prepend-mmtp-packet-counter`** (**`--mmtp-packet-counter`**, requires **ts_psn**) appends **`mmtp_header_counter32`**; optional **`--prepend-mmtp-extension`**: legacy **`--mmtp-extension-type`** / **`--mmtp-extension-hex`** for one **`mmtp_header_extension`**, or repeat **`--mmtp-extension` TYPE:HEX** (multitoken) for a chained **X** list after **ts_psn** / optional counter; optional **`--prepend-mmtp-signalling-prefix`** (**`--mmtp-signalling-fragmentation`**, **`--mmtp-signalling-reserved`**, **`--mmtp-signalling-length-extension`**, **`--mmtp-signalling-aggregation`**, **`--mmtp-signalling-fragment-counter`**) appends **`mmtp_payload_signalling_prefix`** (2 B) after optional extension; with **`--mmtp-signalling-aggregation`**, repeat **`--mmtp-signalling-aggregate-hex`** (multitoken even-length hex per message body; on-wire **`length`** = octet count as **16**- or **32**-bit BE per **`--mmtp-signalling-length-extension`**). **MMTP header (codegen):** **`mmtp_header_word0.yaml`**, **`mmtp_header_ts_psn.yaml`**, **`mmtp_header_counter32.yaml`**, **`mmtp_header_extension.yaml`** (one **X** TLV per decode; repeat for chains); **ISOBMFF payload:** **`mmtp_payload_isobmff_prefix.yaml`** (Figure 3 rows 1–2), **`mmtp_payload_isobmff_du_length16.yaml`** (**A**=**1** aggregation), **`mmtp_payload_isobmff_du_header_timed.yaml`** / **`mmtp_payload_isobmff_du_header_non_timed.yaml`** (Figures 4–5 when **FT**=**2**); **GFD payload header:** **`mmtp_payload_gfd_header.yaml`** (Figure 6, **payload_type** **0x01**); opaque media bodies, signalling-mode payload header (**payload_type** **0x02**), ISOBMFF **FT**=**1** (**MFU**) lab, multi-extension **assembly**; **`mmt_si_*`** §**10.3** validate lab through integration **AAT** (**MPT**/**PLT** table envelopes, body prefixes, **Asset**/**Package**/**DeliveryInfo** slices for **asset_id_length** **0**/**1**/**2**, **location_type** **0**/**1**/**2** zero/non-zero addrs, **4**‑byte descriptors); full receiver-style depacketizer and ROUTE sessions / FEC not in **`atsc3_gw`** yet
- `lib/runtime/lls_table6_1.hh` — **M9** A/331 Table 6.1 four-byte LLS prefix helper (matches `gw/sink.cc`)
- `tools/m9_lls_pack.py` + `fixtures/lls/minimal_slt.xml` — **M9** lab: cleartext XML → prefix + gzip (RFC 1952) for bench / `lls://` ingest

**Test harness**
- Per-protocol fixture round-trip tests (auto-generated)
- `tools/smoke/codec_smoke.py` — pure-Python golden checks (46 cases)
- `scripts/integration_test.sh` — `gw` + `mmt_probe` loopback in 1 process
- `scripts/lct_word0_integration_test.sh` — **A**/word‑0 · **B**/TSI · **C**/TOI · **D**/TSI+TOI + `mmt_probe verify --strip-lct-word0` / `--expect-lct-{tsi,toi}`
- `scripts/mmtp_word0_integration_test.sh` — **E**/word‑0 only · **F**/word‑0+LCT · **G**/word‑0+**ts_psn** · **H**/word‑0+extension · **I**/word‑0+**ts_psn**+extension · **J**/word‑0+**ts_psn**+**packet_counter** · **K**/full prefix stack · **L**/word‑0+signalling prefix · **M**/word‑0+chained **X** extensions · **N**/word‑0+signalling **aggregation** (§**9.3.4** length+body pairs) · **O**/word‑0+**ISOBMFF** prefix (**A**=**0**, Figure 3, **payload_type** **0**) · **P**/word‑0+**ISOBMFF** **aggregation** (**A**=**1**, **DU_length**+DU pairs) · **R**/word‑0+**ISOBMFF** **A**=**1** + **DU_header** per **DU** + **`mmt_probe`** strip (**`--expect-mmtp-isobmff-aggregate-hex`** = media only after each header) · **Q**/word‑0+**ISOBMFF** **DU_header** (**T**=**0**, strip in **`mmt_probe`**) + `mmt_probe verify` strip flags (incl. **`--strip-mmtp-isobmff-prefix`**, **`--strip-mmtp-isobmff-du-header`**, **`--expect-mmtp-isobmff-du-item-id`**, **`--expect-mmtp-isobmff-*`**, **`--expect-mmtp-isobmff-aggregate-hex`**) · **S**/word‑0+**GFD** payload header (**payload_type** **1**, Fig. 6) + **`--strip-mmtp-gfd-header`** / **`--expect-mmtp-gfd-*`** · **T**/ALP **pc**/**hm** (**`--alp-payload-config`** / **`--alp-header-mode`**) + **`mmt_probe verify --expect-alp-payload-config`** / **`--expect-alp-header-mode`** · **U**/word‑0+**ISOBMFF** **FT**=**1** (**MFU**) + **`mmt_probe`** **`--expect-mmtp-isobmff-fragment-type`** · **Y**/word‑0+signalling + §**10.2** **`mmt_si_length32_envelope`** lab · **Z**/same + §**10.3** **`mmt_si_descriptor_loop_u32`** (descriptor region) · **ZA**/nested **Z** inside **Y** · **ZB**/same + §**10.3** **`mmt_si_message_header_len32`** (consumption message-prefix lab) · **ZC**/same as **ZB** + §**10.3** **`mmt_si_pa_table_headers`** (PA table-index + header rows; **`table_length`** **0** ⇒ ingress is SI tail) · **ZD**/same as **ZC** with one MPT row **`table_length`** = ingress size (ingress is table body octets) · **ZE**/two PA rows (**MPT** + **PLT**), all **`table_length` > 0**, ingress = bodies concatenated in row order · **ZF**/mixed **`table_length` 0** and **> 0** — bodies then SI tail · **ZG**/**ZH** normative **`mmt_si_mpt_table`** / **`mmt_si_plt_table`** parse (**table_id** **0x20** / **0x80**) · **ZI**/**ZJ** **`mmt_si_mpt_table_body_prefix`** / **`mmt_si_plt_table_body_prefix`** · **ZK** **`mmt_si_mpt_asset`** (**asset_id_length** **0** lab) · **ZS** **`mmt_si_mpt_asset_id8`** (**asset_id_length** **1** lab) · **ZT** **`mmt_si_mpt_asset_location0`** (**asset_id_length** **0**, **location_type** **0** lab) · **ZU** **`mmt_si_plt_package_entry_ipv4`** (**MMT_package_id_length** **0**, **location_type** **1** lab) · **ZV** **`mmt_si_mpt_asset_location_ipv4`** (**asset_id_length** **0**, **location_type** **1** lab) · **ZL** **`mmt_si_plt_delivery_info`** (**location_type** **0** lab) · **ZM** **`mmt_si_plt_delivery_info_ipv4`** (**location_type** **1** lab) · **ZN** **`mmt_si_plt_delivery_info_ipv6`** (**location_type** **2** lab) · **ZO** **`mmt_si_plt_delivery_info_url`** (**location_type** **5** lab) · **ZP** **`mmt_si_plt_package_entry`** (**MMT_package_id_length** **0** lab) · **ZQ** **`mmt_si_plt_delivery_info_url_3`** (**url_length** **3** lab) · **ZR** **`mmt_si_plt_package_entry_id8`** (**MMT_package_id_length** **1** lab) · **ZS** **`mmt_si_mpt_asset_id8`** (**asset_id_length** **1** lab) · **ZT** **`mmt_si_mpt_asset_location0`** (**location_type** **0** lab) · **ZU** **`mmt_si_plt_package_entry_ipv4`** (**location_type** **1** lab) · **ZV** **`mmt_si_mpt_asset_location_ipv4`** (**location_type** **1** lab) · **ZW** **`mmt_si_mpt_asset_id8_location_ipv4`** (**asset_id_length** **1** + **location_type** **1** lab) · **ZX** **`mmt_si_plt_package_entry_id8_location_ipv4`** (**MMT_package_id_length** **1** + **location_type** **1** lab) · **ZY** **`mmt_si_mpt_asset_location_ipv6`** (**location_type** **2** lab) · **ZZ** **`mmt_si_plt_package_entry_ipv6`** (**location_type** **2** lab) · **AAA** **`mmt_si_mpt_asset_id8_location_ipv6`** (**asset_id_length** **1** + **location_type** **2** lab) · **AAB** **`mmt_si_plt_package_entry_id8_location_ipv6`** (**MMT_package_id_length** **1** + **location_type** **2** lab) · **AAC** **`mmt_si_mpt_asset_descriptors4`** (**asset_descriptors_length** **4** lab) · **AAD** **`mmt_si_plt_delivery_info_url_4`** (**url_length** **4**, URL **http** lab) · **AAE** **`mmt_si_plt_delivery_info_ipv4_nz`** (**10.0.0.1** → **224.0.0.1:5000** lab) · **AAF** **`mmt_si_mpt_asset_location_ipv4_nz`** (MPT asset **IPv4** non-zero addrs lab) · **AAG** **`mmt_si_mpt_asset_id16`** (**asset_id_length** **2** lab) · **AAH** **`mmt_si_mpt_asset_location_ipv6_nz`** (MPT asset **IPv6** non-zero addrs lab) · **AAI** **`mmt_si_plt_package_entry_ipv4_nz`** (PLT package **IPv4** non-zero addrs lab) · **AAJ** **`mmt_si_plt_package_entry_ipv6_nz`** (PLT package **IPv6** non-zero addrs lab) · **AAK** **`mmt_si_plt_package_entry_id8_location_ipv4_nz`** (PLT package **id8** + **IPv4** non-zero addrs lab) · **AAL** **`mmt_si_plt_package_entry_id8_location_ipv6_nz`** (PLT package **id8** + **IPv6** non-zero addrs lab) · **AAM** **`mmt_si_mpt_asset_id8_location_ipv4_nz`** (MPT asset **id8** + **IPv4** non-zero addrs lab) · **AAN** **`mmt_si_mpt_asset_id8_location_ipv6_nz`** (MPT asset **id8** + **IPv6** non-zero addrs lab) · **AAO** **`mmt_si_mpt_asset_id16_location_ipv4`** (MPT asset **id16** + **IPv4** zero addrs lab) · **AAP** **`mmt_si_mpt_asset_id16_location_ipv4_nz`** (MPT asset **id16** + **IPv4** non-zero addrs lab) · **AAQ** **`mmt_si_mpt_asset_id16_location_ipv6`** (MPT asset **id16** + **IPv6** zero addrs lab) · **AAR** **`mmt_si_mpt_asset_id16_location_ipv6_nz`** (MPT asset **id16** + **IPv6** non-zero addrs lab) · **AAS** **`mmt_si_mpt_asset_id16_descriptors4`** (MPT asset **id16** + **DEADBEEF** descriptors lab) · **AAT** **`mmt_si_mpt_asset_id8_descriptors4`** (MPT asset **id8** + **DEADBEEF** descriptors lab) · **V**–**X**/word‑0+**signalling** (**payload_type** **2**) + §**9.3.4** prefix + **`packet_id`** **0** / **1** / **2** (MMT‑SI sub‑flow / **PA**‑style routing lab — not full **§10.3** **PA**/**MPI**/**MPT** table parse)
- `scripts/udp_integration_test.sh` — same payloads through **`udp://`** sink (Python collects UDP payloads)
- `scripts/ipv4udp_file_integration_test.sh` — **`ipv4udp-file://`** M8 append + **`m8_bin_to_pcap.py --extract-tlvmux`** + `mmt_probe verify`
- `scripts/stltp_integration_test.sh` — **`stltp://`** lab UDP + **`_stltp_lab_udp_to_tlvmux.py`** strip + `mmt_probe verify`
- `scripts/lls_integration_test.sh` — **`lls://`** cleartext XML → **Table 6.1 + gzip** UDP; **`_lls_lab_integ_recv.py`** validates one datagram
- `scripts/rtcm_integration_test.sh` — **`mmt_probe rtcm-gen`** → gw → **`send --rtcm-file`** → **`verify --validate-rtcm`**
- `scripts/run_all_integration.sh` — fixed-order suite: **`integration_test.sh`**, **`udp_integration_test.sh`**, **`ipv4udp_file_integration_test.sh`**, **`stltp_integration_test.sh`**, **`lls_integration_test.sh`**, **`admin_patch_config_integration_test.sh`**, **`m7_operator_integration_test.sh`**, **`lct_word0_integration_test.sh`**, **`mmtp_word0_integration_test.sh`** (**E**–**AAT**), **`rtcm_integration_test.sh`** (**12×96**); equivalent to **`make integ-all`**
- `scripts/admin_patch_config_integration_test.sh` — admin **`POST /config/sink`** hot-swaps **`sink_uri`** (`null://` ↔ original) with HTTP checks
- `scripts/m7_operator_integration_test.sh` — Bearer + **`PATCH /services`**, **`POST /ingest`** with **`service_id`**, **`--services-state-file`** persistence (**`SIGTERM`** before reading **`file://`**.**`shard0`** sinks)
- `.github/workflows/ci.yml` — **no Docker**: Python **`tools/lint_protomap.py`**, **`tools/codegen.py`**, **`tools/smoke/codec_smoke.py`**, then **`webapp/`** **`npm ci`** + **`npm run build`** on **`ubuntu-latest`**; **`workflow_dispatch`** on **`push`/`pull_request`** to **`main`**. C++ **`ctest`** and **`scripts/*.sh`** integration legs run locally (**`make build`**, **`make integ*`** or **`make image-integ-*`** when using images).

---

## Protocol stack — where each gap lives

Top is closest to the operator; bottom is closest to RF. Layers flagged
EXTERNAL belong to the exciter or transmitter plant and are intentionally
out of scope for `atsc3_proto`.

| #  | Layer                                | What it covers                                                                                | Status   |
|----|--------------------------------------|-----------------------------------------------------------------------------------------------|----------|
| 01 | Operator UI / API                    | How a human or upstream system says "broadcast this"                                          | PARTIAL  |
| 02 | Content packaging                    | DASH segmenter, MMT packager, NRT file ingest, live RTMP/SRT/RTP                              | MISSING  |
| 03 | Service-layer signaling              | LLS (SLT, SystemTime, AEAT) + SLS (USBD, S-TSID, MPD, HELD)                                   | MISSING  |
| 04 | Transport                            | ROUTE/LCT for DASH, MMTP for MMT, Raptor10/RaptorQ FEC                                        | PARTIAL  |
| 05 | Network (UDP/IP)                     | Multicast IP packet building per service / signaling flow                                     | PARTIAL  |
| 06 | Link layer (ALP + TLV-mux)           | ATSC A/330 — single packet_type, opaque payload, no segmentation                              | PARTIAL  |
| 07 | Gateway → Exciter (A/324)            | BBP framing, PLP scheduler, L1B/L1D, STLTP UDP, SFN time sync                                 | MISSING  |
| 08 | Exciter / OFDM PHY (A/321 + A/322)   | Bootstrap, BCH+LDPC, bit interleaver, constellation, OFDM                                     | EXTERNAL |
| 09 | RF chain                             | Power amp, mask filter, antenna                                                               | EXTERNAL |

---

## Detailed gap inventory

Every concrete component with its ATSC / IETF spec citation and current status.

### UI / API

| Spec | Component                          | Status  | Notes                                                  |
|------|------------------------------------|---------|--------------------------------------------------------|
| —    | Web UI (operator dashboard)        | PARTIAL | Thin **Operator** tab in `webapp/` (Vite dev proxy **`/__atsc3_admin`**); config/services/metrics/sink; full dashboard (PLP map, telemetry, push-to-broadcast) still missing; static GitHub Pages build has no admin backend |
| —    | REST or gRPC control API           | PARTIAL | **`--admin-http`**: **`POST /ingest`**, **`GET /metrics`**, **`GET /config`**, **`POST /config/sink`** / **`PATCH` / `PUT` /config** (mutators: **`sink_uri`** only), **`GET/POST/PATCH/DELETE /services`** (**`PATCH`** **`?id=`**), optional Bearer (**`--admin-bearer-token`**) on mutators + **`POST /ingest`**, PEM server TLS (**`--admin-tls-cert`** + **`--admin-tls-key`**), optional **`service_id`** on **`POST /ingest`** → row **`sink_uri`** (**HTTP** only **—** TCP **`--sink`** only), **`--services-state-file`** (**`schema_version` 2**), **`tools/atsc3ctl.py`**. **Still missing:** gRPC, YAML/SQLite bootstrap, **client** mTLS, richer schema. |
| —    | Service config persistence         | PARTIAL | **`--services-state-file`**: JSON snapshot of **`/services`** (shard 0; reactor **`file`** I/O for load/write); **`examples/gw.operator.example.json`**. Full operator YAML/SQLite + schema versioning still missing |

### Content

| Spec             | Component                              | Status  | Notes                                                   |
|------------------|----------------------------------------|---------|---------------------------------------------------------|
| ISO/IEC 23009-1  | MPEG-DASH segmenter                    | MISSING | H.264 / HEVC + AAC / AC-4 → ISOBMFF segments + MPD      |
| A/331 §10        | MMT packager (MPU / MFU)               | MISSING | For MMT-delivered services (alternative to ROUTE/DASH)  |
| —                | NRT file ingest (drop folder)          | MISSING | Watch `/in`, schedule for ROUTE delivery                |
| —                | Live A/V ingest (RTMP / SRT / RTP)     | MISSING | From upstream encoders into the segmenter               |

### Service-layer signaling

| Spec       | Component                                  | Status  | Notes                                                   |
|------------|--------------------------------------------|---------|---------------------------------------------------------|
| A/331 §6   | LLS framing + SLT                          | PARTIAL | **Table 6.1 + gzip UDP** via `lls://` sink; `lib/runtime/lls_table6_1.hh` (4-byte prefix); **`tools/m9_lls_pack.py`** + **`fixtures/lls/minimal_slt.xml`** for lab XML→wire; SLT scheduler / full A/331 XML not built |
| A/331 §6.4 | LLS SystemTime                             | MISSING | Wall-clock reference; one entry per LLS table set       |
| A/331 §6.5 | LLS AEAT (emergency alerts)                | MISSING | EAS / WEA-equivalent payload, optional but spec-required|
| A/331 §6.6 | LLS RRT (region rating table)              | MISSING | Companion to EPG; rarely operationally critical         |
| A/331 §7   | SLS bundle (USBD / S-TSID / MPD / HELD)    | MISSING | Per-service signaling carried on its own ROUTE TSI      |

### Transport

| Spec               | Component                              | Status  | Notes                                                |
|--------------------|----------------------------------------|---------|------------------------------------------------------|
| A/331 §A.3         | ROUTE / LCT packetizer                 | PARTIAL | **`protocol/lct_rfc5651_word0.yaml`** — RFC 5651 §5.1 first word (codegen + fixtures); gw lab adds word‑0 and optional BE32 **TSI** (**S**) and/or BE32 **TOI** (**O**=**1**, `toi_flag`); CCI/ALC sessions, larger **O**/**H**, source/repair, ROUTE binding still missing |
| A/331 §10          | MMTP packetizer + signaling messages   | PARTIAL | **`mmtp_desc`** / **`mmtp_desc_loop`** (**Annex A.5** TLVs); **MMTP packet header (codegen):** **`mmtp_header_word0`**, **`mmtp_header_ts_psn`**, **`mmtp_header_counter32`**, **`mmtp_header_extension`** (type+length+opaque; one unit per YAML — repeat for **X** chains); **gw** **`--prepend-mmtp-word0`** + optional **`--prepend-mmtp-ts-psn`** + optional **`--prepend-mmtp-packet-counter`** + optional **`--prepend-mmtp-extension`** + optional **`--prepend-mmtp-signalling-prefix`** (+ **`--mmtp-signalling-aggregate-hex`** when **aggregation**) + optional **`--prepend-mmtp-isobmff-prefix`** (**`--mmtp-isobmff-*`**, **`--mmtp-isobmff-aggregate-hex`** when **ISOBMFF** **aggregation**, **`--prepend-mmtp-isobmff-du-header`** when **FT**=**2**, **payload_type** **0**) + optional **`--prepend-mmtp-gfd-header`** (**`--mmtp-gfd-*`**, **payload_type** **1**); **`mmt_probe verify`** **`--strip-mmtp-word0`** / **`--strip-mmtp-ts-psn`** / **`--strip-mmtp-packet-counter`** / **`--strip-mmtp-extension`** / **`--strip-mmtp-signalling-prefix`** / **`--strip-mmtp-signalling-aggregate-count`** / **`--strip-mmtp-isobmff-prefix`** / **`--strip-mmtp-isobmff-du-header`** / **`--strip-mmtp-gfd-header`** (**A**=**0** or **A**=**1**; with **`--expect-mmtp-isobmff-aggregate-hex`** and strip on, expects are **media-only**; optional **`--expect-mmtp-isobmff-du-*`**) (+ optional **`--expect-mmtp-*`**, **`--expect-mmtp-gfd-*`**, **`--expect-alp-payload-config`**, **`--expect-alp-header-mode`**) with **`scripts/mmtp_word0_integration_test.sh`** (**E**–**ZB**; phases **V**–**X** **signalling** **`packet_id`** lab plus **Y**/**Z**/**ZA**/**ZB** §**10.2**/§**10.3** MMT-SI lab strips); **ISOBMFF payload YAML:** **`mmtp_payload_isobmff_prefix`**, **`mmtp_payload_isobmff_du_length16`**, **`mmtp_payload_isobmff_du_header_timed`**, **`mmtp_payload_isobmff_du_header_non_timed`**; **GFD:** **`mmtp_payload_gfd_header`**; **signalling prefix:** **`mmtp_payload_signalling_prefix`** (**9.3.4**); **`mmt_si_message_header_len32`** (**§10.3** message-prefix lab); **`mmt_si_length32_envelope`** (**§10.2** lab); **`mmt_si_descriptor_loop_u32`** (**§10.3** table-region lab); MFU / PA / MPI / MPT bodies — still missing |
| RFC 5053 / 6330    | Raptor10 / RaptorQ FEC                 | MISSING | Required for ROUTE robustness over a one-way link    |

### Network

| Spec               | Component                              | Status  | Notes                                                |
|--------------------|----------------------------------------|---------|------------------------------------------------------|
| RFC 768 + RFC 791  | UDP / IPv4 builder + checksums         | PARTIAL | `lib/runtime/ipv4_udp.{hh,cc}` — `encapsulate_ipv4_udp`; **`ipv4udp-file://`** sink appends full datagrams; **`udp://`** lab send (kernel IP/UDP); **`lct_rfc5651_word0`** + **`--prepend-lct-word0`** (optional **`--lct-include-tsi`**, **`--lct-include-toi`**) lab prefix inside ALP; **`--prepend-mmtp-word0`** + optional **`--prepend-mmtp-ts-psn`** + optional **`--prepend-mmtp-packet-counter`** + optional **`--prepend-mmtp-extension`** + optional **`--prepend-mmtp-signalling-prefix`** + optional **`--prepend-mmtp-isobmff-prefix`** + optional **`--prepend-mmtp-gfd-header`** lab MMTP header prefix before optional LCT; full ROUTE/ALC/MMTP sessions still missing |

### Link (this is the part `atsc3_proto` already owns)

| Spec            | Component                                  | Status  | Notes                                                  |
|-----------------|--------------------------------------------|---------|--------------------------------------------------------|
| A/330 §5.2      | ALP base header (16-bit)                   | DONE    | Default **PACKET_TYPE_EXTENSION**, opaque payload, ≤ 2047 B (M3); optional **pc**/**hm** on wire (**`--alp-payload-config`** / **`--alp-header-mode`**; **`mmt_probe --expect-alp-*`**) — segmentation/concatenation still missing |
| A/330 §5.2.4    | ALP segmentation + concatenation           | MISSING | For IP packets > MTU and small-packet aggregation      |
| A/330 §5.2.6    | ALP additional headers                     | MISSING | Sub-stream ID, sequence number, header compression ctx |
| A/330 Annex A   | TLV multiplex (single packet)              | DONE    | Single packet, 16-bit length, opaque payload (M3)      |
| A/330 Annex A   | TLV-mux frame composition (N packets)      | DONE    | M6 nested-protocol via `repeated:`; `tlv_mux_frame.yaml` |

### Broadcast gateway → Exciter (A/324)

| Spec          | Component                                  | Status  | Notes                                                 |
|---------------|--------------------------------------------|---------|-------------------------------------------------------|
| A/322 §5.1    | Baseband packet (BBP) framing              | MISSING | BBP type + length + ALP payload + padding to PLP cell |
| A/324         | PLP scheduler                              | MISSING | Map IP / ALP packets → PLPs by service / QoS / FEC class |
| A/322 §5.6    | L1 signaling (L1B 200b + L1D var)          | MISSING | FFT, GI, pilot pattern, MOD/COD, subframe layout per PLP |
| A/324         | STLTP packetizer (UDP wire)                | PARTIAL | **M10** wire format still missing; **`stltp://host:port`** lab wrap of TLV-mux in `gw/sink.cc` |
| A/324 §6      | Time / SFN sync (PTPv2)                    | MISSING | GPS-disciplined source; coherent emission across TXs  |
| A/324         | Preamble Data Pipe (PDP)                   | MISSING | Low-bitrate sideband for L1 changes between frames    |

### Exciter / RF (intentionally out of scope)

| Spec          | Component                                       | Status   | Notes                                                  |
|---------------|-------------------------------------------------|----------|--------------------------------------------------------|
| A/321         | Bootstrap signal generator                      | EXTERNAL | OOK preamble; allows cold tuners to discover frames    |
| A/322 §6.5    | BCH (outer) + LDPC (inner) FEC                  | EXTERNAL | Per-PLP block coding driven by L1D modcod settings     |
| A/322         | Bit interleave + constellation map              | EXTERNAL | QPSK / 16 / 64 / 256 / 1024 / 4096-QAM (NUC)           |
| A/322         | Time interleaver per PLP                        | EXTERNAL | Convolutional or hybrid; depth from L1D                |
| A/322         | OFDM modulator (8K / 16K / 32K FFT)             | EXTERNAL | Pilots, GI, frame structure → IFFT → I/Q baseband      |
| —             | Up-converter, PA, mask filter, antenna          | EXTERNAL | Broadcaster's transmitter plant                        |

### Operations / cross-cutting

| Spec | Component                                | Status  | Notes                                                    |
|------|------------------------------------------|---------|----------------------------------------------------------|
| —    | Prometheus / OpenTelemetry metrics       | PARTIAL | Text `GET /metrics` when `--admin-http` is set (aggregate counters); OTEL + PLP/service labels still missing |
| —    | Auth + TLS on the control API            | PARTIAL | Bearer (`--admin-bearer-token`) + HTTPS PEM listener shipped; client mTLS, OIDC/integration auth, and audit trails still missing |
| —    | Health + readiness probes                | PARTIAL | `GET /healthz`, `GET /readyz` on `--admin-http` bind address |

---

## Recommended build order

Each milestone is small enough to land in 1–3 weeks of focused work and
unlocks a concrete capability you can demo end-to-end.

### M7 — Control plane

REST or gRPC API + a service-config YAML schema persisted under
`/var/lib/atsc3_proto`. Replaces the current TCP-only ingress with a
first-class operator surface: declare a service, attach a content source,
push it. **Shipped (minimal operator surface):** **`tools/atsc3ctl.py`**
(stdlib HTTP), webapp **Operator** tab (dev via **`/__atsc3_admin`**
→ **`ATSC3_ADMIN_URL`**), **`examples/gw.operator.example.json`**,
optional **`PATCH /services?id=`** for per-row **`sink_uri`**, optional
**Bearer** + **HTTPS** admin, **`POST /ingest`** **`service_id`** routing to
those sinks (shard 0; TCP ingress unchanged), **`--services-state-file`**
(load/save on reactor **`file`** path). Full YAML/SQLite persistence, **gRPC**,
and a production-grade dashboard remain future work.

**Unlocks:** Drive **`--admin-http`** via curl **`/ atsc3ctl / Operator`**; optional **`--services-state-file`**; global sink hot-swap; per-service HTTP ingest sink selection + registry persistence under the JSON schema noted in **`README`**.

**Closes:** Web UI (partial) · REST (still partial: **gRPC**, **client** mTLS/SQLite bootstrap open) · Service config (**partial**: JSON file only).

### M8 — Network + transport (UDP/IP, ROUTE/LCT, MMTP)

Move from opaque length-framed payloads to real broadcast-shaped traffic.
**UDP/IPv4** is already exercised in C++ via **`lib/runtime/ipv4_udp.{hh,cc}`**
and **`udp://`** / **`ipv4udp-file://`** sinks (not YAML-driven). **LCT**
starts with **`protocol/lct_rfc5651_word0.yaml`** (first on-wire word only).
Full **ROUTE/LCT** sessions, **MMTP** payload modes on the air interface, and
**Raptor10/RaptorQ** remain to be built. ALP encapsulation already accepts
opaque payloads; the gateway can **prefix** the codegen **LCT word‑0** with
**`--prepend-lct-word0`** (**`--lct-codepoint`**) and optional **`--lct-include-tsi`**
(and/or **`--lct-include-toi`**) (lab: skips **CCI**; **TSI**/ **TOI** (**O**=**1**) as 32‑bit BE fields in **RFC** order after word‑0, **header_length_words** = **2–3**). Full **CCI**, arbitrary larger
**S**/**O**/**H** combos, ALC semantics, ROUTE bindings, and production **MMTP** modes beyond the **`gw`/`mmt_probe` lab harness** already exercised by **`mmtp_word0_integration_test.sh`** phases **E**–**AAT** (prefix stack through **ISOBMFF** **A**=**0|1**, **FT**=**0|1|2**, **DU_length** aggregation, optional **DU_header**, **GFD** peel, **ALP** §5.2 **pc**/**hm**, **signalling** **§9.3.4** **V**–**X**, **§10.2**/**§10.3** envelopes **Y**/**Z**/**ZA**, message-prefix **ZB**, PA table labs **ZC**–**ZF**, **MPT**/**PLT** table labs **ZG**/**ZH**, body-prefix **ZI**/**ZJ**, full **MPT** **Asset** matrix **ZK**/**ZS**/**ZT**/**ZV**/**ZW**/**ZY**/**AAA**/**AAC**/**AAF**/**AAG**/**AAH**/**AAM**/**AAN**/**AAO**–**AAT**, full **PLT** **DeliveryInfo** + **package entry** matrix **ZL**–**ZZ**/**AAB**/**AAD**/**AAE**/**AAI**–**AAL**, and **`mmt_probe`** strip/expect including **media-only** aggregate hex when stripping per-**DU** headers). **Still open on the transport slice:** full **ROUTE/LCT** sessions, **Raptor** FEC, a **receiver-style** depacketizer, and wiring validated **§10.3** bodies into live **PA**/**MPI**/**MPT** emit paths in **`atsc3_gw`** (not only prepend/validate labs).

**Unlocks:** Real IP multicast packets ride through ALP+TLV-mux.
**Closes:** UDP/IPv4 builder (partial: C++ datagram builder + sinks) · ROUTE/LCT packetizer (partial: LCT header word-0 YAML + gw prepend) · MMTP packetizer (partial: **`mmtp_header_*`** + **`mmtp_desc`** + full **`mmt_si_*`** §**10.3** validate lab through **AAT** + gw prepend/**`mmt_probe`** strip/expect, integration **E**–**AAT**; production depacketizer/ROUTE/FEC still open) · Raptor10/RaptorQ FEC.

### M9 — Service-layer signaling

Generate the SLT/SystemTime/AEAT LLS table set and the per-service SLS
bundle (USBD, S-TSID, MPD, HELD). Without this no ATSC 3.0 receiver can
discover the broadcast or know how to decode it. Naturally splits into
three sub-tasks: an XML emitter (use TinyXML2 or hand-rolled), the LLS
framer (32-bit header + GZIP), and the per-service scheduler that puts SLS
on its own TSI.

**Unlocks:** Off-the-shelf ATSC 3.0 receivers can tune your broadcast.
**Closes:** LLS framing + SLT · LLS SystemTime · LLS AEAT · LLS RRT · SLS bundle.

### M10 — A/324 STLTP (broadcast gateway → exciter)

The biggest payoff. Implement the A/324 Studio-Transmitter Link Tunneling
Protocol: BBP framing, PLP scheduler, L1B + L1D signaling, STLTP UDP wire
format, and PTPv2-based time alignment for SFN. After this lands,
`atsc3_proto` plugs into any commercial exciter (GatesAir Maxiva XTE,
Sinclair RoVer, Enensys MUX-3000) over plain Ethernet and the exciter
happily emits OFDM on RF. **This is the canonical broadcast-gateway
surface.**

**Unlocks:** Real RF transmission via off-the-shelf exciters.
**Closes:** Baseband packet framing · PLP scheduler · L1B / L1D · STLTP packetizer · Time / SFN sync · Preamble Data Pipe.

### M11 — Content packaging (DASH + MMT)

The last piece for a true end-to-end demo without an external
encoder/packager: an embedded MPEG-DASH segmenter (wrap libavformat / GPAC)
plus an MMT packager. Live A/V ingest via SRT/RTMP/RTP feeds the segmenter,
segments stream into the M8 ROUTE/MMTP transport. Heaviest milestone in
lines of code; defer until the whole pipe is otherwise exercised.

**Unlocks:** Self-contained broadcast: live encoder → `atsc3_proto` → exciter.
**Closes:** MPEG-DASH segmenter · MMT packager (MPU/MFU) · NRT file ingest · Live A/V ingest.

### M12 — ALP enrichment + Ops

Round out the link layer with ALP segmentation + concatenation (so jumbo
IP packets and small signaling bursts behave correctly under MTU pressure)
and the additional-headers stream. On operations, **`--admin-http` already
serves** text **`GET /metrics`**, **`GET /healthz`**, **`GET /readyz`**, optional
**Bearer** + **PEM HTTPS**; M12 is where that stack is **finished for production**:
OpenTelemetry + PLP/service labels, **client** **mTLS** (and integration-style auth), audit trails, structured JSON logs, and any deeper
readiness semantics still missing.

**Unlocks:** Production-readable telemetry + clean MTU semantics.
**Closes:** ALP segmentation/concatenation · ALP additional headers · Prometheus / OpenTelemetry metrics · Auth + TLS on the control API (**client** mTLS, OIDC, audits) · Health + readiness probes.

---

## Beyond the gateway (intentionally external)

`atsc3_proto`'s job ends at the A/324 STLTP wire (M10). The exciter
consumes those packets and is responsible for generating the bootstrap
(A/321), the inner BCH+LDPC FEC, the bit interleaver, the constellation
mapper (QPSK through 4096-QAM NUC), the time interleaver, and the OFDM
modulator itself (A/322). The transmitter plant then handles
up-conversion, the power amplifier, the mask filter, and the antenna.

Reference exciters that consume A/324 STLTP today: **GatesAir Maxiva XTE**,
**Sinclair RoVer**, **Enensys MUX-3000**, **Harmonic Electra X3**. Any of
them can act as the downstream peer once M10 lands.

---

## If you want a usable demo this week

### Smallest input surface

**Implemented (optional):** pass **`--admin-http host:port`** to **`atsc3_gw`**. The gateway serves **`POST /ingest`**, **`GET /config`**, **`POST /config/sink`**, **`PATCH` / `PUT` /config** (mutating bodies are **`{"sink_uri":"…"}`** only—global hot-swap), **`GET`** / **`POST`** / **`PATCH`** / **`DELETE /services`**, **`GET /healthz`**, **`GET /readyz`**, **`GET /metrics`**. Optional **`--admin-bearer-token`**, **`--admin-tls-cert`** + **`--admin-tls-key`** (**HTTPS** listener), **`--services-state-file`** (JSON **`schema_version` 2**, shard 0), and (**M8**) **`--prepend-lct-word0`** (**`--lct-codepoint`**) with optional **`--lct-include-tsi --lct-tsi`** and/or **`--lct-include-toi --lct-toi`** (RFC 5651 word‑0 plus **S**/TSI and/or **`O`**=**1** **TOI** inside ALP; **combined** ⇒ **`header_length_words` = 3**, max **2035** inline user octets vs **2039**/**2043**). Optional **`--prepend-mmtp-word0`** (**`--mmtp-payload-type`**, **`--mmtp-packet-id`**) with optional **`--prepend-mmtp-ts-psn`** (**`--mmtp-timestamp`**, **`--mmtp-psn`**), optional **`--prepend-mmtp-packet-counter`** (**`--mmtp-packet-counter`**), optional **`--prepend-mmtp-extension`** (**`--mmtp-extension-type`**, **`--mmtp-extension-hex`**), optional **`--prepend-mmtp-signalling-prefix`** (**`--mmtp-signalling-fragmentation`**, **`--mmtp-signalling-reserved`**, **`--mmtp-signalling-length-extension`**, **`--mmtp-signalling-aggregation`**, **`--mmtp-signalling-fragment-counter`**), optional **`--alp-payload-config`** / **`--alp-header-mode`** (**A/330** §5.2 ALP **pc**/**hm**). **`POST /ingest`** JSON envelope:

```json
{ "service_id": 1, "type": "rtcm" | "raw" | "lls", "payload_b64": "..." }
```

Payloads are base64-decoded. If **`service_id`** is present, it must match the registry from **`GET /services`**; when **`sink_uri`** is set on that row, HTTP ingest routes there (TCP ingress **`--sink`** only—see **`README`**). With **`--sink lls://…`**, cleartext (or gzip) LLS still uses **A/331 Table 6.1 + gzip** UDP and skips **ALP**/**TLV**; otherwise payloads use **ALP→TLV-mux** like TCP ingress (**`type`** is validated but not otherwise routed).

Use **`--sink udp://host:port`** for plain TLV-mux over UDP (kernel stacks IP/UDP). Use **`--sink ipv4udp-file:///tmp/out.bin?src=10.0.0.1&dst=224.0.1.1&srcport=4000&dstport=5000`** to append **M8** IPv4+UDP datagrams (for offline inspection / PCAP tooling). Use **`--sink stltp://host:port`** for a minimal lab STLTP-style UDP wrap of each TLV-mux frame (see `gw/sink.cc`). Not full M10 conformance, but useful on the bench with a tolerant exciter.

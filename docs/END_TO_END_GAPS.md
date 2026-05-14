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
- **`--prepend-lct-word0`** (**`--lct-codepoint`**), optional **`--lct-include-tsi --lct-tsi`**: RFC 5651 LCT lab header **inside** ALP ahead of ingress (word‑0 only ⇒ max **2043** user octets **+** **4**‑byte prefix; with TSI BE32 ⇒ max **2039** **+** **8** bytes); **`GET /config`** echoes **`prepend_lct_word0`**, **`lct_codepoint`**, **`lct_include_tsi`**, **`lct_tsi`** **—** ROUTE sessions / FEC still future
- Optional HTTP admin (**`--admin-http host:port`**): **`POST /ingest`**, **`GET /config`**, **`POST /config/sink`** plus **`PATCH` / `PUT` /config** (mutators accept **`sink_uri`** only — hot-swaps **`--sink` on every shard**), **`GET /services`** / **`POST /services`** / **`PATCH /services?id=`** (**`sink_uri`** or **`null`** for per-row HTTP ingest routing) / **`DELETE /services?id=`**, **`GET /healthz`**, **`GET /readyz`**, **`GET /metrics`**; optional **`--admin-bearer-token`** (Bearer auth on **`POST/PATCH/PUT/DELETE`** and **`POST /ingest`**); optional PEM **`--admin-tls-cert`** + **`--admin-tls-key`** (HTTPS listener); optional **`--services-state-file`** — JSON (**`schema_version` 2**) load/save on shard 0 using reactor **`open_file_dma`/`dma_read`** read path and streamed write + **`rename_file`** (**no** `fstream`/`seastar::async` mixing). Thin **Operator** tab in **`webapp/`** (**`npm run dev`**) via Vite **`/__atsc3_admin`** → **`ATSC3_ADMIN_URL`**. **`tools/atsc3ctl.py`**. **`examples/gw.operator.example.json`**.

**What it produces on the wire**
- ALP packet: 16-bit base header + opaque payload (≤ 2047 B)
- TLV-mux packet: 24-bit header + ALP payload (≤ 65 535 B)
- Sinks: `stdout://`, `file:///path`, `null://`, **`udp://host:port`** (TLV-mux as UDP payload; MTU guard), **`ipv4udp-file:///path?src=&dst=&srcport=&dstport=[&ttl=]`** (append M8 IPv4+UDP wire per frame; per-shard `*.shardN`), **`stltp://host:port`** (lab STLTP/UDP), **`lls://`** / **`lls://host:port`** (A/331 LLS Table 6.1 + gzip on UDP; default multicast 224.0.23.60:4937; optional `?table=&group=&gcm1=`)

**Codec generator**
- `tools/codegen.py` reads `protocol/*.yaml` → C++ types/decoder/encoder/JSON
- Recursive nested support via `repeated:` (M6) — see `tlv_mux_frame.yaml`
- MSB-first bit reader/writer in `lib/runtime/`

**M8 / M9 (lab transport & LLS helpers)**
- `lib/runtime/ipv4_udp.{hh,cc}` — **M8** IPv4 + UDP encapsulation with IPv4/UDP checksums (`encapsulate_ipv4_udp`); used by **`ipv4udp-file://`** sink in `gw/sink.cc` (append wire to file); **`udp://`** uses kernel UDP (no user-space IP header). **`protocol/lct_rfc5651_word0.yaml`** — RFC 5651 first LCT header word (codegen); gateway **`--prepend-lct-word0`** prefixes that word (optional **`--lct-include-tsi`**) inside ALP (lab stitch); ROUTE sessions / MMTP wire / FEC not in **`atsc3_gw`** yet
- `lib/runtime/lls_table6_1.hh` — **M9** A/331 Table 6.1 four-byte LLS prefix helper (matches `gw/sink.cc`)
- `tools/m9_lls_pack.py` + `fixtures/lls/minimal_slt.xml` — **M9** lab: cleartext XML → prefix + gzip (RFC 1952) for bench / `lls://` ingest

**Test harness**
- Per-protocol fixture round-trip tests (auto-generated)
- `tools/smoke/codec_smoke.py` — pure-Python golden checks (27 cases)
- `scripts/integration_test.sh` — `gw` + `mmt_probe` loopback in 1 process
- `scripts/lct_word0_integration_test.sh` — `gw` with word‑0 then word‑0+TSI + `mmt_probe verify --strip-lct-word0 [--expect-lct-tsi]` (same hex payloads as `integration_test.sh`)
- `scripts/udp_integration_test.sh` — same payloads through **`udp://`** sink (Python collects UDP payloads)
- `scripts/ipv4udp_file_integration_test.sh` — **`ipv4udp-file://`** M8 append + **`m8_bin_to_pcap.py --extract-tlvmux`** + `mmt_probe verify`
- `scripts/stltp_integration_test.sh` — **`stltp://`** lab UDP + **`_stltp_lab_udp_to_tlvmux.py`** strip + `mmt_probe verify`
- `scripts/lls_integration_test.sh` — **`lls://`** cleartext XML → **Table 6.1 + gzip** UDP; **`_lls_lab_integ_recv.py`** validates one datagram
- `scripts/rtcm_integration_test.sh` — **`mmt_probe rtcm-gen`** → gw → **`send --rtcm-file`** → **`verify --validate-rtcm`**
- `scripts/run_all_integration.sh` — runs the sink/LLS/STLTP scripts above plus admin + **M7** + LCT word‑0 + RTCM (**12×96**)
- `scripts/admin_patch_config_integration_test.sh` — admin **`POST /config/sink`** hot-swaps **`sink_uri`** (`null://` ↔ original) with HTTP checks
- `scripts/m7_operator_integration_test.sh` — Bearer + **`PATCH /services`**, **`POST /ingest`** with **`service_id`**, **`--services-state-file`** persistence (**`SIGTERM`** before reading **`file://`**.**`shard0`** sinks)
- `.github/workflows/ci.yml` — same **`make image-integ-all`** Docker sequence (**eight** shell scripts **before** RTCM, then RTCM **12×96**); skips `webapp/` / `docs` / **`pages.yml`**–only diffs; **`workflow_dispatch`**

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
| A/331 §A.3         | ROUTE / LCT packetizer                 | PARTIAL | **`protocol/lct_rfc5651_word0.yaml`** — RFC 5651 §5.1 first 32-bit LCT header word (codegen + fixtures); gw lab stitch adds word‑0 and optional BE32 **TSI** inside ALP; ALC sessions, TOI/full headers, source/repair, and ATSC ROUTE binding still missing |
| A/331 §10          | MMTP packetizer + signaling messages   | MISSING | MMTP header, MFU mode, PA / MPI / MPT messages       |
| RFC 5053 / 6330    | Raptor10 / RaptorQ FEC                 | MISSING | Required for ROUTE robustness over a one-way link    |

### Network

| Spec               | Component                              | Status  | Notes                                                |
|--------------------|----------------------------------------|---------|------------------------------------------------------|
| RFC 768 + RFC 791  | UDP / IPv4 builder + checksums         | PARTIAL | `lib/runtime/ipv4_udp.{hh,cc}` — `encapsulate_ipv4_udp`; **`ipv4udp-file://`** sink appends full datagrams; **`udp://`** lab send (kernel IP/UDP); no ROUTE/LCT/MMTP framing yet |

### Link (this is the part `atsc3_proto` already owns)

| Spec            | Component                                  | Status  | Notes                                                  |
|-----------------|--------------------------------------------|---------|--------------------------------------------------------|
| A/330 §5.2      | ALP base header (16-bit)                   | DONE    | Single packet_type, opaque payload, ≤ 2047 B (M3)      |
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
Full **ROUTE/LCT** sessions, **MMTP** payloads on the air interface, and
**Raptor10/RaptorQ** remain to be built. ALP encapsulation already accepts
opaque payloads; the gateway can now **prefix** the codegen **LCT word‑0**
(**`--prepend-lct-word0`**, optional **`--lct-include-tsi`**) as a lab stitch—**TOI**
and ROUTE object delivery beyond this prefix are still the integration target
after richer codecs exist.

**Unlocks:** Real IP multicast packets ride through ALP+TLV-mux.
**Closes:** UDP/IPv4 builder (partial: C++ datagram builder + sinks) · ROUTE/LCT packetizer (partial: LCT header word-0 YAML) · MMTP packetizer · Raptor10/RaptorQ FEC.

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

**Implemented (optional):** pass **`--admin-http host:port`** to **`atsc3_gw`**. The gateway serves **`POST /ingest`**, **`GET /config`**, **`POST /config/sink`**, **`PATCH` / `PUT` /config** (mutating bodies are **`{"sink_uri":"…"}`** only—global hot-swap), **`GET`** / **`POST`** / **`PATCH`** / **`DELETE /services`**, **`GET /healthz`**, **`GET /readyz`**, **`GET /metrics`**. Optional **`--admin-bearer-token`**, **`--admin-tls-cert`** + **`--admin-tls-key`** (**HTTPS** listener), **`--services-state-file`** (JSON **`schema_version` 2**, shard 0), and (**M8**) **`--prepend-lct-word0`** with **`--lct-codepoint`** and optional **`--lct-include-tsi --lct-tsi`** (RFC 5651 word‑0 + optional BE32 **TSI** inside ALP; max **2039** / **2043** user octets). **`POST /ingest`** JSON envelope:

```json
{ "service_id": 1, "type": "rtcm" | "raw" | "lls", "payload_b64": "..." }
```

Payloads are base64-decoded. If **`service_id`** is present, it must match the registry from **`GET /services`**; when **`sink_uri`** is set on that row, HTTP ingest routes there (TCP ingress **`--sink`** only—see **`README`**). With **`--sink lls://…`**, cleartext (or gzip) LLS still uses **A/331 Table 6.1 + gzip** UDP and skips **ALP**/**TLV**; otherwise payloads use **ALP→TLV-mux** like TCP ingress (**`type`** is validated but not otherwise routed).

Use **`--sink udp://host:port`** for plain TLV-mux over UDP (kernel stacks IP/UDP). Use **`--sink ipv4udp-file:///tmp/out.bin?src=10.0.0.1&dst=224.0.1.1&srcport=4000&dstport=5000`** to append **M8** IPv4+UDP datagrams (for offline inspection / PCAP tooling). Use **`--sink stltp://host:port`** for a minimal lab STLTP-style UDP wrap of each TLV-mux frame (see `gw/sink.cc`). Not full M10 conformance, but useful on the bench with a tolerant exciter.

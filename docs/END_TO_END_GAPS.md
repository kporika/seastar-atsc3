<!--
  Auto-rendered from end_to_end_gaps.canvas.tsx. If you change one, change
  the other so they stay in sync. The canvas is the interactive Cursor
  artifact; this markdown is what GitHub / non-Cursor readers see.
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
| **Done in `atsc3_proto`** | 3 components |
| **Missing (in scope)** | 27 components |
| **Out of scope (exciter / RF)** | 6 components |
| **In-scope coverage** | 10 % |

> The interactive version of this document lives at
> [`end_to_end_gaps.canvas.tsx`](./end_to_end_gaps.canvas.tsx) and renders
> as a Cursor canvas with sortable tables and styled status pills.

---

## What `atsc3_proto` ships today

**Inputs the gateway accepts**
- TCP length-prefix ingress: `[u32 BE length] [payload]`
- Per-shard `SO_REUSEPORT` load balancing on the listen socket
- RTCM v3 frames as a special-case payload via `mmt_probe --rtcm-file`

**What it produces on the wire**
- ALP packet: 16-bit base header + opaque payload (≤ 2047 B)
- TLV-mux packet: 24-bit header + ALP payload (≤ 65 535 B)
- Sinks: `stdout://`, `file:///path`, `null://` (throughput soak)

**Codec generator**
- `tools/codegen.py` reads `protocol/*.yaml` → C++ types/decoder/encoder/JSON
- Recursive nested support via `repeated:` (M6) — see `tlv_mux_frame.yaml`
- MSB-first bit reader/writer in `lib/runtime/`

**Test harness**
- Per-protocol fixture round-trip tests (auto-generated)
- `tools/smoke/codec_smoke.py` — pure-Python golden checks (25 cases)
- `scripts/integration_test.sh` — `gw` + `mmt_probe` loopback in 1 process

---

## Protocol stack — where each gap lives

Top is closest to the operator; bottom is closest to RF. Layers flagged
EXTERNAL belong to the exciter or transmitter plant and are intentionally
out of scope for `atsc3_proto`.

| #  | Layer                                | What it covers                                                                                | Status   |
|----|--------------------------------------|-----------------------------------------------------------------------------------------------|----------|
| 01 | Operator UI / API                    | How a human or upstream system says "broadcast this"                                          | MISSING  |
| 02 | Content packaging                    | DASH segmenter, MMT packager, NRT file ingest, live RTMP/SRT/RTP                              | MISSING  |
| 03 | Service-layer signaling              | LLS (SLT, SystemTime, AEAT) + SLS (USBD, S-TSID, MPD, HELD)                                   | MISSING  |
| 04 | Transport                            | ROUTE/LCT for DASH, MMTP for MMT, Raptor10/RaptorQ FEC                                        | MISSING  |
| 05 | Network (UDP/IP)                     | Multicast IP packet building per service / signaling flow                                     | MISSING  |
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
| —    | Web UI (operator dashboard)        | MISSING | Service list, PLP map, telemetry, push-to-broadcast    |
| —    | REST or gRPC control API           | MISSING | `POST /services`, `/sources`, `/signaling/lls`, `GET /stats` |
| —    | Service config persistence         | MISSING | YAML or SQLite — survives restarts; schema-versioned   |

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
| A/331 §6   | LLS framing + SLT                          | MISSING | 32-bit header + GZIPed XML on `224.0.23.60:4937`        |
| A/331 §6.4 | LLS SystemTime                             | MISSING | Wall-clock reference; one entry per LLS table set       |
| A/331 §6.5 | LLS AEAT (emergency alerts)                | MISSING | EAS / WEA-equivalent payload, optional but spec-required|
| A/331 §6.6 | LLS RRT (region rating table)              | MISSING | Companion to EPG; rarely operationally critical         |
| A/331 §7   | SLS bundle (USBD / S-TSID / MPD / HELD)    | MISSING | Per-service signaling carried on its own ROUTE TSI      |

### Transport

| Spec               | Component                              | Status  | Notes                                                |
|--------------------|----------------------------------------|---------|------------------------------------------------------|
| A/331 §A.3         | ROUTE / LCT packetizer                 | MISSING | RFC 5651 LCT + ALC sessions, source flow + repair flow |
| A/331 §10          | MMTP packetizer + signaling messages   | MISSING | MMTP header, MFU mode, PA / MPI / MPT messages       |
| RFC 5053 / 6330    | Raptor10 / RaptorQ FEC                 | MISSING | Required for ROUTE robustness over a one-way link    |

### Network

| Spec               | Component                              | Status  | Notes                                                |
|--------------------|----------------------------------------|---------|------------------------------------------------------|
| RFC 768 + RFC 791  | UDP / IPv4 builder + checksums         | MISSING | Trivial codegen target; multicast addr per service   |

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
| A/324         | STLTP packetizer (UDP wire)                | MISSING | `{BBP-per-PLP, L1B, L1D, Time, Preamble}`             |
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
| —    | Prometheus / OpenTelemetry metrics       | MISSING | `bytes_in`, `payloads`, `encode_errors` per shard / PLP / service |
| —    | Auth + TLS on the control API            | MISSING | mTLS or token; required before any production exposure   |
| —    | Health + readiness probes                | MISSING | `/healthz`, `/readyz` for orchestrators                  |

---

## Recommended build order

Each milestone is small enough to land in 1–3 weeks of focused work and
unlocks a concrete capability you can demo end-to-end.

### M7 — Control plane

REST or gRPC API + a service-config YAML schema persisted under
`/var/lib/atsc3_proto`. Replaces the current TCP-only ingress with a
first-class operator surface: declare a service, attach a content source,
push it. Includes a CLI (`atsc3ctl`) and a thin web UI as the smallest
deliverable that an operator can actually use.

**Unlocks:** A human (or upstream system) can say *"broadcast this"*.
**Closes:** Web UI · REST/gRPC API · Service config persistence.

### M8 — Network + transport (UDP/IP, ROUTE/LCT, MMTP)

Move from opaque length-framed payloads to real broadcast-shaped traffic.
UDP/IPv4 builder (another codegen YAML), then ROUTE/LCT for DASH delivery
and MMTP for MMT delivery. ALP encapsulation already in place picks up real
IP packets instead of opaque blobs. Adds Raptor10/RaptorQ FEC for the
one-way path.

**Unlocks:** Real IP multicast packets ride through ALP+TLV-mux.
**Closes:** UDP/IPv4 builder · ROUTE/LCT packetizer · MMTP packetizer · Raptor10/RaptorQ FEC.

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
and the additional-headers stream. In parallel, ship Prometheus metrics,
`/healthz`, `/readyz`, mTLS on the control API, and structured JSON logs.

**Unlocks:** Production-readable telemetry + clean MTU semantics.
**Closes:** ALP segmentation/concatenation · ALP additional headers · Prometheus metrics · Auth + TLS · Health + readiness probes.

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

Skip the full REST API. Add a single **`POST /ingest`** HTTP endpoint
inside the existing Seastar gateway (use `seastar/http`) that accepts a
JSON envelope:

```json
{ "service_id": 1, "type": "rtcm" | "raw" | "lls", "payload_b64": "..." }
```

The gateway routes by `type` into the existing encoder pipeline, plus a
new **`lls://`** sink that emits LLS-framed XML on a configurable multicast
IP. Two days of work.

### Smallest output surface

Add a third sink: **`stltp://exciter:30000`** that wraps each TLV-mux frame
in a minimal A/324 STLTP packet (BBP for one PLP, hard-coded L1B/L1D,
monotonic-counter timestamps, no PTP).

Doesn't pass conformance, but a real exciter on the bench will accept it
and emit OFDM. Lets you exercise the whole chain on a single PLP, single
MODCOD before investing in the full M10 surface.

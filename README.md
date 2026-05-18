# atsc3_proto

A self-contained ATSC 3.0 protocol toolkit: a YAML-driven C++ codec
generator, a Seastar-based gateway that frames and encodes payloads,
and a standalone test client (`mmt_probe`) for end-to-end loopback
and RTCM ingest.

> **Status:** M6 landed. Codegen supports **nested protocols** via the
> `repeated:` block — a parent YAML declares a length-prefixed loop of
> another protocol's units, and the codegen emits a fully-recursive C++
> decoder/encoder/JSON path. Two worked examples ship: `mmtp_desc_loop`
> (canonical ATSC A/331 descriptor list, inner element `mmtp_desc`) and
> `tlv_mux_frame` (multi-packet wrapper, inner element `tlv_mux`). The
> python smoke validates the M6 path including a frame composition that
> rides the gw's encoder pipeline.

The repo has **no external workspace dependencies** — `Dockerfile.deps`
bundles every build-time library (Seastar 25.05.0 + transitive deps +
RapidJSON + Python codegen tooling) into a reproducible `atsc3-deps`
image.

> Looking for the bigger picture? See
> [`docs/END_TO_END_GAPS.md`](./docs/END_TO_END_GAPS.md) for a full
> inventory of every protocol-level component between an operator API and
> the RF exciter, with status, ATSC/IETF spec citations, and a recommended
> build order. The same content is published as a live single-page app at
> **https://kporika.github.io/seastar-atsc3/** — sources under
> [`webapp/`](./webapp/), built and deployed by
> [`.github/workflows/pages.yml`](./.github/workflows/pages.yml) on every
> push to `main`.

## Layout

```
atsc3_proto/
├── protocol/                  # YAML protocol definitions
│   ├── alp.yaml               #   ATSC A/330 §5.2 — ALP base header
│   ├── tlv_mux.yaml           #   ATSC A/330 Annex A — TLV multiplex packet
│   ├── tlv_mux_frame.yaml     #   wrapper: N tlv_mux packets (M6 example)
│   ├── lct_rfc5651_word0.yaml #   RFC 5651 §5.1 — LCT header first 32 bits (M8 slice)
│   ├── mmtp_header_word0.yaml #   ISO/IEC 23008-1 — MMTP packet header word 0 (M8)
│   ├── mmtp_header_ts_psn.yaml #  MMTP timestamp + packet_sequence_number (M8)
│   ├── mmtp_header_counter32.yaml # MMTP optional packet_counter when C=1 (M8)
│   ├── mmtp_header_extension.yaml # MMTP header extension TLV (type+len+value) when X=1 (M8)
│   ├── mmtp_payload_isobmff_prefix.yaml # MMTP ISOBMFF-mode payload header — first 64b (M8)
│   ├── mmtp_payload_isobmff_du_length16.yaml # ISOBMFF DU_length when A=1 (M8)
│   ├── mmtp_payload_isobmff_du_header_timed.yaml # ISOBMFF DU header timed (Figure 4) (M8)
│   ├── mmtp_payload_isobmff_du_header_non_timed.yaml # ISOBMFF DU header non-timed (Figure 5) (M8)
│   ├── mmtp_payload_gfd_header.yaml # MMTP GFD-mode payload header (Figure 6, type 0x01) (M8)
│   ├── mmtp_payload_signalling_prefix.yaml # MMTP signalling-mode payload header — first 16b (type 0x02, §9.3.4) (M8)
│   ├── mmtp_desc.yaml         #   ATSC A/331 Annex A.5 — MMTP descriptor
│   └── mmtp_desc_loop.yaml    #   length-prefixed loop of mmtp_desc (M6 example)
├── tools/
│   ├── codegen.py             # YAML → C++ (jinja2 templates)
│   ├── atsc3ctl.py            # M7: stdlib CLI for --admin-http (config, services, ingest, metrics)
│   ├── codegen_templates/     # types.h, decoder.{h,cc}, encoder.{h,cc},
│   │                          # tojson.{h,cc}, fromjson.{h,cc}, fixtures_test.cc
│   ├── lint_protomap.py       # schema validator
│   ├── m9_lls_pack.py         # M9 lab: XML → A/331 Table 6.1 + gzip (stdout binary)
│   ├── m8_bin_to_pcap.py      # M8 lab: IPv4 chain → pcap (DLT_IPV4) or --extract-tlvmux for verify
│   ├── requirements.txt       # PyYAML, Jinja2
│   └── smoke/codec_smoke.py   # python mirror of decode/encode + pipeline check
├── lib/                       # codec library
│   ├── runtime/
│   │   ├── bit_reader.h       # MSB-first bit reader used by generated decoders
│   │   ├── bit_writer.h       # MSB-first bit writer used by generated encoders
│   │   ├── ipv4_udp.{hh,cc}   # M8: IPv4 + UDP encapsulation + checksums
│   │   └── lls_table6_1.hh    # M9: A/331 Table 6.1 LLS 4-byte prefix helper
│   └── generated/             # codegen output (regenerated each build)
│       ├── <p>_types.h        # enums + <enum>_name + <enum>_from_name
│       ├── <p>_decoder.{cc,h} # raw bytes  -> decoded_t
│       ├── <p>_encoder.{cc,h} # decoded_t  -> raw bytes
│       ├── <p>_tojson.{cc,h}  # decoded_t  -> rapidjson::Document
│       ├── <p>_fromjson.{cc,h}# rapidjson  -> decoded_t
│       └── <p>_fixtures_test.cc
├── gw/                        # Seastar gateway service
│   ├── main.cc
│   ├── admin_http.{cc,h}      # optional --admin-http control plane (TLS + bearer auth, /config, /services PATCH, /ingest)
│   ├── atsc3_gw.{cc,h}        # sharded server, wires ingress → encoder → sink
│   ├── ingress_tcp.{cc,h}     # SO_REUSEPORT TCP listener, per-conn framer
│   ├── length_framer.{cc,h}   # 4-byte BE length-prefix stream framer
│   ├── encoder_pipeline.{cc,h}# payload → ALP → TLV-mux composition
│   └── sink.{cc,h}
├── mmt_probe/                 # standalone POSIX CLI
│   ├── main.cc                # send / verify / rtcm-gen subcommands
│   ├── rtcm_v3.{cc,h}         # CRC-24Q + RTCM v3 frame parser/builder
│   └── CMakeLists.txt
├── tests/
│   ├── CMakeLists.txt         # generated fixture tests + hand-written tests
│   ├── encoder_pipeline_test.cc
│   └── udp_ipv4_test.cc       # M8 IPv4+UDP header + checksum unit test
├── scripts/
│   ├── _lib.sh               # resolve_bin + detect_default_build_dir (integration scripts)
│   ├── lct_word0_integration_test.sh  # gw --prepend-lct-word0 + verify --strip-lct-word0 (M8)
│   ├── mmtp_word0_integration_test.sh # gw MMTP lab (E–AEA: … + ISOBMFF FT=1 MFU + ALP pc/hm + MMT-SI §10.3 message header ZB + PA table index ZC + PA table body ZD + multi-table bodies ZE + mixed PA rows + SI tail ZF + MPT/PLT table wire ZG/ZH + body prefix ZI/ZJ + consumption PA+table twins ACN–ACQ + PA+MPT asset ACR–ACY + PA+PLT delivery/package ACZ–ADO + PA+MPT asset location ADP–ADW + PA+MPT/PLT tail ADX–AEA + MPT asset ZK/ZS/AAG/AAH/AAI/AAJ/AAK/AAL/AAM/AAN/AAO/AAP/AAQ/AAR/AAS/AAT/AAU/ZT/ZV/ZW/ZY/AAA/AAC + PLT DeliveryInfo ZL/ZM/ZN/ZO/ZQ/AAD/AAE + PLT package entry ZP/ZR/ZU/ZX/ZZ/AAB + §10.2/§10.3 Y/Z/ZA + SI packet_id 0/1/2 lab V–X) + mmt_probe strip (M8)
│   ├── udp_integration_test.sh # same via udp:// sink + _udp_recv_concat.py
│   ├── ipv4udp_file_integration_test.sh  # ipv4udp-file:// + m8 strip + verify
│   ├── stltp_integration_test.sh  # stltp:// lab UDP + _stltp_lab_udp_to_tlvmux.py + verify
│   ├── lls_integration_test.sh    # lls:// + _lls_lab_integ_recv.py (Table 6.1 + gzip)
│   ├── admin_patch_config_integration_test.sh  # POST /config/sink hot-swap (python3 http.client)
│   ├── rtcm_integration_test.sh   # rtcm-gen → gw → send → verify --validate-rtcm
│   └── throughput_soak.sh     # null:// sink + duration-bounded burst
├── fixtures/lls/              # M9 lab: minimal_slt.xml (SLT stub XML)
├── examples/                  # reference JSON for operator/automation (gw flags)
│   └── gw.operator.example.json
├── docs/                      # architecture notes + gap analyses
│   ├── END_TO_END_GAPS.md     #   full inventory: input API → RF exciter
│   └── end_to_end_gaps.canvas.tsx  # Cursor-canvas rendering of the same
├── webapp/                    # SPA mirror of the gap-analysis canvas
│   └── src/                   #   built + deployed to GitHub Pages
├── .github/workflows/
│   ├── ci.yml                 # GitHub Actions: Python protocol lint + codegen + codec smoke; webapp build (no Docker)
│   └── pages.yml              # Pages: build webapp/, publish on push
├── seastar/                   # git submodule, pinned to seastar-25.05.0
├── Dockerfile.deps            # base image: Seastar + transitive build deps
├── Dockerfile.app             # builder + slim runtime image (atsc3-proto)
├── CMakeLists.txt
├── build.sh
└── Makefile
```

### Operator CLI and thin web UI (M7)

With **`--admin-http`**, you can drive the same JSON endpoints from the shell
via **`tools/atsc3ctl.py`** (Python 3 stdlib only; no pip install):

```bash
export ATSC3_ADMIN=http://127.0.0.1:8080   # or: --base http://...
python3 tools/atsc3ctl.py health
python3 tools/atsc3ctl.py config get
python3 tools/atsc3ctl.py services list
```

For a browser UI during local development, run **`cd webapp && npm install && npm run dev`**, start the gateway with **`--admin-http`**, open the **Operator** tab, and set **`ATSC3_ADMIN_URL`** if the admin bind is not `http://127.0.0.1:8080` (the dev server proxies **`/__atsc3_admin`** to that URL). The static GitHub Pages build does not include an admin backend; use **`atsc3ctl`** or curl there.

Compose-oriented defaults live in **`examples/gw.operator.example.json`** (reference only; **`atsc3_gw`** still takes argv flags).

## Build

### Recommended: Docker (zero local dependencies)

The build uses the same two-stage pattern as the sibling SIP toolchain
shipped in this organization: a heavy `deps` image holds Seastar and its
transitive build deps, and a slim `app` image is layered on top with just
the project binaries.

```bash
make deps              # 1) build atsc3-deps (Seastar + tooling)   ← ~15 min once
make docker-ctest      #    recommended: full Linux+Seastar build + ctest + codec_smoke in deps image (~tens of s)
make docker-build      #    optional: codegen + ninja → ./build-docker (repeat after edits; no slim image)
make image             # 2) build atsc3-proto (codegen + cmake + ninja
                       #    + ctest + python smoke, then a runtime layer
                       #    carrying just the binaries + protocol YAMLs)
make image-integ       # 3) end-to-end loopback inside the runtime image
make image-integ-all   #    same scripts as make integ-all / run_all_integration.sh (separate docker runs; RTCM 12×96)
make image-shell       # interactive bash in the runtime image
make run RUN_ARGS="--smp 4 --sink stdout://"
                       # docker run atsc3-proto, args via RUN_ARGS
```

`make image` auto-rebuilds `atsc3-deps` whenever `Dockerfile.deps` changes
(tracked via `.make/deps.stamp`), so once you've run `make deps` you can
mostly forget about it.

**Host scripts** (`scripts/*.sh`, `make integ`, …): see `scripts/_lib.sh`
**`detect_default_build_dir`** — uses **`ATSC3_BUILD_DIR`** if set (`build`,
`build-docker`, or absolute), else **`build/`** when **`gw/atsc3_gw`** exists
there, else **`build-docker/`**, else **`build/`** (error path).

On GitHub, [`.github/workflows/ci.yml`](./.github/workflows/ci.yml) runs
**without Docker**: it installs Python dependencies, runs **`tools/lint_protomap.py`**, regenerates **`lib/generated/`** via **`tools/codegen.py`**, executes **`tools/smoke/codec_smoke.py`**, then **`npm ci`** + **`npm run build`** under **`webapp/`**. Use **`make build`** and **`make integ*`** (or **`make image-integ-*`**) on your machine for the C++ gateway, **`ctest`**, and shell integration scripts.

For fast iteration that *skips* the in-image ctest + smoke step:

```bash
make image-fast        # docker build --build-arg RUN_TESTS=0
```

Override Seastar pin or job count when building the deps image:

```bash
docker build -f Dockerfile.deps -t atsc3-deps \
    --build-arg SEASTAR_VERSION=seastar-25.05.0 \
    --build-arg MAKE_JOBS=4 .
```

### Native build

If you have Seastar 25.05.0 installed (`find_package(Seastar)` must
resolve via `<prefix>/lib/<arch>/cmake/Seastar/SeastarConfig.cmake`),
plus RapidJSON, Python 3 with PyYAML and Jinja2:

```bash
git submodule update --init --recursive   # populates ./seastar/ (optional)
make build                                # codegen + cmake + ninja → ./build
ctest --test-dir build --output-on-failure
make integ                                # loopback — defaults ./build then ./build-docker
make integ-udp                             # same via udp:// sink (needs python3)
make integ-ipv4udp                         # ipv4udp-file:// + m8 strip + verify (needs python3)
make integ-stltp                           # stltp:// lab UDP strip + verify (needs python3)
make integ-lct-word0                       # --prepend-lct-word0 + verify --strip-lct-word0
make integ-mmtp-word0                      # MMTP lab E–AAT + mmt_probe strip (M8)
make integ-lls                             # lls:// Table 6.1 + gzip validate (needs python3)
make integ-admin                           # PATCH /config sink hot-swap (needs python3)
make integ-rtcm                            # RTCM path (default 32×128 in script; pass frames/bytes as extra args)
make integ-all                             # all host integ scripts (incl. MMTP E–AEA; RTCM 12×96)
```

**No `build/gw/atsc3_gw` on the host?** (macOS or minimal trees often see **`Seastar not found`** from **`cmake`**.) Use the same Linux + Seastar setup the repo already ships: **`make deps`** once (**`atsc3-deps:latest`**), then **`make docker-ctest`** for **`ninja` + `ctest` + `codec_smoke`** inside that image, or **`make image`** and **`make image-integ-mmtp-word0`** / **`make image-integ-all`** to run **`scripts/mmtp_word0_integration_test.sh`** (phases **E**–**ZB**) and the other integration scripts against the **`atsc3-proto`** runtime image.

Optional env vars: `BUILD_TYPE=RelWithDebInfo`, `MAKE_JOBS=8`.

To install Seastar manually, follow the same recipe baked into
[`Dockerfile.deps`](./Dockerfile.deps) (clone the pinned tag, configure
with the same `cmake` flags, `ninja install`).

### Codegen + lint (manual)

CMake runs codegen at configure time, but you can also drive it directly:

```bash
python3 tools/lint_protomap.py protocol
python3 tools/codegen.py --in protocol --out lib/generated
```

Python deps for codegen + smoke:

```bash
python3 -m pip install -r tools/requirements.txt
# Debian/Ubuntu:  apt-get install python3-yaml python3-jinja2
```

## M8 / M9 lab helpers

- **M8:** `lib/runtime/ipv4_udp.{hh,cc}` builds a full **IPv4 + UDP** datagram (20+8+payload bytes) with **header checksums** (`encapsulate_ipv4_udp`, `ipv4_quad`). Unit test: `tests/udp_ipv4_test.cc`. **`ipv4udp-file://`** sink in `gw/sink.cc` appends each TLV-mux frame as one M8 datagram (query: `src`, `dst`, `srcport`, `dstport`, optional `ttl`). **`udp://host:port`** sends TLV-mux as plain UDP (kernel IP/UDP). **`protocol/lct_rfc5651_word0.yaml`** is RFC 5651 LCT header **word‑0** in codegen; **`atsc3_gw`** **`--prepend-lct-word0 [--lct-codepoint N]`** accepts optional **`--lct-include-tsi --lct-tsi`** and/or **`--lct-include-toi --lct-toi`** (RFC order **TSI** then **TOI** when both; **`header_length_words`** **3** for the combo — max **2035** / **2039** / **2043** user octets by prefix size). **`--prepend-mmtp-word0 [--mmtp-payload-type N] [--mmtp-packet-id M]`** prepends **MMTP** packet header **word‑0** (4 B); optional **`--prepend-mmtp-ts-psn`** with **`--mmtp-timestamp`** / **`--mmtp-psn`** appends **`mmtp_header_ts_psn`** (8 B); optional **`--prepend-mmtp-packet-counter`** with **`--mmtp-packet-counter`** (requires **ts_psn**) appends **`mmtp_header_counter32`** (4 B); optional **`--prepend-mmtp-extension`**: one TLV via **`--mmtp-extension-type`** / **`--mmtp-extension-hex`**, or repeat **`--mmtp-extension` TYPE:HEX** (multitoken) for chained **`mmtp_header_extension`**; optional **`--prepend-mmtp-isobmff-prefix`** with **`--mmtp-isobmff-*`** (**`--mmtp-isobmff-aggregate-hex`** when **aggregation**) (ISO/IEC 23008-1 Figure 3 first 64 bits; **payload_type** **0** only; lab **A**=**0** or **A**=**1**), optional **`--prepend-mmtp-isobmff-du-header`** (**`--mmtp-isobmff-du-*`**) before each **DU** body when **FT**=**2**, **`mmt_probe --strip-mmtp-isobmff-prefix`** / **`--expect-mmtp-isobmff-*`** / **`--expect-mmtp-isobmff-aggregate-hex`** (with **`--strip-mmtp-isobmff-du-header`** and **A**=**1**, expects are **media-only** after each **DU_header**), **`--strip-mmtp-isobmff-du-header`** (**A**=**0** or **A**=**1**) with optional **`--expect-mmtp-isobmff-du-*`**, **`--prepend-mmtp-signalling-prefix`** with **`--mmtp-signalling-fragmentation`**, **`--mmtp-signalling-reserved`**, **`--mmtp-signalling-length-extension`**, **`--mmtp-signalling-aggregation`**, **`--mmtp-signalling-fragment-counter`** appends **`mmtp_payload_signalling_prefix`** (2 B) after optional extension; with **`--mmtp-signalling-aggregation`**, repeat **`--mmtp-signalling-aggregate-hex`** (multitoken even-length body hex; on-wire **`length`** = octet count as **16**- or **32**-bit BE per **`--mmtp-signalling-length-extension`**) — all before optional LCT inside ALP. **`mmt_probe verify`** supports **`--strip-mmtp-word0`** (optional **`--expect-mmtp-payload-type`** / **`--expect-mmtp-packet-id`**) and **`--strip-mmtp-ts-psn`** (optional **`--expect-mmtp-timestamp`** / **`--expect-mmtp-psn`**), **`--strip-mmtp-packet-counter`** (optional **`--expect-mmtp-packet-counter`**; requires **`--strip-mmtp-ts-psn`**), **`--strip-mmtp-extension`** (optional **`--expect-mmtp-extension-type`** / **`--expect-mmtp-extension-hex`**), **`--strip-mmtp-signalling-prefix`** (requires **`--strip-mmtp-word0`**; optional **`--expect-mmtp-signalling-*`**), **`--strip-mmtp-signalling-aggregate-count`** (optional repeat **`--expect-mmtp-signalling-aggregate-hex`**; requires **`aggregation_flag`** **1** on the prefix) **before** **`--strip-lct-word0`** when those lab prefixes are on the wire; LCT strip still uses **`--expect-lct-codepoint`** and optional **`--expect-lct-tsi`** / **`--expect-lct-toi`**. Scripts: **`./scripts/mmtp_word0_integration_test.sh`** (**E**–**U**), **`make integ-mmtp-word0`**; **`./scripts/lct_word0_integration_test.sh`** (**A**–**D**), **`make integ-lct-word0`**. **MMTP (ISO/IEC 23008-1) in codegen:** **`mmtp_header_word0.yaml`**, **`mmtp_header_ts_psn.yaml`**, **`mmtp_header_counter32.yaml`** (**C**=**1**), **`mmtp_header_extension.yaml`** (one **X** TLV per YAML; repeat for extension chains), **`mmtp_payload_signalling_prefix.yaml`** (signalling-mode payload header §9.3.4 first 16b, **payload_type** **0x02**), **`mmtp_payload_isobmff_prefix.yaml`** (ISOBMFF payload header Figure 3 rows 1–2), **`mmtp_payload_isobmff_du_length16.yaml`** (**DU_length** when **A**=**1**), **`mmtp_payload_isobmff_du_header_timed.yaml`** / **`mmtp_payload_isobmff_du_header_non_timed.yaml`** (Figures 4–5 for **FT**=**2**), **`mmtp_payload_gfd_header.yaml`** (GFD Figure 6, **payload_type** **0x01**). Optional **`--alp-payload-config`** / **`--alp-header-mode`** set **A/330** §5.2 ALP base **pc**/**hm**; **`mmt_probe verify`** accepts **`--expect-alp-payload-config`** / **`--expect-alp-header-mode`**. MFU / PA / MPI / MPT bodies and full depacketizer remain future work. ROUTE sessions / FEC remain future work.
- **M9:** `lib/runtime/lls_table6_1.hh` matches the **A/331 Table 6.1** four-byte prefix used by `lls://`. **`tools/m9_lls_pack.py`** reads cleartext XML (e.g. `fixtures/lls/minimal_slt.xml`) and writes **prefix + gzip** to stdout for piping into `lls://` or `POST /ingest` (base64-wrap as needed).

```bash
python3 tools/m9_lls_pack.py --table 1 fixtures/lls/minimal_slt.xml | xxd | head
python3 tools/m8_bin_to_pcap.py --self-test
# after capturing ipv4udp-file://… output:
# python3 tools/m8_bin_to_pcap.py -i /tmp/ip.bin.shard0 -o /tmp/out.pcap
# python3 tools/m8_bin_to_pcap.py -i /tmp/ip.bin.shard0 --extract-tlvmux /tmp/tlv.bin
```

## Run tests

**Preferred (Docker):** after **`make deps`** (image **`atsc3-deps:latest`**), run the full matrix the same way the **`Dockerfile.app`** builder does — Linux toolchain, **Seastar**, **`atsc3_gw` linked**, **`ctest`**, then **`codec_smoke`** — without waiting for a multi-stage **`docker build`**:

```bash
make docker-ctest
# or: ./scripts/docker_ctest.sh
# Optional: ATSC3_DEPS_IMAGE=…  DOCKER_MAKE_JOBS=16
```

Scratch output lives under **`build-docker-ctest/`** (gitignored).

**Native:** use **`build/`** after **`make build`**, or **`build-docker/`** after **`make docker-build`**:

```bash
cd build-docker   # or: cd build
ctest --output-on-failure
# includes udp_ipv4_test (M8) + encoder_pipeline_test + generated *_fixtures_test
```

The python smoke can be run without a C++ build (useful when iterating on
YAML or templates):

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r tools/requirements.txt
python tools/smoke/codec_smoke.py
```

## Run the gateway (M4)

Binaries live under **`./build/`** (native **`make build`**) or **`./build-docker/`**
(**`make docker-build`**). The examples below use **`./build/`** — substitute
accordingly.

The wire protocol on the ingress socket is **length-prefixed**: each
message is `[u32 length, big-endian][payload bytes]`. The gateway wraps
the payload as ALP (PACKET_TYPE_EXTENSION), then as TLV-mux (SIGNALING),
and writes the TLV-mux bytes to the sink.

**M8 lab (optional ROUTE-ish framing):** pass **`--prepend-lct-word0`** to insert the
RFC 5651 LCT header **first 32‑bit word** (see **`protocol/lct_rfc5651_word0.yaml`**
_fixture `minimal_v1_c0`_) before ingress inside ALP. With word‑0 only (**`header_length_words=1`**), the opaque body is **4 bytes + user** (max **2043** user bytes).
With **`--lct-include-tsi`** and **`--lct-tsi U32`** (RFC 5651 TSI BE32 — lab path **without** TOI on the wire, **`header_length_words=2`**), opaque is **8 bytes header + user** (max **2039** user bytes). With **`--lct-include-toi`** (**`--lct-toi`**) only (**RFC5651 O**=**1** TOI BE32 after word‑0, **`header_length_words=2`**, no **S**/TSI), same **8-byte** opaque prefix (**2039** user max).
With **both** **`--lct-include-tsi`** and **`--lct-include-toi`**, the lab path emits word‑0 + **TSI BE32 + TOI BE32** (**`header_length_words=3`**; **CCI** omitted) — **12 bytes prefix**, max **2035** user bytes.
**`--lct-codepoint N`** sets the **`codepoint`** (**0–255**; **`--prepend-lct-word0`** only). **`GET /config`** echoes **`prepend_lct_word0`**, **`lct_codepoint`**, **`lct_include_tsi`**, **`lct_tsi`**, **`lct_include_toi`**, **`lct_toi`**, **`alp_payload_config`**, **`alp_header_mode`**, **`prepend_mmtp_word0`**, **`mmtp_payload_type`**, **`mmtp_packet_id`**, **`prepend_mmtp_ts_psn`**, **`mmtp_timestamp`**, **`mmtp_psn`**, **`prepend_mmtp_packet_counter`**, **`mmtp_packet_counter`**, **`prepend_mmtp_extension`**, **`mmtp_extension_type`** / **`mmtp_extension_hex`** (first TLV mirror), **`mmtp_extensions`** (array of **`extension_type`** + **`extension_hex`** for the full chain), **`prepend_mmtp_signalling_prefix`**, **`mmtp_signalling_fragmentation`**, **`mmtp_signalling_reserved`**, **`mmtp_signalling_length_extension`**, **`mmtp_signalling_aggregation`**, **`mmtp_signalling_fragment_counter`**, **`mmtp_signalling_aggregate_hex`**. **`prepend_mmtp_isobmff_prefix`**, **`mmtp_isobmff_fragment_type`**, **`mmtp_isobmff_timed`**, **`mmtp_isobmff_fragmentation`**, **`mmtp_isobmff_aggregation`**, **`mmtp_isobmff_fragment_counter`**, **`mmtp_isobmff_sequence_number`**, **`prepend_mmtp_isobmff_du_header`**, **`mmtp_isobmff_du_item_id`**, **`mmtp_isobmff_du_movie_fragment_sequence_number`**, **`mmtp_isobmff_du_sample_number`**, **`mmtp_isobmff_du_offset`**, **`mmtp_isobmff_du_subsample_priority`**, **`mmtp_isobmff_du_dependency_counter`**, **`mmtp_isobmff_aggregate_hex`** (array of DU bodies as hex strings when **aggregation**).

```bash
# Single shard, sink to a file (one file per shard: gw.out.shard0, ...)
./build/gw/atsc3_gw --smp 1 --ingress 0.0.0.0:9000 --sink file:///tmp/gw.out

# Multi-shard
./build/gw/atsc3_gw --smp 4 --ingress 0.0.0.0:9000 --sink file:///tmp/gw.out
```

### HTTP admin (control-plane stub)

When you pass **`--admin-http host:port`**, the gateway also exposes:

Optional **`--services-state-file /path/to/services.json`** (with or without admin HTTP): on **shard 0** the file is loaded at startup (if present) and rewritten after each successful **`POST /services`**, **`PATCH /services?id=`**, or **`DELETE /services`**. JSON uses **`schema_version`** `2`, e.g. `{"schema_version":2,"next_id":N,"services":[{"id":1,"name":"…","sink_uri"?: "file:///tmp/x"},…]}` — **`sink_uri`** is optional; when set, **`POST /ingest`** with that **`service_id`** writes to that sink instead of the default shard sink (**TCP ingress** still uses only the global `--sink`).

Optional **`--admin-bearer-token`**: **`POST` / `PATCH` / `PUT` / `DELETE`** on **`/config`**, **`/config/sink`**, **`/services`**, plus **`POST /ingest`**, must include **`Authorization: Bearer …`** (same secret as the CLI flag). **`GET`** routes (**`/healthz`**, **`/readyz`**, **`/metrics`**, **`/config`**, **`/services`**, **`/`**) stay open.

HTTPS admin requires PEM **`--admin-tls-cert`** and **`--admin-tls-key`** together; **`--admin-http`** then serves TLS (**`curl`**, **`atsc3ctl --base https://…`**, …).
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` | JSON index listing admin paths (discovery) |
| GET | `/healthz` | Process liveness (`200` + `ok`) |
| GET | `/readyz` | All shards have sink + ingress up (`200` or `503`) |
| GET | `/config` | **`ingress`**, **`sink_uri`**, **`services_state_file`**, **`prepend_lct_word0`**, **`lct_codepoint`**, **`lct_include_tsi`**, **`lct_tsi`**, **`lct_include_toi`**, **`lct_toi`**, **`admin`**: **`operator_schema_version`**, **`tls`**, **`bearer_auth_required`** |
| POST | `/config/sink` | Body **`{"sink_uri":"…"}`** — hot-swaps sink on every shard (**bearer** if enabled); returns **`GET /config` JSON** |
| PATCH or PUT | `/config` | Same as **`POST /config/sink`** |
| GET | `/services` | **`{"services":[{"id","name","sink_uri"},…]}`** (**`sink_uri`** **`null`** when absent) |
| PATCH | `/services?id=<uint>` | Body **`{"sink_uri":"<uri>"}`** or **`{"sink_uri":null}`**. Bearer when token enabled; persisted when **`--services-state-file`**. |
| GET | `/metrics` | Prometheus text counters |
| DELETE | `/services?id=<uint>` | Remove (**`404`** unknown id); bearer when enabled. |
| POST | `/ingest` | **`payload_b64`**, **`type`**, optional **`service_id`** — routes via that row's **`sink_uri`** when present; **`202`**; bearer when enabled. |
| POST | `/services` | **`{"name"[, "sink_uri"]}`** → **`201`**; **`409`** duplicate name; bearer when enabled. |

`POST /ingest` runs on **shard 0** (stable **`file://`** demos). Omit **`service_id`** to write to **`--sink`**. When set, **`service_id`** must exist in **`GET /services`**; if that row declares **`sink_uri`**, HTTP ingest writes there (**TCP ingress ignores registry sinks and keeps using **`--sink`**).

Per-row **`file://…`** **`sink_uri`** values follow the same on-disk naming as **`--sink file://…`**: one path per shard, e.g. **`/tmp/x.shard0`** when **`sink_uri`** is **`file:///tmp/x`** and **`--smp 1`**.

Example:

```bash
./build/gw/atsc3_gw --smp 1 --ingress 127.0.0.1:9000 --sink stdout:// \
    --services-state-file /tmp/atsc3_services.json \
    --admin-http 127.0.0.1:8080 &
curl -sSf http://127.0.0.1:8080/
curl -sSf http://127.0.0.1:8080/healthz
curl -sSf http://127.0.0.1:8080/config
curl -sSf -X POST http://127.0.0.1:8080/config/sink \
  -H 'Content-Type: application/json' -d '{"sink_uri":"null://"}'
curl -sSf http://127.0.0.1:8080/services
curl -sSf -X POST http://127.0.0.1:8080/services \
  -H 'Content-Type: application/json' -d '{"name":"demo"}'
curl -sSf -X DELETE 'http://127.0.0.1:8080/services?id=1'
# payload "hi" -> base64 aGk=
curl -sSf -X POST http://127.0.0.1:8080/ingest \
  -H 'Content-Type: application/json' \
  -d '{"type":"raw","payload_b64":"aGk="}'
```

### End-to-end loopback with mmt_probe

```bash
# Push a couple of payloads through a running gw at 127.0.0.1:9000:
./build/mmt_probe/mmt_probe send \
    --target 127.0.0.1:9000 \
    --payloads "DEADBEEF,CAFEBABE,1122334455"

# Verify the gw's sink file contains the matching encoded TLV-mux/ALP packets:
./build/mmt_probe/mmt_probe verify \
    --file /tmp/gw.out.shard0 \
    --expected-payloads "DEADBEEF,CAFEBABE,1122334455"
```

### One-shot integration scripts

```bash
./scripts/integration_test.sh                              # defaults: ./build, else ./build-docker
./scripts/integration_test.sh /path/to/custom-build        # explicit build dir
./scripts/lct_word0_integration_test.sh                    # M8 LCT word-0 phases A–D
./scripts/mmtp_word0_integration_test.sh                   # M8 MMTP phases E–AEA (needs built atsc3_gw)
./scripts/run_all_integration.sh                           # integration + UDP/IPv4UDP/STLTP/LLS/admin/M7 + LCT A–D + MMTP E–AEA + RTCM (12×96)
make integ-all                                             # Makefile wrapper → run_all_integration.sh
# Each single-script harness spawns gw, runs mmt_probe send + verify against a temp sink,
# then tears gw down (exit 0 on success). run_all_integration.sh chains them in fixed order.
```

## RTCM ingest (M5)

The gw can ingest GNSS RTCM v3 frames from any standards-conformant source
(RTCM-STANDARDS-104 §3.1: preamble `0xD3` + 6 reserved bits + 10-bit length
+ payload + CRC-24Q over header+payload). Every RTCM frame becomes one
length-framed payload pushed through `mmt_probe send --rtcm-file`.

```bash
# 1) Generate a deterministic .rtcm file (no external GNSS deps required):
./build/mmt_probe/mmt_probe rtcm-gen \
    --out /tmp/test.rtcm --frames 64 --payload-bytes 256 --msg-type 1077

# 2) Pipe each frame through a running gateway:
./build/mmt_probe/mmt_probe send \
    --target 127.0.0.1:9000 --rtcm-file /tmp/test.rtcm

# 3) Verify the sink stream both as TLV-mux/ALP and as inner RTCM frames:
./build/mmt_probe/mmt_probe verify \
    --file /tmp/gw.out.shard0 --validate-rtcm
```

The full thing is automated:

```bash
./scripts/rtcm_integration_test.sh                # 32 frames × 128B default
./scripts/rtcm_integration_test.sh ./build 128 256
# Generates rtcm → spawns gw → sends → verifies (CRC + exact bytes).
```

To consume a real RTCM dump from any external GNSS toolchain, point
`--rtcm-file` at the captured `.rtcm` blob — `mmt_probe` accepts any
back-to-back concatenation of RTCM v3 frames.

## Throughput soak (M5)

For sustained-load testing, use the `null://` sink to keep the disk and
filesystem out of the picture:

```bash
./scripts/throughput_soak.sh                   # 60s, smp=1, 64-byte payload
./scripts/throughput_soak.sh ./build 600 4 DEADBEEFCAFEBABE
# Args: BUILD_DIR DURATION_S SHARDS PAYLOAD_HEX

# On exit, the gw logs cross-shard totals. The script asserts:
#   * encode_errors == 0
#   * payloads      >  0
# and prints an avg-pps summary.
```

For ad-hoc runs you can drive `--burst` directly:

```bash
./build/gw/atsc3_gw --smp 4 --ingress 0.0.0.0:9000 --sink null:// &
./build/mmt_probe/mmt_probe send \
    --target 127.0.0.1:9000 \
    --burst 1000000 --payload-bytes 256 --duration 30 --rate 50000
```

## Nested protocols (M6)

Two YAMLs ship as worked examples of `repeated:`, the codegen's nested
loop construct:

| Parent | Inner element | What it models |
|--------|---------------|----------------|
| `mmtp_desc_loop` | `mmtp_desc` | ATSC A/331 §A.5 descriptor list (`descriptor_loop_length` + N `(tag, len, body)` records) |
| `tlv_mux_frame`  | `tlv_mux`   | Synthetic carriage frame holding N back-to-back TLV-mux packets |

The codegen emits a fully recursive C++ codec for each parent — `decoded_t`
carries `std::vector<::atsc3::<inner>::decoded_t> elements`, the encoder
auto-derives the `length_field` from the encoded element bytes, and the
fixture-test executable round-trips the nested JSON shape end to end.

Verify offline (no C++ build needed):

```bash
python3 tools/smoke/codec_smoke.py
# … fixture round-trip section runs every fixture in every protocol/*.yaml,
#   including the nested mmtp_desc_loop and tlv_mux_frame cases.
# A separate "tlv_mux_frame → gw pipeline" check confirms a 3-packet frame
# survives payload→ALP→TLV-mux→ALP→frame end-to-end.
```

Inside the C++ build (atsc3-deps image or native), each YAML produces
its own `<name>_fixtures_test` CTest case automatically.

## Adding a new protocol

1. Drop a new `protocol/<name>.yaml` (use `tlv_mux.yaml` as the smallest template).
2. `python3 tools/lint_protomap.py protocol` to validate.
3. Rebuild — `./build.sh` reruns codegen and a `ctest` case appears
   automatically (`<name>_fixtures_test`).

The YAML schema is documented inline in the protocol files and
`tools/lint_protomap.py`. Supported field types:

- `enum` (uses an entry from the `enums:` block; emits a strongly-typed
  C++ `enum class` plus `<enum>_name(v)` and `<enum>_from_name(s)` helpers)
- `bool` (1-bit field)
- `uint` (1..64 bits, widened to `uint8_t`/`uint16_t`/`uint32_t`/`uint64_t`)

Each protocol declares **exactly one** trailer shape:

```yaml
# Leaf protocol — opaque payload of `length_field` bytes:
payload:
  length_field: <name of header field>
  kind: opaque
```

```yaml
# Parent protocol — length-prefixed loop of another protocol's units:
repeated:
  length_field: <name of header field; bytes-budget for the loop>
  element:      <name of another protocol in this map>
```

For a `repeated:` parent the generated `decoded_t` carries
`std::vector<::atsc3::<element>::decoded_t> elements` instead of an
opaque payload span. The encoder auto-derives `length_field` from the
sum of encoded element bytes (or rejects a non-zero mismatch). See
`protocol/mmtp_desc_loop.yaml` and `protocol/tlv_mux_frame.yaml` for
working examples.

Future iterations: `IPV4`/`IPV6` typed fields, ALP additional-header
flag-driven optional sections, and richer enum types.

## Roadmap

| Milestone | Status | Scope |
|-----------|--------|-------|
| **M1** | done | Skeleton, Seastar wired, TCP ingest → sink echo |
| **M2** | done | YAML protomap (ALP + TLV-mux), `codegen.py` emits decoder + tojson + fixture tests |
| **M3** | done | Encoder + fromjson + full encode↔decode round-trip in fixture tests |
| **M4** | done | `length_framer` + `encoder_pipeline` wired between ingress and sink; `mmt_probe` send/verify CLI; integration script; pure-C++ pipeline unit test |
| **M5** | done | RTCM v3 ingest (`mmt_probe send --rtcm-file`, `rtcm-gen`, `verify --validate-rtcm`); `null://` sink; throughput soak script with cross-shard totals assertions |
| **M6** | done | Nested protocols via `repeated: {length_field, element}`; codegen emits recursive decoder/encoder/JSON; `mmtp_desc` + `mmtp_desc_loop` (canonical ATSC A/331 descriptor list) and `tlv_mux_frame` (multi-packet wrapper) ship as worked examples; smoke validates `frame → ALP → TLV-mux → ALP → frame` end-to-end |
| later | pending | More protocol families (LLS, MMTP-sig top-level messages, LCT-ext); ALP additional headers (flag-driven optional sections); DPDK egress sink; frame pacing |

## Repository conventions

- **Seastar pin:** `seastar-25.05.0`. The git submodule under `seastar/`
  and the `SEASTAR_VERSION` build-arg in `Dockerfile.deps` track the
  same tag — bump both together.
- **C++ standard:** C++20 throughout (CMake target standard + Seastar
  build flag in `Dockerfile.deps` are both pinned to 20).
- **Codegen at configure time:** CMake invokes `tools/codegen.py` once
  per CMake reconfigure, so editing `protocol/*.yaml` and re-running
  `ninja` is enough to pick up new fields/fixtures/tests.
- **Test layout:** every `protocol/<name>.yaml` produces a standalone
  `<name>_fixtures_test` CTest binary; hand-written tests live in
  `tests/`. Both classes are picked up automatically by
  `tests/CMakeLists.txt`.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) for the full text.

All first-party source files carry an `SPDX-License-Identifier:
Apache-2.0` tag in their header so toolchain-level license scanners
(REUSE, scancode, ...) classify the project correctly without parsing
file-level boilerplate.

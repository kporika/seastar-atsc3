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
> build order.

## Layout

```
atsc3_proto/
├── protocol/                  # YAML protocol definitions
│   ├── alp.yaml               #   ATSC A/330 §5.2 — ALP base header
│   ├── tlv_mux.yaml           #   ATSC A/330 Annex A — TLV multiplex packet
│   ├── tlv_mux_frame.yaml     #   wrapper: N tlv_mux packets (M6 example)
│   ├── mmtp_desc.yaml         #   ATSC A/331 Annex A.5 — MMTP descriptor
│   └── mmtp_desc_loop.yaml    #   length-prefixed loop of mmtp_desc (M6 example)
├── tools/
│   ├── codegen.py             # YAML → C++ (jinja2 templates)
│   ├── codegen_templates/     # types.h, decoder.{h,cc}, encoder.{h,cc},
│   │                          # tojson.{h,cc}, fromjson.{h,cc}, fixtures_test.cc
│   ├── lint_protomap.py       # schema validator
│   ├── requirements.txt       # PyYAML, Jinja2
│   └── smoke/codec_smoke.py   # python mirror of decode/encode + pipeline check
├── lib/                       # codec library
│   ├── runtime/
│   │   ├── bit_reader.h       # MSB-first bit reader used by generated decoders
│   │   └── bit_writer.h       # MSB-first bit writer used by generated encoders
│   └── generated/             # codegen output (regenerated each build)
│       ├── <p>_types.h        # enums + <enum>_name + <enum>_from_name
│       ├── <p>_decoder.{cc,h} # raw bytes  -> decoded_t
│       ├── <p>_encoder.{cc,h} # decoded_t  -> raw bytes
│       ├── <p>_tojson.{cc,h}  # decoded_t  -> rapidjson::Document
│       ├── <p>_fromjson.{cc,h}# rapidjson  -> decoded_t
│       └── <p>_fixtures_test.cc
├── gw/                        # Seastar gateway service
│   ├── main.cc
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
│   └── encoder_pipeline_test.cc
├── scripts/
│   ├── integration_test.sh    # spawn gw + mmt_probe hex send/verify loopback
│   ├── rtcm_integration_test.sh   # rtcm-gen → gw → send → verify --validate-rtcm
│   └── throughput_soak.sh     # null:// sink + duration-bounded burst
├── docs/                      # architecture notes + gap analyses
│   ├── END_TO_END_GAPS.md     #   full inventory: input API → RF exciter
│   └── end_to_end_gaps.canvas.tsx  # Cursor-canvas rendering of the same
├── seastar/                   # git submodule, pinned to seastar-25.05.0
├── Dockerfile.deps            # base image: Seastar + transitive build deps
├── Dockerfile.app             # builder + slim runtime image (atsc3-proto)
├── CMakeLists.txt
├── build.sh
└── Makefile
```

## Build

### Recommended: Docker (zero local dependencies)

The build uses the same two-stage pattern as the sibling SIP toolchain
shipped in this organization: a heavy `deps` image holds Seastar and its
transitive build deps, and a slim `app` image is layered on top with just
the project binaries.

```bash
make deps              # 1) build atsc3-deps (Seastar + tooling)   ← ~15 min once
make image             # 2) build atsc3-proto (codegen + cmake + ninja
                       #    + ctest + python smoke, then a runtime layer
                       #    carrying just the binaries + protocol YAMLs)
make image-integ       # 3) end-to-end loopback inside the runtime image
make image-shell       # interactive bash in the runtime image
make run RUN_ARGS="--smp 4 --sink stdout://"
                       # docker run atsc3-proto, args via RUN_ARGS
```

`make image` auto-rebuilds `atsc3-deps` whenever `Dockerfile.deps` changes
(tracked via `.make/deps.stamp`), so once you've run `make deps` you can
mostly forget about it.

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
make integ                                # end-to-end loopback against ./build
```

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

## Run tests

```bash
cd build
ctest --output-on-failure
# expected:
#   Test #1: alp_fixtures_test ........ Passed
#   Test #2: tlv_mux_fixtures_test .... Passed
#   Test #3: encoder_pipeline_test .... Passed
```

The python smoke can be run without a C++ build (useful when iterating on
YAML or templates):

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r tools/requirements.txt
python tools/smoke/codec_smoke.py
```

## Run the gateway (M4)

The wire protocol on the ingress socket is **length-prefixed**: each
message is `[u32 length, big-endian][payload bytes]`. The gateway wraps
the payload as ALP (PACKET_TYPE_EXTENSION), then as TLV-mux (SIGNALING),
and writes the TLV-mux bytes to the sink.

```bash
# Single shard, sink to a file (one file per shard: gw.out.shard0, ...)
./build/gw/atsc3_gw --smp 1 --ingress 0.0.0.0:9000 --sink file:///tmp/gw.out

# Multi-shard
./build/gw/atsc3_gw --smp 4 --ingress 0.0.0.0:9000 --sink file:///tmp/gw.out
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

### One-shot integration script

```bash
./scripts/integration_test.sh                # uses ./build
./scripts/integration_test.sh /path/to/build # or a custom build dir
# Spawns gw, runs mmt_probe send + verify against a temp sink file,
# then tears the gw down. Exits 0 on success.
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

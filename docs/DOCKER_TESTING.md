# Docker testing — command reference

Run the full Linux + Seastar build, **`ctest`**, Python **`codec_smoke`**, and integration scripts (**`atsc3_gw`** + **`mmt_probe`**) without a native Seastar install. This is the recommended path on macOS and minimal host trees.

**Prerequisites:** Docker Desktop (or another engine) running; repo root as cwd.

```bash
cd atsc3_proto   # repository root
```

---

## One-time setup

Build the deps image (**Seastar**, toolchain, headers). Re-run when **`Dockerfile.deps`** changes.

```bash
make deps
# equivalent: docker build -f Dockerfile.deps -t atsc3-deps:latest .
```

---

## Unit tests + codec smoke (fastest full check)

Clean configure + **`ninja`** in **`build-docker-ctest/`**, then **`ctest`** and **`tools/smoke/codec_smoke.py`**. Same checks as the **`Dockerfile.app`** builder stage (without packaging a runtime image).

```bash
make docker-ctest
# equivalent: ./scripts/docker_ctest.sh
```

**Includes:** `tools/lint_protomap.py` → codegen → **23** ctest targets (fixture round-trips, **`encoder_pipeline_test`**, **`udp_ipv4_test`**) → smoke.

**Output tree:** `build-docker-ctest/` (gitignored). Binaries: `build-docker-ctest/gw/atsc3_gw`, `build-docker-ctest/mmt_probe/mmt_probe`.

---

## Integration scripts (gw loopback + sinks)

Use the **`build-docker-ctest`** tree from the step above (must include **`atsc3_gw`**).

### All integration scripts

Same order as **`scripts/run_all_integration.sh`** / **`make integ-all`**:

`integration_test` → `udp` → `ipv4udp_file` → `stltp` → `lls` → `admin_patch_config` → `m7_operator` → `lct_word0` (**A**–**D**) → `mmtp_word0` (**E**–**ZC**) → `rtcm` (**12×96**).

```bash
docker run --rm \
  -v "$(pwd)":/work \
  -w /work \
  atsc3-deps:latest \
  bash -lc './scripts/run_all_integration.sh build-docker-ctest'
```

### MMTP lab only (phases **E**–**ZC**)

```bash
docker run --rm \
  -v "$(pwd)":/work \
  -w /work \
  atsc3-deps:latest \
  bash -lc './scripts/mmtp_word0_integration_test.sh build-docker-ctest'
```

### Single script + custom build dir

```bash
docker run --rm \
  -v "$(pwd)":/work \
  -w /work \
  atsc3-deps:latest \
  bash -lc './scripts/integration_test.sh build-docker-ctest'
```

Host equivalents (when **`./build/gw/atsc3_gw`** or **`./build-docker/gw/atsc3_gw`** exists):

```bash
make integ-all
make integ-mmtp-word0
./scripts/run_all_integration.sh          # auto-picks build/ or build-docker/
./scripts/run_all_integration.sh build-docker-ctest
```

---

## Optional: persistent bind-mount build

Reuse **`./build-docker/`** across edits without wiping **`build-docker-ctest/`** each **`docker-ctest`** run:

```bash
make docker-build
docker run --rm \
  -v "$(pwd)":/work \
  -w /work \
  atsc3-deps:latest \
  bash -lc './scripts/run_all_integration.sh build-docker'
```

---

## Runtime image path (slower, self-contained)

Build **`atsc3-proto`** (multi-stage image with binaries under **`/usr/local/bin`**). Integration entrypoints ignore **`BUILD_DIR`** and use **`PATH`**.

```bash
make image              # builder runs ctest + smoke; fails image build on test failure
make image-fast         # skip tests: docker build --build-arg RUN_TESTS=0

make image-integ        # integration_test.sh only
make image-integ-mmtp-word0
make image-integ-all    # full script suite (separate container per script; RTCM 12×96)
```

---

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `ATSC3_DEPS_IMAGE` | `atsc3-deps:latest` | Override deps image for **`docker_ctest.sh`** |
| `DOCKER_MAKE_JOBS` | `8` | Parallel **`ninja`** jobs in Docker |
| `ATSC3_BUILD_DIR` | (auto) | Integration scripts: `build`, `build-docker`, or absolute path |
| `ATSC3_GW` / `MMT_PROBE` | (auto) | Explicit binary paths for integration scripts |

---

## Troubleshooting

| Symptom | Action |
|---------|--------|
| `Cannot connect to the Docker daemon` | Start Docker Desktop; wait until `docker info` succeeds. |
| `Seastar not found` on host **`cmake`** | Use **`make docker-ctest`** / Docker integration above; do not require host Seastar. |
| Stale CMake cache after macOS ↔ Linux switch | Prefer **`build-docker-ctest/`** or **`make docker-ctest`** (fresh tree); avoid mixing **`build/`** caches across OSes. |
| Integration cannot find **`atsc3_gw`** | Run **`make docker-ctest`** first, or pass **`build-docker-ctest`** (or **`build-docker`**) as the script’s **`BUILD_DIR`** argument. |

---

## Quick “everything green” sequence

```bash
make deps
make docker-ctest
docker run --rm -v "$(pwd)":/work -w /work atsc3-deps:latest \
  bash -lc './scripts/run_all_integration.sh build-docker-ctest'
```

Expect **`=== docker_ctest.sh: ALL PASS ===`** and **`>>> run_all_integration: PASS (all scripts)`**.

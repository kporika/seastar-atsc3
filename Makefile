# Top-level convenience targets for atsc3_proto. The real build is
# CMake/Ninja under ./build; these are thin wrappers.
#
# Quick start (host with native deps):
#   make build              # codegen + cmake + ninja
#   make smoke              # pure-python correctness check (no C++ build)
#   make integ              # end-to-end gw + mmt_probe loopback
#   make integ-udp          # udp:// sink
#   make integ-ipv4udp      # ipv4udp-file:// + m8 strip + verify
#   make integ-admin        # PATCH /config sink_uri hot-swap (needs python3)
#   make integ-all          # all host integ scripts (RTCM 12×96)
#   make integ-stltp       # stltp:// lab UDP + strip + verify
#   make integ-lls         # lls:// Table 6.1 + gzip UDP + Python validate
#
# Quick start (zero local deps; everything runs in Docker):
#   make deps               # build the atsc3-deps image (Seastar + tooling)
#   make image              # build atsc3-proto from source via Dockerfile.app
#                           # (runs ctest + python smoke during build)
#   make run                # docker run atsc3-proto with default args
#   make image-integ        # file-sink integration loopback in the image
#   make image-integ-ipv4udp   # M8 file sink in the image
#   make image-integ-udp    # udp:// in the image
#   make image-integ-admin  # PATCH /config in the image (needs python3)
#   make image-integ-all    # full suite in the image (incl. RTCM 12×96)
#   make image-integ-rtcm   # RTCM path only (12×96) in the image
#   make image-integ-stltp     # STLTP lab UDP integration in the image
#   make image-integ-lls       # LLS UDP integration in the image
#   make image-shell        # interactive shell inside the runtime image

PYTHON         ?= python3
PROTOCOL_DIR   := protocol
GENERATED_DIR  := lib/generated

DOCKER         ?= docker
DEPS_IMAGE     ?= atsc3-deps
APP_IMAGE      ?= atsc3-proto
DEPS_DOCKERFILE := Dockerfile.deps
APP_DOCKERFILE  := Dockerfile.app

# Marker file that records when atsc3-deps was last built. Tracked under
# .make/ so a stale Dockerfile.deps automatically triggers a rebuild before
# the next `make image`.
DEPS_STAMP     := .make/deps.stamp

.PHONY: default build codegen clean lint smoke integ integ-udp integ-ipv4udp integ-stltp integ-lls integ-rtcm integ-admin integ-all \
        deps image image-fast image-integ image-integ-udp image-integ-ipv4udp image-integ-stltp image-integ-lls image-integ-rtcm image-integ-admin image-integ-all run image-shell deps-shell

default: build

# --- native targets ---------------------------------------------------------

codegen:
	$(PYTHON) tools/codegen.py --in $(PROTOCOL_DIR) --out $(GENERATED_DIR)

lint:
	$(PYTHON) tools/lint_protomap.py $(PROTOCOL_DIR)

build: codegen
	./build.sh

# Pure-python correctness check for fixtures + gw/encoder_pipeline composition.
# Useful when iterating on YAML or templates without a full C++ build.
smoke:
	$(PYTHON) tools/smoke/codec_smoke.py

# End-to-end integration: spawns ./build/gw/atsc3_gw, pushes payloads via
# ./build/mmt_probe/mmt_probe send, then verifies the sink file. Requires a
# prior `make build`.
integ:
	./scripts/integration_test.sh

# Same payloads as integ, but gw --sink udp://127.0.0.1:R (Python collects UDP).
integ-udp:
	./scripts/udp_integration_test.sh

# Same as integ-udp, but --sink ipv4udp-file://… then m8_bin_to_pcap --extract-tlvmux.
integ-ipv4udp:
	./scripts/ipv4udp_file_integration_test.sh

# Lab STLTP UDP wrap (gw/sink.cc) → strip fixed prefix → verify TLV-mux.
integ-stltp:
	./scripts/stltp_integration_test.sh

# lls:// sink: cleartext XML → Table 6.1 + gzip UDP (Python validates one datagram).
integ-lls:
	./scripts/lls_integration_test.sh

# RTCM file → gw → TLV-mux → verify --validate-rtcm (default 32×128; override via script args).
integ-rtcm:
	./scripts/rtcm_integration_test.sh

# HTTP admin POST /config/sink (sink_uri ↔ null://); needs python3.
integ-admin:
	./scripts/admin_patch_config_integration_test.sh

# All integration scripts in one shot (RTCM uses 12×96 for speed).
integ-all:
	./scripts/run_all_integration.sh

clean:
	rm -rf build .make
	rm -f $(GENERATED_DIR)/*.cc $(GENERATED_DIR)/*.h

# --- docker targets ---------------------------------------------------------

# Stage 0: build the atsc3-deps base image (Seastar + transitive build deps).
# A marker file under .make/ records the last successful build so `make image`
# can depend on it without re-querying the docker daemon every time.
deps: $(DEPS_STAMP)

$(DEPS_STAMP): $(DEPS_DOCKERFILE)
	$(DOCKER) build -f $(DEPS_DOCKERFILE) -t $(DEPS_IMAGE) .
	@mkdir -p $(dir $@) && touch $@

# Stage 1: build atsc3_proto from source using Dockerfile.app. This runs
# codegen + cmake + ninja inside the deps image, then exercises the full
# ctest + python smoke. The resulting atsc3-proto image carries just the
# atsc3_gw / mmt_probe binaries plus the operator-facing files.
# Auto-builds atsc3-deps first if it's missing or Dockerfile.deps changed.
image: $(DEPS_STAMP)
	$(DOCKER) build -f $(APP_DOCKERFILE) -t $(APP_IMAGE) .

# Same as `image` but skips the ctest + smoke step. Useful for fast
# iteration when you've just verified locally and want to ship quickly.
image-fast: $(DEPS_STAMP)
	$(DOCKER) build -f $(APP_DOCKERFILE) -t $(APP_IMAGE) --build-arg RUN_TESTS=0 .

# Run the integration loopback (gw + mmt_probe in one container) against
# the freshly-built atsc3-proto runtime image.
image-integ: image
	$(DOCKER) run --rm --entrypoint /opt/atsc3_proto/scripts/integration_test.sh $(APP_IMAGE)

image-integ-udp: image
	$(DOCKER) run --rm --entrypoint /opt/atsc3_proto/scripts/udp_integration_test.sh $(APP_IMAGE)

image-integ-ipv4udp: image
	$(DOCKER) run --rm --entrypoint /opt/atsc3_proto/scripts/ipv4udp_file_integration_test.sh $(APP_IMAGE)

image-integ-stltp: image
	$(DOCKER) run --rm --entrypoint /opt/atsc3_proto/scripts/stltp_integration_test.sh $(APP_IMAGE)

image-integ-lls: image
	$(DOCKER) run --rm --entrypoint /opt/atsc3_proto/scripts/lls_integration_test.sh $(APP_IMAGE)

image-integ-rtcm: image
	$(DOCKER) run --rm --entrypoint /opt/atsc3_proto/scripts/rtcm_integration_test.sh $(APP_IMAGE) "" 12 96

image-integ-admin: image
	$(DOCKER) run --rm --entrypoint /opt/atsc3_proto/scripts/admin_patch_config_integration_test.sh $(APP_IMAGE)

# Full integration suite (same order as CI; RTCM uses 12×96).
image-integ-all: image
	set -e; \
	for s in integration_test.sh udp_integration_test.sh ipv4udp_file_integration_test.sh stltp_integration_test.sh lls_integration_test.sh admin_patch_config_integration_test.sh; do \
		echo ">>> $$s"; \
		$(DOCKER) run --rm --entrypoint /opt/atsc3_proto/scripts/$$s $(APP_IMAGE); \
	done; \
	echo ">>> rtcm_integration_test.sh"; \
	$(DOCKER) run --rm --entrypoint /opt/atsc3_proto/scripts/rtcm_integration_test.sh $(APP_IMAGE) "" 12 96; \
	echo ">>> image-integ-all: PASS"

# Override args via RUN_ARGS, e.g.:
#   make run RUN_ARGS="--smp 4 --sink file:///tmp/out --ingress 0.0.0.0:9000"
RUN_ARGS ?=
run:
	$(DOCKER) run --rm -p 9000:9000 $(APP_IMAGE) $(RUN_ARGS)

# Interactive bash shell inside the *runtime* image (binaries + scripts).
# Useful for poking the YAMLs, running mmt_probe by hand, or invoking the
# integration scripts against a sidecar atsc3_gw.
image-shell:
	$(DOCKER) run --rm -it --entrypoint bash $(APP_IMAGE)

# Interactive bash shell inside the *deps* image with the repo bind-mounted
# at /work. Useful when iterating on CMake / template changes that you want
# to recompile without rebuilding the whole atsc3-proto image each time.
deps-shell: $(DEPS_STAMP)
	$(DOCKER) run --rm -it -v "$(CURDIR)":/work -w /work $(DEPS_IMAGE)

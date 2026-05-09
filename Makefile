# Top-level convenience targets for atsc3_proto. The real build is
# CMake/Ninja under ./build; these are thin wrappers.
#
# Quick start (host with native deps):
#   make build              # codegen + cmake + ninja
#   make smoke              # pure-python correctness check (no C++ build)
#   make integ              # end-to-end gw + mmt_probe loopback
#
# Quick start (zero local deps; everything runs in Docker):
#   make deps               # build the atsc3-deps image (Seastar + tooling)
#   make image              # build atsc3-proto from source via Dockerfile.app
#                           # (runs ctest + python smoke during build)
#   make run                # docker run atsc3-proto with default args
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

.PHONY: default build codegen clean lint smoke integ \
        deps image image-fast image-integ run image-shell deps-shell

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

# Run the runtime image with its default ENTRYPOINT (atsc3_gw → stdout sink).
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

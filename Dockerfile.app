# =============================================================================
# Dockerfile.app — build + ship the atsc3_proto application image.
#
# Two stages:
#   1) builder  — FROM atsc3-deps:latest (~2.2 GB; carries Seastar source,
#                 dev headers, the full GCC toolchain, ragel, etc.). Copies
#                 the project source, runs codegen + cmake + ninja, then
#                 exercises ctest. Build fails if any test fails.
#   2) runtime  — FROM debian:12-slim (~80 MB base). Installs ONLY the
#                 runtime .so packages atsc3_gw / mmt_probe link against
#                 (Seastar itself is built as libseastar.a and statically
#                 linked, so the image carries no Seastar dev artifacts).
#                 Plus python3 + python3-yaml so tools/smoke/codec_smoke.py
#                 still runs in-image. The full build tree is *not*
#                 propagated to the runtime layer.
#
# Resulting image is in the 250-300 MB range — ~10x slimmer than the
# naive "FROM atsc3-deps" approach.
#
#   Build:    docker build -f Dockerfile.app -t atsc3-proto .
#             # or, with the make wrapper:
#             $ make image
#
#   Run:      docker run --rm -p 9000:9000 atsc3-proto \
#                 --ingress 0.0.0.0:9000 --sink stdout://
#
#   Inspect:  docker run --rm -it --entrypoint bash atsc3-proto
#
# Skip the test step (faster CI iteration) by overriding RUN_TESTS at build:
#   docker build -f Dockerfile.app -t atsc3-proto --build-arg RUN_TESTS=0 .
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1 — builder
# -----------------------------------------------------------------------------
FROM atsc3-deps:latest AS builder

WORKDIR /src/atsc3_proto

# Copy only what the build needs. Keeping each COPY layer narrow lets docker
# cache the unchanged inputs (e.g. protocol/ rarely churns) across iterations.
COPY CMakeLists.txt build.sh ./
COPY tools/         ./tools/
COPY fixtures/    ./fixtures/
COPY protocol/      ./protocol/
COPY lib/           ./lib/
COPY gw/            ./gw/
COPY mmt_probe/     ./mmt_probe/
COPY tests/         ./tests/
COPY scripts/       ./scripts/

# Run codegen + cmake + ninja inside the image (build.sh handles all of it).
# Codegen is idempotent and lib/generated/ is .gitignored, so any stale files
# accidentally COPYd in are safely overwritten.
ENV BUILD_TYPE=RelWithDebInfo
ENV MAKE_JOBS=8
RUN chmod +x build.sh && ./build.sh

# Run the full ctest matrix (5 fixture round-trip executables +
# encoder_pipeline_test + udp_ipv4_test) and the python smoke. RUN_TESTS=0 skips both
# for faster image iteration; default is 1 so CI catches regressions.
ARG RUN_TESTS=1
RUN if [ "${RUN_TESTS}" = "1" ]; then \
        cd build && ctest --output-on-failure && \
        cd .. && python3 tools/smoke/codec_smoke.py; \
    else \
        echo ">>> RUN_TESTS=0, skipping ctest + smoke"; \
    fi

# -----------------------------------------------------------------------------
# Stage 2 — runtime
# -----------------------------------------------------------------------------
FROM debian:12-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# Runtime .so deps for the two binaries (verified via `ldd` after the
# builder stage). Seastar still links c-ares dynamically on some builds
# (libcares.so.2). Everything else Seastar pulls in (libseastar, lz4, sctp,
# numa, openssl, crypto++, ...) is statically linked into atsc3_gw via
# libseastar.a.
#
# python3 + python3-yaml are kept so tools/smoke/codec_smoke.py runs
# in-image; bash + the integration scripts then double as a self-contained
# verification suite.
RUN apt-get -y update && apt-get -y install --no-install-recommends \
        libc-ares2 \
        libboost-program-options1.74.0 \
        libboost-thread1.74.0 \
        libfmt9 \
        libgnutls30 \
        libhwloc15 \
        libyaml-cpp0.7 \
        python3 \
        python3-yaml \
        ca-certificates \
        bash \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Just the binaries + the operator-facing surface (protocol defs, scripts,
# python smoke, M9 LLS pack helper + fixtures). The C++ build tree,
# lib/generated/, and tests/ are dropped.
COPY --from=builder /src/atsc3_proto/build/gw/atsc3_gw           /usr/local/bin/atsc3_gw
COPY --from=builder /src/atsc3_proto/build/mmt_probe/mmt_probe   /usr/local/bin/mmt_probe
COPY --from=builder /src/atsc3_proto/protocol                    /opt/atsc3_proto/protocol
COPY --from=builder /src/atsc3_proto/scripts                     /opt/atsc3_proto/scripts
COPY --from=builder /src/atsc3_proto/tools/smoke                 /opt/atsc3_proto/tools/smoke
COPY --from=builder /src/atsc3_proto/tools/m9_lls_pack.py        /opt/atsc3_proto/tools/m9_lls_pack.py
COPY --from=builder /src/atsc3_proto/tools/m8_bin_to_pcap.py     /opt/atsc3_proto/tools/m8_bin_to_pcap.py
COPY --from=builder /src/atsc3_proto/fixtures                    /opt/atsc3_proto/fixtures

WORKDIR /opt/atsc3_proto

EXPOSE 9000

# Optional HTTP admin (--admin-http); publish when using control-plane endpoints, e.g.
#   docker run --rm -p 9000:9000 -p 8080:8080 atsc3-proto \
#     --ingress 0.0.0.0:9000 --sink stdout:// --admin-http 0.0.0.0:8080
# anything by passing your own argv after the image name:
#   docker run --rm -p 9000:9000 atsc3-proto --sink file:///tmp/out --smp 4
ENTRYPOINT ["/usr/local/bin/atsc3_gw"]
CMD ["--ingress", "0.0.0.0:9000", "--sink", "stdout://"]

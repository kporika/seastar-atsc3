#!/usr/bin/env bash
# Build atsc3_proto. Configures CMake/Ninja under ./build and compiles
# the gateway, mmt_probe, and codec library.
#
# Env vars:
#   BUILD_TYPE   Debug (default), RelWithDebInfo, Release
#   MAKE_JOBS    parallel compile jobs (default 16; lower if RAM-constrained)
#
# Prereqs (use the in-tree Dockerfile.deps image to satisfy these):
#   - Seastar 25.05.0 installed system-wide; pkg-config must find `seastar`.
#   - python3 with PyYAML and Jinja2 on PATH (codegen runs at configure time).
#   - rapidjson headers under /usr/include (Debian: rapidjson-dev).
#
# See README.md for native-build instructions.
set -euo pipefail

cd "$(dirname "$0")"

mkdir -p build
cd build

cmake -G Ninja \
      -DCMAKE_BUILD_TYPE="${BUILD_TYPE:-Debug}" \
      -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
      ..

ninja -j "${MAKE_JOBS:-16}"

echo
echo ">>> built: $(pwd)/gw/atsc3_gw"
echo ">>> built: $(pwd)/mmt_probe/mmt_probe"
echo ">>> tests: cd $(pwd) && ctest --output-on-failure"

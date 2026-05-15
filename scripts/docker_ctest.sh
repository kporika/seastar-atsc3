#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Run the same checks as Dockerfile.app builder stage (minus packaging):
#   lint → codegen → clean cmake build in build-docker-ctest/ → ctest → codec_smoke
#
# Requires: Docker, image atsc3-deps:latest (`make deps` or Dockerfile.deps).
#
#   ./scripts/docker_ctest.sh
#   ATSC3_DEPS_IMAGE=my-registry/atsc3-deps:tag ./scripts/docker_ctest.sh

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPS_IMAGE="${ATSC3_DEPS_IMAGE:-atsc3-deps:latest}"
JOBS="${DOCKER_MAKE_JOBS:-8}"

exec docker run --rm \
    -v "${ROOT}:/work" \
    -w /work \
    "${DEPS_IMAGE}" \
    bash -lc "set -euo pipefail
        python3 tools/lint_protomap.py protocol
        python3 tools/codegen.py --in protocol --out lib/generated
        rm -rf build-docker-ctest && mkdir -p build-docker-ctest && cd build-docker-ctest
        cmake -GNinja -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
        ninja -j${JOBS}
        ctest --output-on-failure
        cd ..
        python3 tools/smoke/codec_smoke.py
        echo '=== docker_ctest.sh: ALL PASS ==='"

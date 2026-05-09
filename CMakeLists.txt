cmake_minimum_required(VERSION 3.16)

project(atsc3_proto
        VERSION 0.1.0
        LANGUAGES CXX)

# Seastar 25.05.0 builds against C++20 cleanly; the Dockerfile.deps image
# in this directory pins both to keep the consumer/library standards aligned.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

# -----------------------------------------------------------------------------
# Codegen: regenerate lib/generated/* from protocol/*.yaml at configure time.
# `tools/codegen.py` reads every protocol/*.yaml file and emits the
# corresponding C++ types/decoder/encoder/JSON pair plus a fixture-test
# executable per protocol.
# -----------------------------------------------------------------------------
find_program(PYTHON3_EXE python3)
if(PYTHON3_EXE AND EXISTS "${CMAKE_CURRENT_LIST_DIR}/tools/codegen.py")
    execute_process(
        COMMAND ${PYTHON3_EXE} ${CMAKE_CURRENT_LIST_DIR}/tools/codegen.py
                --in  ${CMAKE_CURRENT_LIST_DIR}/protocol
                --out ${CMAKE_CURRENT_LIST_DIR}/lib/generated
        RESULT_VARIABLE _codegen_rc
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR})
    if(NOT _codegen_rc EQUAL 0)
        message(FATAL_ERROR "atsc3_proto codegen failed (rc=${_codegen_rc})")
    endif()
else()
    message(STATUS "atsc3_proto: codegen step skipped "
                   "(missing python3 or tools/codegen.py)")
endif()

# -----------------------------------------------------------------------------
# Find Seastar via its installed CMake config (preferred over pkg-config —
# the SeastarConfig.cmake export carries the full transitive link line:
# libcares-seastar, hwloc, gnutls, sctp, lz4, ucontext/getcontext, ...).
# Dockerfile.deps in this directory installs Seastar 25.05.0 under /usr; for
# native builds install Seastar separately and ensure `find_package(Seastar)`
# resolves (Seastar's own `ninja install` puts SeastarConfig.cmake in
# <prefix>/lib/<arch>/cmake/Seastar/).
# -----------------------------------------------------------------------------
find_package(Seastar REQUIRED)

add_subdirectory(lib)
add_subdirectory(gw)
add_subdirectory(mmt_probe)

enable_testing()
if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/tests/CMakeLists.txt")
    add_subdirectory(tests)
endif()

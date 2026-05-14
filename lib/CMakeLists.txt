# atsc3_proto codec library.
#
# Sources are split into:
#   - runtime/  : hand-written, protocol-agnostic helpers (bit_reader.h, ...)
#   - generated/: codegen output from tools/codegen.py (regenerated each build)
#
# The fixture-test files (lib/generated/*_fixtures_test.cc) are NOT compiled
# into the library — tests/CMakeLists.txt picks them up as standalone
# executables.

set(RUNTIME_SOURCES
    runtime/bit_reader.h
    runtime/bit_writer.h
    runtime/ipv4_udp.hh
    runtime/ipv4_udp.cc
    runtime/lls_table6_1.hh
)

# Generated lib sources: everything in generated/ except the *_fixtures_test.cc
# files (which become standalone test binaries).
file(GLOB GENERATED_ALL CONFIGURE_DEPENDS
     "${CMAKE_CURRENT_LIST_DIR}/generated/*.cc"
     "${CMAKE_CURRENT_LIST_DIR}/generated/*.h")

set(GENERATED_LIB_SOURCES "")
set(GENERATED_TEST_SOURCES "")
foreach(g ${GENERATED_ALL})
    if(g MATCHES "_fixtures_test\\.cc$")
        list(APPEND GENERATED_TEST_SOURCES "${g}")
    else()
        list(APPEND GENERATED_LIB_SOURCES "${g}")
    endif()
endforeach()

# Hand the test list back up to the parent so tests/CMakeLists.txt can use it.
set(ATSC3_PROTO_GENERATED_TESTS "${GENERATED_TEST_SOURCES}"
    CACHE INTERNAL "Generated fixture-test sources" FORCE)

set(ATSC3_PROTO_SOURCES ${RUNTIME_SOURCES})
if(GENERATED_LIB_SOURCES)
    list(APPEND ATSC3_PROTO_SOURCES ${GENERATED_LIB_SOURCES})
endif()

add_library(atsc3_proto STATIC ${ATSC3_PROTO_SOURCES})
target_include_directories(atsc3_proto PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/runtime
    ${CMAKE_CURRENT_LIST_DIR}/generated)
# rapidjson is header-only and ships at /usr/include/rapidjson on the
# atsc3-deps image (and most distro packages). Add explicitly for portability.
target_include_directories(atsc3_proto PUBLIC /usr/include)

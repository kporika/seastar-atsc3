# mmt_probe — standalone POSIX CLI for end-to-end gateway loopback testing.
#
# Intentionally NOT a Seastar app: keeps the binary small and easy to use
# from shell scripts and CI without an SMP runtime. It links against
# atsc3_proto for the TLV-mux/ALP decode used by the verify path.

add_executable(mmt_probe
    main.cc
    rtcm_v3.cc rtcm_v3.h)

target_include_directories(mmt_probe PRIVATE
    ${CMAKE_CURRENT_LIST_DIR})

target_link_libraries(mmt_probe PRIVATE
    atsc3_proto
    pthread)

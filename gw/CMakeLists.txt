# atsc3_proto gateway executable.

set(GW_SOURCES
    main.cc
    atsc3_gw.cc atsc3_gw.h
    ingress_tcp.cc ingress_tcp.h
    sink.cc sink.h
    length_framer.cc length_framer.h
    encoder_pipeline.cc encoder_pipeline.h
)

add_executable(atsc3_gw ${GW_SOURCES})

target_include_directories(atsc3_gw PRIVATE ${CMAKE_CURRENT_LIST_DIR})

# Seastar::seastar is the canonical imported target from SeastarConfig.cmake.
# It transitively pulls in the full set of compile flags (-DSEASTAR_API_LEVEL,
# -DSEASTAR_SSTRING, ...) and link dependencies (boost, hwloc, lz4, c-ares,
# gnutls, sctp, fmt, atomic, dl, rt, libnuma, ...).
target_link_libraries(atsc3_gw PRIVATE
    atsc3_proto
    Seastar::seastar
    boost_program_options
    pthread)

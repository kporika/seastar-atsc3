// SPDX-License-Identifier: Apache-2.0
//
// atsc3_proto gateway — sharded server.
//
// Per-shard topology (M4):
//
//   ingress_tcp                     encoder_pipeline                 sink
//   ──────────►  raw payload  ────►  ALP   ── TLV-mux ──►  bytes  ────►
//   (length-                                                       file://
//    framed)                                                       stdout://

#pragma once

#include <memory>
#include <string>

#include <seastar/core/distributed.hh>
#include <seastar/core/future.hh>
#include <seastar/core/temporary_buffer.hh>
#include <seastar/net/socket_defs.hh>

#include "encoder_pipeline.h"
#include "ingress_tcp.h"
#include "sink.h"

namespace atsc3::gw {

struct gw_config {
    seastar::ipv4_addr ingress_addr;
    std::string sink_uri;
};

class gw_server {
public:
    explicit gw_server(gw_config cfg);

    // Called once per shard by the seastar::sharded<> harness.
    seastar::future<> start();
    seastar::future<> stop();

    // Per-shard counters; aggregated by main() at shutdown for visibility.
    struct stats_t {
        uint64_t bytes_in = 0;        // payload bytes read from ingress
        uint64_t bytes_out = 0;       // encoded TLV-mux bytes written to sink
        uint64_t payloads = 0;        // complete length-framed payloads
        uint64_t encode_errors = 0;   // payloads dropped at the encoder
        uint64_t connections = 0;     // (reserved; not yet incremented)
    };
    seastar::future<stats_t> get_stats() const;

private:
    gw_config _cfg;
    std::unique_ptr<sink> _sink;
    std::unique_ptr<ingress_tcp> _ingress;
    encoder_pipeline _enc{};
    stats_t _stats;

    seastar::future<> on_payload(seastar::temporary_buffer<char> buf);
};

}  // namespace atsc3::gw

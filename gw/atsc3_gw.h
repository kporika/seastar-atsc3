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
//                                                                   null://
//                                                                   udp://
//                                                                   stltp://
//
//   When sink is lls://, raw payload skips the encoder and is framed as
//   A/331 LLS (Table 6.1 + gzip) on UDP by the sink.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <seastar/core/distributed.hh>
#include <seastar/core/future.hh>
#include <seastar/core/semaphore.hh>
#include <seastar/core/temporary_buffer.hh>
#include <seastar/net/socket_defs.hh>

#include "encoder_pipeline.h"
#include "ingress_tcp.h"
#include "sink.h"

namespace atsc3::gw {

struct gw_config {
    seastar::ipv4_addr ingress_addr;
    std::string sink_uri;
    /// When set on shard 0, GET/POST/DELETE /services load and persist this JSON file.
    std::optional<std::string> services_state_file;
};

// Admin service registry (shard 0). Optional JSON persistence via gw_config::services_state_file.
struct admin_service_entry {
    std::uint32_t id = 0;
    std::string name;
};

struct admin_service_add_result {
    bool ok = false;
    std::uint32_t id = 0;
    std::string error;
    std::string accepted_name;  // canonical name after trim (set when ok)
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
        uint64_t bytes_out = 0;       // TLV-mux or raw bytes written (see lls:// bypass)
        uint64_t payloads = 0;        // complete length-framed payloads
        uint64_t encode_errors = 0;   // payloads dropped at the encoder
        uint64_t connections = 0;     // (reserved; not yet incremented)
    };
    seastar::future<stats_t> get_stats() const;

    // Same path as TCP length-framed payloads; used by HTTP POST /ingest.
    seastar::future<> ingest_payload(seastar::temporary_buffer<char> buf);

    /// Atomically (per shard) replace the output sink. Returns `std::nullopt`
    /// on success, or an error message if the new URI is rejected by `make_sink`.
    seastar::future<std::optional<std::string>> replace_sink_uri(std::string new_uri);

    bool is_ready() const noexcept;

    // For admin HTTP GET /config (same on every shard).
    std::string ingress_listen_string() const;
    const std::string& sink_uri() const noexcept { return _cfg.sink_uri; }
    std::optional<std::string> services_state_file_path() const noexcept {
        return _cfg.services_state_file;
    }

    // Admin HTTP GET/POST /services — state kept on shard 0 only.
    std::vector<admin_service_entry> list_admin_services() const;
    admin_service_add_result add_admin_service(std::string name);
    bool admin_service_exists(std::uint32_t id) const;
    bool remove_admin_service(std::uint32_t id);

    seastar::future<> persist_admin_services_if_configured();

private:
    seastar::future<> load_admin_services_from_file_if_set();
    std::string serialize_admin_services_state() const;

    gw_config _cfg;
    std::unique_ptr<sink> _sink;
    std::unique_ptr<ingress_tcp> _ingress;
    encoder_pipeline _enc{};
    stats_t _stats;
    /// Serializes `replace_sink_uri` with sink writes in `on_payload` / `ingest_payload`.
    seastar::semaphore _sink_sem{1};

    std::vector<admin_service_entry> _admin_services;
    std::uint32_t _next_admin_service_id = 1;
    seastar::semaphore _services_persist_sem{1};

    seastar::future<> on_payload(seastar::temporary_buffer<char> buf);
};

}  // namespace atsc3::gw

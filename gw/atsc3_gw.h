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
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
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
    encoder_pipeline::config encoder{};
};

// Admin service registry (shard 0). Optional JSON persistence via gw_config::services_state_file.
struct admin_service_entry {
    std::uint32_t id = 0;
    std::string name;
    /// When set, POST /ingest with this service_id writes here instead of the shard default sink.
    std::optional<std::string> sink_uri;
};

struct admin_service_add_result {
    bool ok = false;
    std::uint32_t id = 0;
    std::string error;
    std::string accepted_name;  // canonical name after trim (set when ok)
    /// Echo of routed sink_uri (nullopt ⇒ POST /ingest uses default shard sink).
    std::optional<std::string> accepted_sink_uri;
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
    // When service_id is set, output may use that service's sink_uri (shard 0 only; TCP ingress
    // remains on the default sink).
    seastar::future<> ingest_payload(seastar::temporary_buffer<char> buf,
                                     std::optional<std::uint32_t> service_id = std::nullopt);

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

    /// True when payloads are prefixed with RFC 5651 LCT word‑0 before ALP (M8 lab).
    bool encoder_prepends_lct_word0() const noexcept {
        return _enc.encoder_config().prepend_rfc5651_lct_word0;
    }
    std::uint8_t encoder_lct_codepoint() const noexcept {
        return _enc.encoder_config().lct_word0.codepoint;
    }
    bool encoder_lct_includes_tsi() const noexcept {
        return _enc.encoder_config().prepend_rfc5651_lct_word0 &&
               _enc.encoder_config().lct_word0.tsi_flag;
    }
    std::uint32_t encoder_lct_tsi() const noexcept {
        return _enc.encoder_config().lct_transport_session_identifier;
    }
    bool encoder_lct_includes_toi() const noexcept {
        const auto& e = _enc.encoder_config();
        return e.prepend_rfc5651_lct_word0 && !e.lct_word0.tsi_flag &&
               e.lct_word0.toi_flag == 1 && !e.lct_word0.half_word_flag;
    }
    std::uint32_t encoder_lct_toi() const noexcept {
        return _enc.encoder_config().lct_transport_object_identifier;
    }

    // Admin HTTP GET/POST /services — state kept on shard 0 only.
    std::vector<admin_service_entry> list_admin_services() const;
    const admin_service_entry* find_admin_service(std::uint32_t id) const noexcept;
    seastar::future<admin_service_add_result> add_admin_service(std::string name,
                                                               std::optional<std::string> sink_uri);
    bool admin_service_exists(std::uint32_t id) const;
    /// Clears routing when clear_sink=true. Otherwise binds to non-empty URI from uri_if_set.
    seastar::future<std::optional<std::string>> patch_admin_service_sink(
        std::uint32_t id, bool clear_sink, std::optional<std::string> uri_if_set);
    seastar::future<bool> remove_admin_service(std::uint32_t id);

    seastar::future<> persist_admin_services_if_configured();

private:
    seastar::future<> load_admin_services_from_file_if_set();
    std::string serialize_admin_services_state() const;
    seastar::future<> write_through_encoder(seastar::temporary_buffer<char> buf, sink& out,
                                            std::string_view effective_sink_uri);
    seastar::future<> flush_close_all_service_sinks();

    gw_config _cfg;
    std::unique_ptr<sink> _sink;
    std::unique_ptr<ingress_tcp> _ingress;
    encoder_pipeline _enc;
    stats_t _stats;
    /// Serializes `replace_sink_uri` with sink writes in `on_payload` / `ingest_payload`.
    seastar::semaphore _sink_sem{1};

    std::vector<admin_service_entry> _admin_services;
    std::uint32_t _next_admin_service_id = 1;
    std::unordered_map<std::uint32_t, std::unique_ptr<sink>> _service_sinks;
    seastar::semaphore _services_persist_sem{1};

    seastar::future<> on_payload(seastar::temporary_buffer<char> buf);
};

}  // namespace atsc3::gw

// SPDX-License-Identifier: Apache-2.0
//
// Optional HTTP admin plane (END_TO_END_GAPS.md — smallest operator surface).
//
// Endpoints: GET /, GET /healthz, GET /readyz, GET /metrics, GET /config, PATCH+PUT /config, POST /config/sink (sink_uri),
// GET /services, POST /ingest, POST /services, PATCH /services?id=<uint>, DELETE /services?id=<uint>

#pragma once

#include <memory>
#include <optional>
#include <string>

#include <seastar/core/future.hh>
#include <seastar/core/shared_ptr.hh>
#include <seastar/net/socket_defs.hh>
#include <seastar/net/tls.hh>

namespace seastar::httpd {
class http_server_control;
}

namespace seastar {
template <typename T>
class sharded;
}

namespace atsc3::gw {

class gw_server;

/// Options gathered from CLI alongside --admin-http.
struct admin_listen_options {
    /// When non-empty, require `Authorization: Bearer <token>` for POST / PATCH / PUT / DELETE handlers.
    std::optional<std::string> bearer_token;
    /// When non-null, listen with HTTPS using these server credentials.
    seastar::shared_ptr<seastar::tls::server_credentials> tls_credentials{};
};

// After ctl.start(name), registers routes and listens on addr.
// POST /ingest forwards payloads to shard 0 for a stable sink ordering in demos.
seastar::future<> admin_http_listen(seastar::httpd::http_server_control& ctl,
                                    seastar::sharded<gw_server>& gw,
                                    seastar::socket_address addr,
                                    admin_listen_options listen_opts);

}  // namespace atsc3::gw

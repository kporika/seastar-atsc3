// SPDX-License-Identifier: Apache-2.0
//
// Optional HTTP admin plane (END_TO_END_GAPS.md — smallest operator surface).
//
// Endpoints: GET /, GET /healthz, GET /readyz, GET /metrics, GET /config, PATCH+PUT /config, POST /config/sink (sink_uri),
// GET /services, POST /ingest, POST /services, DELETE /services?id=<uint> (service registry on shard 0)

#pragma once

#include <seastar/core/future.hh>
#include <seastar/net/socket_defs.hh>

namespace seastar::httpd {
class http_server_control;
}

namespace seastar {
template <typename T>
class sharded;
}

namespace atsc3::gw {

class gw_server;

// After ctl.start(name), registers routes and listens on addr.
// POST /ingest forwards payloads to shard 0 for a stable sink ordering in demos.
seastar::future<> admin_http_listen(seastar::httpd::http_server_control& ctl,
                                    seastar::sharded<gw_server>& gw,
                                    seastar::socket_address addr);

}  // namespace atsc3::gw

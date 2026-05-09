// SPDX-License-Identifier: Apache-2.0
//
// TCP ingress for the atsc3_proto gateway.
//
// One ingress_tcp per shard, each binding to the same (addr,port) with
// SO_REUSEPORT. The Seastar reactor uses
// `server_socket::load_balancing_algorithm::port` so the kernel hashes
// incoming connections across shards — no cross-shard accept hand-off.
//
// Wire format (M4): each ingress message is length-prefixed —
//
//   [u32 length, big-endian] [length bytes of payload]
//
// A per-connection `length_framer` accumulates partial reads and dispatches
// `payload_handler` once per complete payload.

#pragma once

#include <functional>

#include <seastar/core/future.hh>
#include <seastar/core/temporary_buffer.hh>
#include <seastar/net/api.hh>
#include <seastar/net/socket_defs.hh>

namespace atsc3::gw {

// Called once per *complete* length-prefixed payload, on the shard that
// owns the connection. Returning an exceptional future closes the
// connection.
using payload_handler =
    std::function<seastar::future<>(seastar::temporary_buffer<char>)>;

class ingress_tcp {
public:
    ingress_tcp(seastar::ipv4_addr addr, payload_handler on_payload);

    // Bind + start accept loop on this shard. Idempotent within a shard.
    seastar::future<> start();

    // Stop accepting + close the listening socket. Does not wait for
    // in-flight connections to drain (M1 best-effort).
    seastar::future<> stop();

private:
    seastar::ipv4_addr _addr;
    payload_handler _on_payload;
    seastar::server_socket _listener;
    bool _running = false;

    seastar::future<> accept_loop();
    seastar::future<> serve(seastar::connected_socket sock,
                            seastar::socket_address peer);
};

}  // namespace atsc3::gw

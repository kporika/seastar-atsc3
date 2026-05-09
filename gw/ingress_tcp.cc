// SPDX-License-Identifier: Apache-2.0

#include "ingress_tcp.h"

#include <utility>

#include <seastar/core/coroutine.hh>
#include <seastar/core/loop.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/seastar.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/when_all.hh>
#include <seastar/util/log.hh>

#include "length_framer.h"

namespace atsc3::gw {

static seastar::logger ilog("ingress_tcp");

ingress_tcp::ingress_tcp(seastar::ipv4_addr addr, payload_handler on_payload)
    : _addr(addr), _on_payload(std::move(on_payload)) {}

seastar::future<> ingress_tcp::start() {
    if (_running) {
        return seastar::make_ready_future<>();
    }

    seastar::listen_options lo;
    lo.reuse_address = true;
    // Kernel hashes incoming connections across all shards binding the
    // same (addr,port) via SO_REUSEPORT. This is the modern Seastar way.
    lo.lba = seastar::server_socket::load_balancing_algorithm::port;
    lo.set_fixed_cpu(seastar::this_shard_id());

    _listener = seastar::listen(seastar::socket_address(_addr), lo);
    _running = true;

    ilog.info("shard {}: listening on {}", seastar::this_shard_id(), _addr);

    // Fire-and-forget the accept loop; stop() interrupts it via abort_accept().
    (void)accept_loop().handle_exception([](std::exception_ptr ep) {
        ilog.warn("accept loop exited: {}", ep);
    });

    return seastar::make_ready_future<>();
}

seastar::future<> ingress_tcp::stop() {
    if (!_running) {
        return seastar::make_ready_future<>();
    }
    _running = false;
    _listener.abort_accept();
    return seastar::make_ready_future<>();
}

seastar::future<> ingress_tcp::accept_loop() {
    return seastar::do_until(
        [this] { return !_running; },
        [this] {
            return _listener.accept().then(
                [this](seastar::accept_result ar) {
                    // Each accepted socket is served in the background; the
                    // accept loop continues immediately.
                    (void)serve(std::move(ar.connection),
                                std::move(ar.remote_address))
                        .handle_exception([](std::exception_ptr ep) {
                            ilog.debug("connection ended: {}", ep);
                        });
                    return seastar::make_ready_future<>();
                });
        });
}

seastar::future<> ingress_tcp::serve(seastar::connected_socket sock,
                                     seastar::socket_address peer) {
    ilog.debug("shard {}: connection from {}",
               seastar::this_shard_id(), peer);

    auto in = sock.input();
    auto sock_holder = seastar::make_lw_shared<seastar::connected_socket>(
        std::move(sock));
    auto framer_holder = seastar::make_lw_shared<length_framer>();

    // Read until EOF; feed each chunk into the framer, then drain any
    // complete length-prefixed payloads to the handler.
    return seastar::do_with(
        std::move(in), sock_holder, framer_holder,
        [this, peer](auto& in, auto& holder, auto& framer) {
            return seastar::repeat([this, &in, &framer, peer] {
                return in.read().then(
                    [this, &framer, peer](
                        seastar::temporary_buffer<char> buf)
                        -> seastar::future<seastar::stop_iteration> {
                        if (buf.empty()) {
                            co_return seastar::stop_iteration::yes;
                        }
                        if (!framer->feed(std::move(buf))) {
                            ilog.warn(
                                "shard {}: closing {} — frame size cap "
                                "exceeded",
                                seastar::this_shard_id(), peer);
                            co_return seastar::stop_iteration::yes;
                        }
                        while (auto frame = framer->try_extract()) {
                            co_await _on_payload(std::move(*frame));
                        }
                        co_return seastar::stop_iteration::no;
                    });
            }).finally([&in, &holder, &framer] {
                return in.close().handle_exception(
                    [](auto) { /* ignore */ });
            });
        });
}

}  // namespace atsc3::gw

// SPDX-License-Identifier: Apache-2.0

#include "atsc3_gw.h"

#include <cstring>
#include <span>
#include <utility>

#include <seastar/core/coroutine.hh>
#include <seastar/util/log.hh>

namespace atsc3::gw {

static seastar::logger glog("gw");

gw_server::gw_server(gw_config cfg) : _cfg(std::move(cfg)) {}

seastar::future<> gw_server::start() {
    glog.info("shard {}: starting (ingress={}, sink={})",
              seastar::this_shard_id(), _cfg.ingress_addr, _cfg.sink_uri);

    _sink = co_await make_sink(_cfg.sink_uri);
    glog.info("shard {}: sink ready: {}",
              seastar::this_shard_id(), _sink->describe());

    _ingress = std::make_unique<ingress_tcp>(
        _cfg.ingress_addr,
        [this](seastar::temporary_buffer<char> buf) {
            return on_payload(std::move(buf));
        });
    co_await _ingress->start();

    co_return;
}

seastar::future<> gw_server::stop() {
    glog.info("shard {}: stopping", seastar::this_shard_id());
    if (_ingress) {
        co_await _ingress->stop();
    }
    if (_sink) {
        co_await _sink->flush();
        co_await _sink->close();
    }
    co_return;
}

seastar::future<gw_server::stats_t> gw_server::get_stats() const {
    return seastar::make_ready_future<stats_t>(_stats);
}

seastar::future<> gw_server::on_payload(seastar::temporary_buffer<char> buf) {
    _stats.bytes_in += buf.size();
    _stats.payloads += 1;

    auto enc = _enc.encode(std::span<const std::byte>(
        reinterpret_cast<const std::byte *>(buf.get()), buf.size()));
    if (!enc.ok) {
        _stats.encode_errors += 1;
        glog.warn("shard {}: encode failed: {}",
                  seastar::this_shard_id(), enc.error);
        co_return;
    }

    // The encoder owns its bytes via std::vector; copy into a
    // temporary_buffer for the sink. A future optimization is to
    // teach the encoder to write into a caller-provided buffer.
    seastar::temporary_buffer<char> out(enc.bytes.size());
    if (!enc.bytes.empty()) {
        std::memcpy(out.get_write(), enc.bytes.data(), enc.bytes.size());
    }
    _stats.bytes_out += out.size();
    co_await _sink->write(std::move(out));
}

}  // namespace atsc3::gw

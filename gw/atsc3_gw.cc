// SPDX-License-Identifier: Apache-2.0

#include "atsc3_gw.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include <seastar/core/coroutine.hh>
#include <seastar/core/semaphore.hh>
#include <seastar/core/thread.hh>
#include <seastar/util/log.hh>

namespace atsc3::gw {

namespace {

std::string trim_copy(std::string_view sv) {
    while (!sv.empty() &&
           std::isspace(static_cast<unsigned char>(sv.front()))) {
        sv.remove_prefix(1);
    }
    while (!sv.empty() &&
           std::isspace(static_cast<unsigned char>(sv.back()))) {
        sv.remove_suffix(1);
    }
    return std::string(sv);
}

}  // namespace

static seastar::logger glog("gw");

gw_server::gw_server(gw_config cfg) : _cfg(std::move(cfg)) {}

std::string gw_server::ingress_listen_string() const {
    return std::string(
        seastar::format("{}", seastar::socket_address(_cfg.ingress_addr)));
}

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

    co_await load_admin_services_from_file_if_set();

    co_return;
}

seastar::future<> gw_server::stop() {
    glog.info("shard {}: stopping", seastar::this_shard_id());
    if (seastar::this_shard_id() == 0) {
        co_await persist_admin_services_if_configured();
    }
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

seastar::future<> gw_server::ingest_payload(seastar::temporary_buffer<char> buf) {
    co_return co_await on_payload(std::move(buf));
}

seastar::future<std::optional<std::string>> gw_server::replace_sink_uri(
    std::string new_uri) {
    auto units = co_await seastar::get_units(_sink_sem, 1);

    std::unique_ptr<sink> new_sink;
    try {
        new_sink = co_await make_sink(new_uri);
    } catch (const std::exception& ex) {
        co_return std::string(ex.what());
    } catch (...) {
        co_return std::string("sink: unknown error from make_sink");
    }

    co_await _sink->flush();
    co_await _sink->close();
    _cfg.sink_uri = std::move(new_uri);
    _sink = std::move(new_sink);
    glog.info("shard {}: sink replaced -> {}",
              seastar::this_shard_id(), _sink->describe());
    co_return std::nullopt;
}

bool gw_server::is_ready() const noexcept {
    return static_cast<bool>(_sink) && static_cast<bool>(_ingress);
}

std::vector<admin_service_entry> gw_server::list_admin_services() const {
    return _admin_services;
}

admin_service_add_result gw_server::add_admin_service(std::string name) {
    name = trim_copy(name);
    if (name.empty()) {
        return {.ok = false, .id = 0, .error = "name required"};
    }
    if (name.size() > 256) {
        return {.ok = false, .id = 0, .error = "name too long (max 256)"};
    }
    for (const auto& e : _admin_services) {
        if (e.name == name) {
            return {.ok = false, .id = 0, .error = "duplicate name"};
        }
    }
    const std::uint32_t id = _next_admin_service_id++;
    _admin_services.push_back({id, std::move(name)});
    return {.ok = true,
            .id = id,
            .error = {},
            .accepted_name = _admin_services.back().name};
}

bool gw_server::admin_service_exists(std::uint32_t id) const {
    for (const auto& e : _admin_services) {
        if (e.id == id) {
            return true;
        }
    }
    return false;
}

bool gw_server::remove_admin_service(std::uint32_t id) {
    auto it = std::find_if(
        _admin_services.begin(), _admin_services.end(),
        [id](const admin_service_entry& e) { return e.id == id; });
    if (it == _admin_services.end()) {
        return false;
    }
    _admin_services.erase(it);
    return true;
}

std::string gw_server::serialize_admin_services_state() const {
    rapidjson::StringBuffer buf;
    rapidjson::Writer<rapidjson::StringBuffer> w(buf);
    w.StartObject();
    w.Key("version");
    w.Uint(1);
    w.Key("next_id");
    w.Uint(_next_admin_service_id);
    w.Key("services");
    w.StartArray();
    for (const auto& e : _admin_services) {
        w.StartObject();
        w.Key("id");
        w.Uint(e.id);
        w.Key("name");
        w.String(e.name.c_str(),
                 static_cast<rapidjson::SizeType>(e.name.size()));
        w.EndObject();
    }
    w.EndArray();
    w.EndObject();
    return std::string(buf.GetString(), buf.GetSize());
}

seastar::future<> gw_server::persist_admin_services_if_configured() {
    if (!_cfg.services_state_file || _cfg.services_state_file->empty()) {
        co_return;
    }
    const std::string path = *_cfg.services_state_file;
    const std::string json = serialize_admin_services_state();
    try {
        co_await seastar::with_semaphore(
            _services_persist_sem, 1, [path, json] {
                return seastar::async([path, json] {
                    const std::string tmp = path + ".tmp";
                    {
                        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
                        if (!out) {
                            throw std::runtime_error(
                                "cannot open services state temp file");
                        }
                        out << json;
                        if (!out.good()) {
                            throw std::runtime_error(
                                "short write services state temp file");
                        }
                    }
                    std::error_code ec;
                    std::filesystem::rename(tmp, path, ec);
                    if (ec) {
                        throw std::system_error(ec);
                    }
                });
            });
    } catch (const std::exception& ex) {
        glog.warn("persist admin services: {}", ex.what());
    }
    co_return;
}

seastar::future<> gw_server::load_admin_services_from_file_if_set() {
    if (seastar::this_shard_id() != 0) {
        co_return;
    }
    if (!_cfg.services_state_file || _cfg.services_state_file->empty()) {
        co_return;
    }
    const std::string path = *_cfg.services_state_file;
    std::string contents;
    try {
        contents = co_await seastar::async([path] {
            std::ifstream in(path, std::ios::binary);
            if (!in) {
                return std::string{};
            }
            return std::string(std::istreambuf_iterator<char>(in),
                               std::istreambuf_iterator<char>());
        });
    } catch (const std::exception& ex) {
        glog.warn("load admin services: {}", ex.what());
        co_return;
    }
    if (contents.empty()) {
        co_return;
    }

    rapidjson::Document doc;
    doc.Parse(contents.data(), contents.size());
    if (doc.HasParseError() || !doc.IsObject()) {
        glog.warn("load admin services: invalid JSON in {}", path);
        co_return;
    }
    if (!doc.HasMember("services") || !doc["services"].IsArray()) {
        glog.warn("load admin services: missing services array in {}", path);
        co_return;
    }

    std::vector<admin_service_entry> loaded;
    std::uint32_t max_id = 0;
    for (const auto& v : doc["services"].GetArray()) {
        if (!v.IsObject() || !v.HasMember("id") || !v.HasMember("name")) {
            continue;
        }
        if (!v["id"].IsUint() || !v["name"].IsString()) {
            continue;
        }
        admin_service_entry e;
        e.id = v["id"].GetUint();
        e.name.assign(v["name"].GetString(), v["name"].GetStringLength());
        if (e.id > max_id) {
            max_id = e.id;
        }
        loaded.push_back(std::move(e));
    }

    std::uint32_t next = max_id + 1;
    if (doc.HasMember("next_id") && doc["next_id"].IsUint()) {
        const std::uint32_t jn = doc["next_id"].GetUint();
        if (jn > next) {
            next = jn;
        }
    }

    _admin_services = std::move(loaded);
    _next_admin_service_id = next;
    glog.info("shard 0: loaded {} admin service(s) from {}", _admin_services.size(),
              path);
    co_return;
}

seastar::future<> gw_server::on_payload(seastar::temporary_buffer<char> buf) {
    auto units = co_await seastar::get_units(_sink_sem, 1);

    _stats.bytes_in += buf.size();
    _stats.payloads += 1;
    // LLS sink expects cleartext XML (or pre-gzipped / pre-framed LLS bytes), not
    // ALP+TLV-mux — see gw/sink.cc and docs/END_TO_END_GAPS.md.
    if (std::string_view(_cfg.sink_uri).starts_with("lls://")) {
        _stats.bytes_out += buf.size();
        co_await _sink->write(std::move(buf));
        co_return;
    }

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

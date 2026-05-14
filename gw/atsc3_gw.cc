// SPDX-License-Identifier: Apache-2.0

#include "atsc3_gw.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <optional>
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
#include <seastar/core/file.hh>
#include <seastar/core/fstream.hh>
#include <seastar/core/seastar.hh>
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

gw_server::gw_server(gw_config cfg)
    : _cfg(std::move(cfg)),
      _enc(_cfg.encoder) {}

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
        co_await flush_close_all_service_sinks();
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

seastar::future<> gw_server::ingest_payload(seastar::temporary_buffer<char> buf,
                                            std::optional<std::uint32_t> service_id) {
    auto units = co_await seastar::get_units(_sink_sem, 1);

    _stats.bytes_in += buf.size();
    _stats.payloads += 1;

    sink* out_sink = _sink.get();
    std::string_view effective_uri{_cfg.sink_uri};
    if (seastar::this_shard_id() == 0 && service_id.has_value()) {
        const admin_service_entry* ent = find_admin_service(*service_id);
        // Caller validated existence; defensive fallback to default sink.
        if (ent && ent->sink_uri && !ent->sink_uri->empty()) {
            auto it = _service_sinks.find(*service_id);
            if (it != _service_sinks.end() && it->second) {
                out_sink = it->second.get();
                effective_uri = std::string_view(*ent->sink_uri);
            }
        }
    }

    co_return co_await write_through_encoder(std::move(buf), *out_sink, effective_uri);
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

const admin_service_entry* gw_server::find_admin_service(std::uint32_t id) const noexcept {
    for (const auto& e : _admin_services) {
        if (e.id == id) {
            return &e;
        }
    }
    return nullptr;
}

seastar::future<admin_service_add_result> gw_server::add_admin_service(
    std::string name, std::optional<std::string> sink_uri) {
    if (seastar::this_shard_id() != 0) {
        co_return admin_service_add_result{.ok = false, .error = "services registry on shard 0 only"};
    }
    name = trim_copy(name);
    if (name.empty()) {
        co_return admin_service_add_result{.ok = false, .id = 0, .error = "name required"};
    }
    if (name.size() > 256) {
        co_return admin_service_add_result{.ok = false, .id = 0, .error = "name too long (max 256)"};
    }
    std::optional<std::string> uri_opt{};
    if (sink_uri.has_value()) {
        std::string u = trim_copy(*sink_uri);
        if (!u.empty()) {
            uri_opt = std::move(u);
        }
    }
    for (const auto& e : _admin_services) {
        if (e.name == name) {
            co_return admin_service_add_result{.ok = false,
                                                .id = 0,
                                                .error = "duplicate name"};
        }
    }

    std::unique_ptr<sink> new_sk{};
    if (uri_opt.has_value()) {
        try {
            new_sk = co_await make_sink(*uri_opt);
        } catch (const std::exception& ex) {
            co_return admin_service_add_result{.ok = false,
                                                .id = 0,
                                                .error = ex.what()};
        } catch (...) {
            co_return admin_service_add_result{
                .ok = false,
                .id = 0,
                .error = "sink: unknown error from make_sink"};
        }
    }

    const std::uint32_t id = _next_admin_service_id++;
    admin_service_entry e{.id = id, .name = std::move(name), .sink_uri = uri_opt};
    const std::string accepted = e.name;
    _admin_services.push_back(std::move(e));

    if (new_sk) {
        _service_sinks.emplace(id, std::move(new_sk));
    }

    co_return admin_service_add_result{.ok = true,
                                        .id = id,
                                        .error = {},
                                        .accepted_name = accepted,
                                        .accepted_sink_uri = uri_opt};
}

bool gw_server::admin_service_exists(std::uint32_t id) const {
    return find_admin_service(id) != nullptr;
}

seastar::future<std::optional<std::string>> gw_server::patch_admin_service_sink(
    std::uint32_t id, bool clear_sink, std::optional<std::string> uri_if_set) {
    if (seastar::this_shard_id() != 0) {
        co_return std::string("shard");
    }
    admin_service_entry* ent = nullptr;
    for (auto& e : _admin_services) {
        if (e.id == id) {
            ent = &e;
            break;
        }
    }
    if (!ent) {
        co_return std::string("unknown service id");
    }

    auto sk_it = _service_sinks.find(id);
    if (sk_it != _service_sinks.end()) {
        co_await sk_it->second->flush();
        co_await sk_it->second->close();
        _service_sinks.erase(sk_it);
    }

    if (clear_sink) {
        ent->sink_uri.reset();
        co_return std::nullopt;
    }

    if (!uri_if_set) {
        co_return std::string("sink_uri must be a non-empty string or null");
    }

    std::string u = trim_copy(*uri_if_set);
    if (u.empty()) {
        ent->sink_uri.reset();
        co_return std::nullopt;
    }

    ent->sink_uri = u;

    std::unique_ptr<sink> sk;
    try {
        sk = co_await make_sink(*ent->sink_uri);
    } catch (const std::exception& ex) {
        ent->sink_uri.reset();
        co_return std::string(ex.what());
    } catch (...) {
        ent->sink_uri.reset();
        co_return std::string("sink: unknown error from make_sink");
    }
    _service_sinks.emplace(id, std::move(sk));

    co_return std::nullopt;
}

seastar::future<bool> gw_server::remove_admin_service(std::uint32_t id) {
    auto it = std::find_if(
        _admin_services.begin(), _admin_services.end(),
        [id](const admin_service_entry& e) { return e.id == id; });
    if (it == _admin_services.end()) {
        co_return false;
    }
    auto sk_it = _service_sinks.find(id);
    if (sk_it != _service_sinks.end()) {
        co_await sk_it->second->flush();
        co_await sk_it->second->close();
        _service_sinks.erase(sk_it);
    }
    _admin_services.erase(it);
    co_return true;
}

seastar::future<> gw_server::flush_close_all_service_sinks() {
    for (auto& kv : _service_sinks) {
        if (!kv.second) {
            continue;
        }
        co_await kv.second->flush();
        co_await kv.second->close();
    }
    _service_sinks.clear();
    co_return;
}

std::string gw_server::serialize_admin_services_state() const {
    rapidjson::StringBuffer buf;
    rapidjson::Writer<rapidjson::StringBuffer> w(buf);
    w.StartObject();
    w.Key("schema_version");
    w.Uint(2);
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
        if (e.sink_uri && !e.sink_uri->empty()) {
            w.Key("sink_uri");
            w.String(e.sink_uri->c_str(),
                     static_cast<rapidjson::SizeType>(e.sink_uri->size()));
        }
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
    const std::string tmp = path + ".tmp";

    // Same rationale as load: avoid `seastar::async` + libstdc++ file I/O (different
    // allocator domain than the Seastar reactor).
    auto units = co_await seastar::get_units(_services_persist_sem, 1);
    (void)units;

    try {
        seastar::open_flags flags = seastar::open_flags::wo | seastar::open_flags::create |
                                    seastar::open_flags::truncate;
        seastar::file f =
            co_await seastar::open_file_dma(seastar::sstring(tmp), flags);
        auto out = co_await seastar::make_file_output_stream(std::move(f), 4096);
        co_await out.write(json);
        co_await out.flush();
        co_await out.close();
        co_await seastar::rename_file(tmp, path);
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

    // Read on the Seastar reactor with `file` + `dma_read`. A prior version used
    // `seastar::async` + `std::ifstream`, which runs on the thread pool and mixed
    // libstdc++ allocations with the reactor allocator — that corrupted Seastar
    // heap and crashed later (e.g. when bringing up HTTP admin).
    constexpr std::uint64_t k_max_services_json_bytes = 4u * 1024u * 1024u;
    seastar::file f{};
    try {
        f = co_await seastar::open_file_dma(seastar::sstring(path),
                                            seastar::open_flags::ro);
    } catch (const std::system_error& ex) {
        if (ex.code().value() == ENOENT) {
            co_return;
        }
        glog.warn("load admin services: {}", ex.what());
        co_return;
    } catch (const std::exception& ex) {
        glog.warn("load admin services: {}", ex.what());
        co_return;
    }

    std::uint64_t sz = 0;
    bool size_ok = true;
    try {
        sz = co_await f.size();
    } catch (const std::exception& ex) {
        glog.warn("load admin services: {}", ex.what());
        size_ok = false;
    }
    if (!size_ok) {
        co_await f.close();
        co_return;
    }

    if (sz == 0) {
        co_await f.close();
        co_return;
    }
    if (sz > k_max_services_json_bytes) {
        co_await f.close();
        glog.warn("load admin services: {} too large ({} bytes, max {})", path,
                  sz, k_max_services_json_bytes);
        co_return;
    }

    seastar::temporary_buffer<char> raw;
    bool read_ok = true;
    try {
        raw =
            co_await f.dma_read<char>(0, static_cast<std::size_t>(sz));
    } catch (const std::exception& ex) {
        glog.warn("load admin services: read {}: {}", path, ex.what());
        read_ok = false;
    }
    co_await f.close();
    if (!read_ok) {
        co_return;
    }

    std::string contents(raw.get(), raw.size());
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
        if (v.HasMember("sink_uri") && v["sink_uri"].IsString()) {
            std::string u(
                trim_copy(std::string_view(v["sink_uri"].GetString(),
                                           v["sink_uri"].GetStringLength())));
            if (!u.empty()) {
                e.sink_uri = std::move(u);
            }
        }
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

    co_await flush_close_all_service_sinks();
    for (const auto& e : _admin_services) {
        if (!e.sink_uri || e.sink_uri->empty()) {
            continue;
        }
        try {
            auto sk = co_await make_sink(*e.sink_uri);
            _service_sinks.emplace(e.id, std::move(sk));
        } catch (const std::exception& ex) {
            glog.warn("load admin services: service id {} sink_uri invalid ({}): "
                      "routing falls back to default",
                      e.id, ex.what());
            for (auto& mut : _admin_services) {
                if (mut.id == e.id) {
                    mut.sink_uri.reset();
                    break;
                }
            }
        } catch (...) {
            glog.warn("load admin services: service id {} sink_uri unknown error; "
                      "routing falls back to default",
                      e.id);
            for (auto& mut : _admin_services) {
                if (mut.id == e.id) {
                    mut.sink_uri.reset();
                    break;
                }
            }
        }
    }

    glog.info("shard 0: loaded {} admin service(s) from {}", _admin_services.size(),
              path);
    co_return;
}

seastar::future<> gw_server::write_through_encoder(
    seastar::temporary_buffer<char> buf, sink& out, std::string_view effective_sink_uri) {
    if (effective_sink_uri.starts_with("lls://")) {
        _stats.bytes_out += buf.size();
        co_await out.write(std::move(buf));
        co_return;
    }

    auto enc = _enc.encode(std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(buf.get()), buf.size()));
    if (!enc.ok) {
        _stats.encode_errors += 1;
        glog.warn("shard {}: encode failed: {}",
                  seastar::this_shard_id(), enc.error);
        co_return;
    }

    seastar::temporary_buffer<char> outbuf(enc.bytes.size());
    if (!enc.bytes.empty()) {
        std::memcpy(outbuf.get_write(), enc.bytes.data(), enc.bytes.size());
    }
    _stats.bytes_out += outbuf.size();
    co_await out.write(std::move(outbuf));
}

seastar::future<> gw_server::on_payload(seastar::temporary_buffer<char> buf) {
    auto units = co_await seastar::get_units(_sink_sem, 1);

    _stats.bytes_in += buf.size();
    _stats.payloads += 1;
    std::string_view effective_uri{_cfg.sink_uri};
    co_return co_await write_through_encoder(std::move(buf), *_sink, effective_uri);
}

}  // namespace atsc3::gw

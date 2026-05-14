// SPDX-License-Identifier: Apache-2.0

#include "admin_http.h"

#include "atsc3_gw.h"

#include <cctype>
#include <cstdint>
#include <cstring>
#include <charconv>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include <seastar/core/coroutine.hh>
#include <seastar/core/smp.hh>
#include <seastar/core/sstring.hh>
#include <seastar/http/common.hh>
#include <seastar/http/handlers.hh>
#include <seastar/http/httpd.hh>
#include <seastar/http/reply.hh>
#include <seastar/http/request.hh>
#include <seastar/http/routes.hh>
#include <seastar/util/log.hh>

namespace atsc3::gw {

namespace {

seastar::logger alog("admin_http");

class index_handler final : public seastar::httpd::handler_base {
public:
    seastar::future<std::unique_ptr<seastar::http::reply>> handle(
        const seastar::sstring& /*path*/,
        std::unique_ptr<seastar::http::request> /*req*/,
        std::unique_ptr<seastar::http::reply> rep) override {
        rep->set_status(seastar::http::reply::status_type::ok);
        rep->write_body(
            "json",
            seastar::sstring(
                R"({"service":"atsc3_gw","endpoints":["GET /","GET /healthz","GET /readyz","GET /metrics","GET /config","PATCH /config","PUT /config","POST /config/sink","GET /services","POST /ingest","POST /services","DELETE /services?id=<uint>"]})"));
        return seastar::make_ready_future<std::unique_ptr<seastar::http::reply>>(
            std::move(rep));
    }
};

std::optional<std::vector<char>> base64_decode(std::string_view in) {
    static constexpr signed char kDec[256] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
        -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    };

    std::vector<char> out;
    out.reserve((in.size() * 3) / 4);
    int val = 0;
    int valb = -8;
    for (unsigned char c : in) {
        if (std::isspace(c)) {
            continue;
        }
        if (c == '=') {
            break;
        }
        int d = static_cast<unsigned>(kDec[c]);
        if (d < 0) {
            return std::nullopt;
        }
        val = (val << 6) + d;
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

std::optional<std::uint32_t> parse_decimal_u32_strict(std::string_view sv) {
    if (sv.empty()) {
        return std::nullopt;
    }
    std::uint32_t v = 0;
    const char* const begin = sv.data();
    const char* const end = begin + sv.size();
    const auto r = std::from_chars(begin, end, v);
    if (r.ec != std::errc{} || r.ptr != end) {
        return std::nullopt;
    }
    return v;
}

std::string trim_http_json_string(std::string_view sv) {
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

seastar::sstring json_quote_err(seastar::sstring msg) {
    rapidjson::StringBuffer buf;
    rapidjson::Writer<rapidjson::StringBuffer> w(buf);
    w.StartObject();
    w.Key("error");
    w.String(msg.c_str(), static_cast<rapidjson::SizeType>(msg.size()));
    w.EndObject();
    return seastar::sstring(buf.GetString(), buf.GetSize());
}

seastar::future<seastar::sstring> read_http_body(
    std::unique_ptr<seastar::http::request>& req) {
    // If a content_stream exists but yields nothing before EOF, the body may
    // still be in req.content — drain the stream first, then fall back.
    if (req->content_stream) {
        seastar::sstring out;
        while (true) {
            auto chunk = co_await req->content_stream->read();
            if (chunk.empty()) {
                break;
            }
            out.append(chunk.get(), chunk.size());
        }
        if (!out.empty()) {
            co_return out;
        }
    }
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    co_return std::move(req->content);
#pragma GCC diagnostic pop
}

class health_handler final : public seastar::httpd::handler_base {
public:
    seastar::future<std::unique_ptr<seastar::http::reply>> handle(
        const seastar::sstring& /*path*/,
        std::unique_ptr<seastar::http::request> /*req*/,
        std::unique_ptr<seastar::http::reply> rep) override {
        rep->set_status(seastar::http::reply::status_type::ok);
        rep->write_body("txt", seastar::sstring("ok\n"));
        return seastar::make_ready_future<std::unique_ptr<seastar::http::reply>>(
            std::move(rep));
    }
};

class ready_handler final : public seastar::httpd::handler_base {
public:
    explicit ready_handler(seastar::sharded<gw_server>* gw) : _gw(gw) {}

    seastar::future<std::unique_ptr<seastar::http::reply>> handle(
        const seastar::sstring& /*path*/,
        std::unique_ptr<seastar::http::request> /*req*/,
        std::unique_ptr<seastar::http::reply> rep) override {
        bool all_ready = true;
        for (unsigned i = 0; i < seastar::smp::count; ++i) {
            bool shard_ok =
                co_await _gw->invoke_on(i, [](gw_server& s) { return s.is_ready(); });
            if (!shard_ok) {
                all_ready = false;
            }
        }
        if (all_ready) {
            rep->set_status(seastar::http::reply::status_type::ok);
            rep->write_body("txt", seastar::sstring("ready\n"));
        } else {
            rep->set_status(seastar::http::reply::status_type::service_unavailable);
            rep->write_body("txt", seastar::sstring("not_ready\n"));
        }
        co_return std::move(rep);
    }

private:
    seastar::sharded<gw_server>* _gw;
};

class metrics_handler final : public seastar::httpd::handler_base {
public:
    explicit metrics_handler(seastar::sharded<gw_server>* gw) : _gw(gw) {}

    seastar::future<std::unique_ptr<seastar::http::reply>> handle(
        const seastar::sstring& /*path*/,
        std::unique_ptr<seastar::http::request> /*req*/,
        std::unique_ptr<seastar::http::reply> rep) override {
        gw_server::stats_t total{};
        for (unsigned i = 0; i < seastar::smp::count; ++i) {
            gw_server::stats_t st = co_await _gw->invoke_on(
                i, [](gw_server& s) -> seastar::future<gw_server::stats_t> {
                    co_return co_await s.get_stats();
                });
            total.bytes_in += st.bytes_in;
            total.bytes_out += st.bytes_out;
            total.payloads += st.payloads;
            total.encode_errors += st.encode_errors;
            total.connections += st.connections;
        }

        auto text = seastar::format(
            "# HELP atsc3_gw_bytes_in Payload bytes accepted on each shard (TCP + HTTP).\n"
            "# TYPE atsc3_gw_bytes_in counter\n"
            "atsc3_gw_bytes_in {}\n"
            "# HELP atsc3_gw_bytes_out Bytes written to the sink (TLV-mux or raw LLS bypass).\n"
            "# TYPE atsc3_gw_bytes_out counter\n"
            "atsc3_gw_bytes_out {}\n"
            "# HELP atsc3_gw_payloads_total Complete payloads encoded.\n"
            "# TYPE atsc3_gw_payloads_total counter\n"
            "atsc3_gw_payloads_total {}\n"
            "# HELP atsc3_gw_encode_errors_total Encoder rejects.\n"
            "# TYPE atsc3_gw_encode_errors_total counter\n"
            "atsc3_gw_encode_errors_total {}\n",
            total.bytes_in, total.bytes_out, total.payloads, total.encode_errors);

        rep->set_status(seastar::http::reply::status_type::ok);
        rep->write_body("txt", text);
        co_return std::move(rep);
    }

private:
    seastar::sharded<gw_server>* _gw;
};

class config_handler final : public seastar::httpd::handler_base {
public:
    explicit config_handler(seastar::sharded<gw_server>* gw) : _gw(gw) {}

    seastar::future<std::unique_ptr<seastar::http::reply>> handle(
        const seastar::sstring& /*path*/,
        std::unique_ptr<seastar::http::request> /*req*/,
        std::unique_ptr<seastar::http::reply> rep) override {
        const auto snap = co_await _gw->invoke_on(0, [](const gw_server& s) {
            return seastar::make_ready_future<
                std::tuple<std::string, std::string, std::optional<std::string>>>(
                std::tuple<std::string, std::string, std::optional<std::string>>{
                    s.ingress_listen_string(), std::string(s.sink_uri()),
                    s.services_state_file_path()});
        });

        rapidjson::StringBuffer buf;
        rapidjson::Writer<rapidjson::StringBuffer> w(buf);
        w.StartObject();
        w.Key("ingress");
        w.String(std::get<0>(snap).c_str(),
                 static_cast<rapidjson::SizeType>(std::get<0>(snap).size()));
        w.Key("sink_uri");
        w.String(std::get<1>(snap).c_str(),
                 static_cast<rapidjson::SizeType>(std::get<1>(snap).size()));
        w.Key("services_state_file");
        if (const auto& sf = std::get<2>(snap)) {
            w.String(sf->c_str(), static_cast<rapidjson::SizeType>(sf->size()));
        } else {
            w.Null();
        }
        w.EndObject();

        rep->set_status(seastar::http::reply::status_type::ok);
        rep->write_body("json",
                        seastar::sstring(buf.GetString(), buf.GetSize()));
        co_return std::move(rep);
    }

private:
    seastar::sharded<gw_server>* _gw;
};

class patch_config_handler final : public seastar::httpd::handler_base {
public:
    explicit patch_config_handler(seastar::sharded<gw_server>* gw) : _gw(gw) {}

    seastar::future<std::unique_ptr<seastar::http::reply>> handle(
        const seastar::sstring& /*path*/,
        std::unique_ptr<seastar::http::request> req,
        std::unique_ptr<seastar::http::reply> rep) override {
        auto body = co_await read_http_body(req);
        if (body.empty()) {
            rep->set_status(seastar::http::reply::status_type::bad_request);
            rep->write_body("json", json_quote_err("empty body"));
            co_return std::move(rep);
        }

        rapidjson::Document doc;
        doc.Parse(body.begin(), body.size());
        if (doc.HasParseError() || !doc.IsObject()) {
            rep->set_status(seastar::http::reply::status_type::bad_request);
            rep->write_body("json", json_quote_err("invalid JSON"));
            co_return std::move(rep);
        }

        for (auto it = doc.MemberBegin(); it != doc.MemberEnd(); ++it) {
            const std::string_view kn(it->name.GetString(), it->name.GetStringLength());
            if (kn == "sink_uri") {
                continue;
            }
            rep->set_status(seastar::http::reply::status_type::bad_request);
            rep->write_body("json",
                            json_quote_err(
                                "only sink_uri may be set (use POST /config/sink, "
                                "PATCH /config, or PUT /config)"));
            co_return std::move(rep);
        }

        if (!doc.HasMember("sink_uri") || !doc["sink_uri"].IsString()) {
            rep->set_status(seastar::http::reply::status_type::bad_request);
            rep->write_body("json", json_quote_err("missing sink_uri string"));
            co_return std::move(rep);
        }

        std::string new_uri = trim_http_json_string(std::string_view(
            doc["sink_uri"].GetString(), doc["sink_uri"].GetStringLength()));
        if (new_uri.empty()) {
            rep->set_status(seastar::http::reply::status_type::bad_request);
            rep->write_body("json", json_quote_err("sink_uri is empty"));
            co_return std::move(rep);
        }

        const std::string old_uri = co_await _gw->invoke_on(0, [](const gw_server& s) {
            return seastar::make_ready_future<std::string>(std::string(s.sink_uri()));
        });

        unsigned fail_index = seastar::smp::count;
        seastar::sstring fail_err;
        for (unsigned i = 0; i < seastar::smp::count; ++i) {
            const auto err = co_await _gw->invoke_on(
                i, [uri = new_uri](gw_server& s) {
                    return s.replace_sink_uri(uri);
                });
            if (err) {
                fail_index = i;
                fail_err = seastar::sstring(err->c_str(), err->size());
                break;
            }
        }

        if (fail_index < seastar::smp::count) {
            for (unsigned j = 0; j < fail_index; ++j) {
                const auto rb = co_await _gw->invoke_on(
                    j, [&old_uri](gw_server& s) {
                        return s.replace_sink_uri(old_uri);
                    });
                if (rb) {
                    alog.warn("PATCH /config rollback shard {}: {}", j, *rb);
                }
            }
            rep->set_status(seastar::http::reply::status_type::bad_request);
            rep->write_body("json", json_quote_err(std::move(fail_err)));
            co_return std::move(rep);
        }

        const auto snap = co_await _gw->invoke_on(0, [](const gw_server& s) {
            return seastar::make_ready_future<
                std::tuple<std::string, std::string, std::optional<std::string>>>(
                std::tuple<std::string, std::string, std::optional<std::string>>{
                    s.ingress_listen_string(), std::string(s.sink_uri()),
                    s.services_state_file_path()});
        });

        rapidjson::StringBuffer buf;
        rapidjson::Writer<rapidjson::StringBuffer> w(buf);
        w.StartObject();
        w.Key("ingress");
        w.String(std::get<0>(snap).c_str(),
                 static_cast<rapidjson::SizeType>(std::get<0>(snap).size()));
        w.Key("sink_uri");
        w.String(std::get<1>(snap).c_str(),
                 static_cast<rapidjson::SizeType>(std::get<1>(snap).size()));
        w.Key("services_state_file");
        if (const auto& sf = std::get<2>(snap)) {
            w.String(sf->c_str(), static_cast<rapidjson::SizeType>(sf->size()));
        } else {
            w.Null();
        }
        w.EndObject();

        rep->set_status(seastar::http::reply::status_type::ok);
        rep->write_body("json",
                        seastar::sstring(buf.GetString(), buf.GetSize()));
        co_return std::move(rep);
    }

private:
    seastar::sharded<gw_server>* _gw;
};

class services_get_handler final : public seastar::httpd::handler_base {
public:
    explicit services_get_handler(seastar::sharded<gw_server>* gw) : _gw(gw) {}

    seastar::future<std::unique_ptr<seastar::http::reply>> handle(
        const seastar::sstring& /*path*/,
        std::unique_ptr<seastar::http::request> /*req*/,
        std::unique_ptr<seastar::http::reply> rep) override {
        auto rows = co_await _gw->invoke_on(0, [](const gw_server& s) {
            return seastar::make_ready_future<std::vector<admin_service_entry>>(
                s.list_admin_services());
        });

        rapidjson::StringBuffer buf;
        rapidjson::Writer<rapidjson::StringBuffer> w(buf);
        w.StartObject();
        w.Key("services");
        w.StartArray();
        for (const auto& e : rows) {
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

        rep->set_status(seastar::http::reply::status_type::ok);
        rep->write_body("json",
                        seastar::sstring(buf.GetString(), buf.GetSize()));
        co_return std::move(rep);
    }

private:
    seastar::sharded<gw_server>* _gw;
};

class services_post_handler final : public seastar::httpd::handler_base {
public:
    explicit services_post_handler(seastar::sharded<gw_server>* gw) : _gw(gw) {}

    seastar::future<std::unique_ptr<seastar::http::reply>> handle(
        const seastar::sstring& /*path*/,
        std::unique_ptr<seastar::http::request> req,
        std::unique_ptr<seastar::http::reply> rep) override {
        auto body = co_await read_http_body(req);
        if (body.empty()) {
            rep->set_status(seastar::http::reply::status_type::bad_request);
            rep->write_body("json", json_quote_err("empty body"));
            co_return std::move(rep);
        }

        rapidjson::Document doc;
        doc.Parse(body.begin(), body.size());
        if (doc.HasParseError() || !doc.IsObject()) {
            rep->set_status(seastar::http::reply::status_type::bad_request);
            rep->write_body("json", json_quote_err("invalid JSON"));
            co_return std::move(rep);
        }

        if (!doc.HasMember("name") || !doc["name"].IsString()) {
            rep->set_status(seastar::http::reply::status_type::bad_request);
            rep->write_body("json", json_quote_err("missing name"));
            co_return std::move(rep);
        }

        std::string name(doc["name"].GetString(), doc["name"].GetStringLength());

        auto r = co_await _gw->invoke_on(0, [name = std::move(name)](
                                                 gw_server& s) mutable
                                             -> seastar::future<admin_service_add_result> {
            auto r = s.add_admin_service(std::move(name));
            if (r.ok) {
                co_await s.persist_admin_services_if_configured();
            }
            co_return r;
        });

        if (!r.ok) {
            const bool conflict = (r.error == "duplicate name");
            rep->set_status(conflict ? seastar::http::reply::status_type::conflict
                                     : seastar::http::reply::status_type::bad_request);
            rep->write_body("json", json_quote_err(seastar::sstring(r.error)));
            co_return std::move(rep);
        }

        rapidjson::StringBuffer out;
        rapidjson::Writer<rapidjson::StringBuffer> w(out);
        w.StartObject();
        w.Key("id");
        w.Uint(r.id);
        w.Key("name");
        w.String(r.accepted_name.c_str(),
                 static_cast<rapidjson::SizeType>(r.accepted_name.size()));
        w.EndObject();

        rep->set_status(seastar::http::reply::status_type::created);
        rep->write_body("json", seastar::sstring(out.GetString(), out.GetSize()));
        co_return std::move(rep);
    }

private:
    seastar::sharded<gw_server>* _gw;
};

class services_delete_handler final : public seastar::httpd::handler_base {
public:
    explicit services_delete_handler(seastar::sharded<gw_server>* gw) : _gw(gw) {}

    seastar::future<std::unique_ptr<seastar::http::reply>> handle(
        const seastar::sstring& /*path*/,
        std::unique_ptr<seastar::http::request> req,
        std::unique_ptr<seastar::http::reply> rep) override {
        const seastar::sstring id_s = req->get_query_param("id");
        if (id_s.empty()) {
            rep->set_status(seastar::http::reply::status_type::bad_request);
            rep->write_body("json", json_quote_err("missing id query parameter"));
            co_return std::move(rep);
        }
        const std::string_view id_sv(id_s.begin(), id_s.end());
        const auto parsed = parse_decimal_u32_strict(id_sv);
        if (!parsed) {
            rep->set_status(seastar::http::reply::status_type::bad_request);
            rep->write_body(
                "json",
                json_quote_err("id must be a decimal uint32 (no extra characters)"));
            co_return std::move(rep);
        }

        const bool removed = co_await _gw->invoke_on(0, [id = *parsed](
                                                         gw_server& s)
                                                     -> seastar::future<bool> {
            const bool ok = s.remove_admin_service(id);
            if (ok) {
                co_await s.persist_admin_services_if_configured();
            }
            co_return ok;
        });
        if (!removed) {
            rep->set_status(seastar::http::reply::status_type::not_found);
            rep->write_body("json", json_quote_err("unknown service id"));
            co_return std::move(rep);
        }

        rapidjson::StringBuffer out;
        rapidjson::Writer<rapidjson::StringBuffer> w(out);
        w.StartObject();
        w.Key("ok");
        w.Bool(true);
        w.Key("id");
        w.Uint(*parsed);
        w.EndObject();

        rep->set_status(seastar::http::reply::status_type::ok);
        rep->write_body("json", seastar::sstring(out.GetString(), out.GetSize()));
        co_return std::move(rep);
    }

private:
    seastar::sharded<gw_server>* _gw;
};

class ingest_handler final : public seastar::httpd::handler_base {
public:
    explicit ingest_handler(seastar::sharded<gw_server>* gw) : _gw(gw) {}

    seastar::future<std::unique_ptr<seastar::http::reply>> handle(
        const seastar::sstring& /*path*/,
        std::unique_ptr<seastar::http::request> req,
        std::unique_ptr<seastar::http::reply> rep) override {
        auto body = co_await read_http_body(req);
        if (body.empty()) {
            rep->set_status(seastar::http::reply::status_type::bad_request);
            rep->write_body("json", json_quote_err("empty body"));
            co_return std::move(rep);
        }

        rapidjson::Document doc;
        doc.Parse(body.begin(), body.size());
        if (doc.HasParseError() || !doc.IsObject()) {
            rep->set_status(seastar::http::reply::status_type::bad_request);
            rep->write_body("json", json_quote_err("invalid JSON"));
            co_return std::move(rep);
        }

        if (!doc.HasMember("payload_b64") || !doc["payload_b64"].IsString()) {
            rep->set_status(seastar::http::reply::status_type::bad_request);
            rep->write_body("json", json_quote_err("missing payload_b64"));
            co_return std::move(rep);
        }

        if (doc.HasMember("service_id")) {
            const auto& sidv = doc["service_id"];
            if (sidv.IsNull()) {
                rep->set_status(seastar::http::reply::status_type::bad_request);
                rep->write_body("json", json_quote_err("service_id must not be null"));
                co_return std::move(rep);
            }
            std::uint32_t sid = 0;
            bool sid_ok = false;
            if (sidv.IsUint()) {
                sid = sidv.GetUint();
                sid_ok = true;
            } else if (sidv.IsInt() && sidv.GetInt() >= 0) {
                sid = static_cast<std::uint32_t>(sidv.GetInt());
                sid_ok = true;
            }
            if (!sid_ok) {
                rep->set_status(seastar::http::reply::status_type::bad_request);
                rep->write_body(
                    "json",
                    json_quote_err("service_id must be a non-negative integer"));
                co_return std::move(rep);
            }
            const bool known = co_await _gw->invoke_on(0, [sid](const gw_server& s) {
                return seastar::make_ready_future<bool>(s.admin_service_exists(sid));
            });
            if (!known) {
                rep->set_status(seastar::http::reply::status_type::bad_request);
                rep->write_body("json", json_quote_err("unknown service_id"));
                co_return std::move(rep);
            }
        }

        std::string_view type = "raw";
        if (doc.HasMember("type") && doc["type"].IsString()) {
            type = std::string_view(doc["type"].GetString(), doc["type"].GetStringLength());
        }

        seastar::sstring b64(doc["payload_b64"].GetString(),
                             doc["payload_b64"].GetStringLength());
        auto decoded = base64_decode(std::string_view(b64.begin(), b64.size()));
        if (!decoded) {
            rep->set_status(seastar::http::reply::status_type::bad_request);
            rep->write_body("json", json_quote_err("invalid base64 in payload_b64"));
            co_return std::move(rep);
        }

        // Reserved for routing (LLS multicast, RTCM validation, …); same ALP path today.
        if (!type.empty() && type != "raw" && type != "rtcm" && type != "lls") {
            rep->set_status(seastar::http::reply::status_type::bad_request);
            rep->write_body(
                "json", json_quote_err("type must be raw, rtcm, or lls"));
            co_return std::move(rep);
        }

        seastar::temporary_buffer<char> tb(static_cast<size_t>(decoded->size()));
        if (!decoded->empty()) {
            std::memcpy(tb.get_write(), decoded->data(), decoded->size());
        }

        co_await _gw->invoke_on(0, [buf = std::move(tb)](gw_server& s) mutable {
            return s.ingest_payload(std::move(buf));
        });

        rep->set_status(seastar::http::reply::status_type::accepted);
        rep->write_body("json", seastar::sstring(R"({"ok":true})"));
        co_return std::move(rep);
    }

private:
    seastar::sharded<gw_server>* _gw;
};

}  // namespace

seastar::future<> admin_http_listen(seastar::httpd::http_server_control& ctl,
                                    seastar::sharded<gw_server>& gw,
                                    seastar::socket_address addr) {
    co_await ctl.set_routes([&gw](seastar::httpd::routes& r) {
        r.put(seastar::httpd::operation_type::GET,
              seastar::sstring("/"), new index_handler());
        r.put(seastar::httpd::operation_type::GET,
              seastar::sstring("/healthz"), new health_handler());
        r.put(seastar::httpd::operation_type::GET,
              seastar::sstring("/readyz"), new ready_handler(&gw));
        r.put(seastar::httpd::operation_type::GET,
              seastar::sstring("/metrics"), new metrics_handler(&gw));
        // Match-rule registration: some deployments saw 404 on /config with put()
        // alone; add() is the documented alternate for path handlers.
        r.add(seastar::httpd::operation_type::GET,
              seastar::httpd::url("/config"),
              new config_handler(&gw));
        r.add(seastar::httpd::operation_type::PATCH,
              seastar::httpd::url("/config"),
              new patch_config_handler(&gw));
        r.add(seastar::httpd::operation_type::PUT,
              seastar::httpd::url("/config"),
              new patch_config_handler(&gw));
        r.add(seastar::httpd::operation_type::POST,
              seastar::httpd::url("/config/sink"),
              new patch_config_handler(&gw));
        r.put(seastar::httpd::operation_type::GET,
              seastar::sstring("/services"), new services_get_handler(&gw));
        r.put(seastar::httpd::operation_type::POST,
              seastar::sstring("/services"), new services_post_handler(&gw));
        r.put(seastar::httpd::operation_type::DELETE,
              seastar::sstring("/services"), new services_delete_handler(&gw));
        r.put(seastar::httpd::operation_type::POST,
              seastar::sstring("/ingest"), new ingest_handler(&gw));
    });

    co_await ctl.listen(addr);
    alog.info(
        "admin HTTP on {} (GET / /healthz /readyz /metrics /config PATCH+PUT /config POST /config/sink /services, "
        "POST /ingest /services, DELETE /services?id=)",
        addr);
}

}  // namespace atsc3::gw

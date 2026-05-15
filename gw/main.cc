// SPDX-License-Identifier: Apache-2.0
//
// atsc3_gw entry point. Parses CLI, builds a sharded<gw_server>, and runs
// until SIGINT/SIGTERM.

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <optional>
#include <string>

#include <limits>
#include <cstdint>

#include <boost/program_options.hpp>

#include <seastar/core/app-template.hh>
#include <seastar/core/distributed.hh>
#include <seastar/core/future.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/signal.hh>
#include <seastar/core/sleep.hh>
#include <seastar/http/httpd.hh>
#include <seastar/net/tls.hh>
#include <seastar/net/socket_defs.hh>
#include <seastar/util/later.hh>
#include <seastar/util/log.hh>

#include "admin_http.h"
#include "atsc3_gw.h"
#include "encoder_pipeline.h"

namespace bpo = boost::program_options;

static seastar::logger mlog("main");

int main(int argc, char** argv) {
    seastar::app_template app;
    app.add_options()
        ("ingress",
         bpo::value<std::string>()->default_value("0.0.0.0:9000"),
         "ingress TCP bind address (host:port)")
        ("sink",
         bpo::value<std::string>()->default_value("stdout://"),
         "output sink URI (file:///…, stdout://, null://, udp://host:port, "
         "stltp://host:port, lls://[host:port][?table=&group=&gcm1=], "
         "ipv4udp-file:///path?src=&dst=&srcport=&dstport=[&ttl=])")
        ("admin-http",
         bpo::value<std::string>()->default_value(""),
         "optional HTTP/HTTPS admin bind host:port: / /healthz /readyz /metrics /config, "
         "PATCH+PUT /config POST /config/sink, GET+POST+PATCH+DELETE /services, POST /ingest "
         "(empty disables)")
        ("services-state-file",
         bpo::value<std::string>()->default_value(""),
         "optional JSON file for /services registry (shard 0); load at start, save on POST/PATCH/DELETE "
         "(schema_version 2; empty disables)")
        ("admin-bearer-token",
         bpo::value<std::string>()->default_value(""),
         "optional shared secret: require Authorization: Bearer <token> on mutating admin routes "
         "(POST/PATCH/PUT/DELETE; empty disables)")
        ("admin-tls-cert",
         bpo::value<std::string>()->default_value(""),
         "PEM certificate for HTTPS admin (requires --admin-tls-key; empty = plain HTTP)")
        ("admin-tls-key",
         bpo::value<std::string>()->default_value(""),
         "PEM private key for HTTPS admin (requires --admin-tls-cert)")
        ("prepend-lct-word0",
         bpo::bool_switch()->default_value(false),
         "M8 lab: prepend RFC 5651 LCT header word-0 before ALP (header_length_words=1;"
         " see protocol/lct_rfc5651_word0.yaml minimal_v1_c0)")
        ("lct-codepoint",
         bpo::value<unsigned>()->default_value(0),
         "when --prepend-lct-word0: LCT codepoint octet (0-255)")
        ("lct-include-tsi",
         bpo::bool_switch()->default_value(false),
         "when --prepend-lct-word0: append 32-bit big-endian RFC 5651 TSI after "
         "word‑0 (--lct-tsi); with --lct-include-toi, TSI precedes TOI "
         "(header_length_words=3)")
        ("lct-tsi",
         bpo::value<std::uint32_t>()->default_value(0),
         "when --prepend-lct-word0 and --lct-include-tsi: Transport Session Id")
        ("lct-include-toi",
         bpo::bool_switch()->default_value(false),
         "when --prepend-lct-word0: append 32-bit BE TOI per RFC 5651 O=1 "
         "(header_length_words=2 alone, or =3 combined with --lct-include-tsi)")
        ("lct-toi",
         bpo::value<std::uint32_t>()->default_value(0),
         "when --prepend-lct-word0 and --lct-include-toi: Transport Object Id")
        ("prepend-mmtp-word0",
         bpo::bool_switch()->default_value(false),
         "M8 lab: prepend ISO/IEC 23008-1 MMTP packet header word-0 before ALP "
         "(before optional --prepend-lct-word0; see protocol/mmtp_header_word0.yaml)")
        ("mmtp-payload-type",
         bpo::value<unsigned>()->default_value(2),
         "when --prepend-mmtp-word0: MMTP payload_type field (0-63)")
        ("mmtp-packet-id",
         bpo::value<unsigned>()->default_value(1),
         "when --prepend-mmtp-word0: MMTP packet_id (0-65535)");

    return app.run(argc, argv, [&app]() -> seastar::future<int> {
        auto& cfg = app.configuration();

        const std::string admin_bind = cfg["admin-http"].as<std::string>();
        const std::string services_state = cfg["services-state-file"].as<std::string>();
        const bool prepend_lct = cfg["prepend-lct-word0"].as<bool>();
        const bool lct_include_tsi = cfg["lct-include-tsi"].as<bool>();
        const bool lct_include_toi = cfg["lct-include-toi"].as<bool>();
        const unsigned cp_in = cfg["lct-codepoint"].as<unsigned>();
        const std::uint32_t lct_tsi = cfg["lct-tsi"].as<std::uint32_t>();
        const std::uint32_t lct_toi = cfg["lct-toi"].as<std::uint32_t>();
        const bool prepend_mmtp = cfg["prepend-mmtp-word0"].as<bool>();
        const unsigned mmtp_pt_in = cfg["mmtp-payload-type"].as<unsigned>();
        const unsigned mmtp_pid_in = cfg["mmtp-packet-id"].as<unsigned>();
        if (!prepend_lct && cp_in != 0u) {
            mlog.error("--lct-codepoint is only meaningful with --prepend-lct-word0");
            co_return 2;
        }
        if (!prepend_lct && lct_include_tsi) {
            mlog.error("--lct-include-tsi requires --prepend-lct-word0");
            co_return 2;
        }
        if (!prepend_lct && lct_include_toi) {
            mlog.error("--lct-include-toi requires --prepend-lct-word0");
            co_return 2;
        }
        if (prepend_mmtp && mmtp_pt_in > 63u) {
            mlog.error("--mmtp-payload-type must be <= 63");
            co_return 2;
        }
        if (prepend_mmtp && mmtp_pid_in > 65535u) {
            mlog.error("--mmtp-packet-id must be <= 65535");
            co_return 2;
        }
        if (cp_in > std::numeric_limits<std::uint8_t>::max()) {
            mlog.error("--lct-codepoint must be <= 255");
            co_return 2;
        }
        atsc3::gw::encoder_pipeline::config enc_cfg{};
        if (prepend_lct) {
            if (lct_include_tsi && lct_include_toi) {
                enc_cfg = atsc3::gw::with_prepended_lab_lct_word0_tsi_toi(
                    static_cast<std::uint8_t>(cp_in), lct_tsi, lct_toi);
            } else if (lct_include_tsi) {
                enc_cfg = atsc3::gw::with_prepended_lab_lct_word0_tsi(
                    static_cast<std::uint8_t>(cp_in), lct_tsi);
            } else if (lct_include_toi) {
                enc_cfg = atsc3::gw::with_prepended_lab_lct_word0_toi(
                    static_cast<std::uint8_t>(cp_in), lct_toi);
            } else {
                enc_cfg = atsc3::gw::with_prepended_lab_lct_word0(
                    static_cast<std::uint8_t>(cp_in));
            }
        }
        if (prepend_mmtp) {
            enc_cfg = atsc3::gw::with_prepended_lab_mmtp_word0(
                static_cast<std::uint8_t>(mmtp_pt_in),
                static_cast<std::uint16_t>(mmtp_pid_in), std::move(enc_cfg));
        }

        atsc3::gw::gw_config gcfg{
            .ingress_addr = seastar::ipv4_addr(cfg["ingress"].as<std::string>()),
            .sink_uri     = cfg["sink"].as<std::string>(),
            .services_state_file =
                services_state.empty() ? std::nullopt
                                       : std::make_optional(services_state),
            .encoder = enc_cfg,
        };

        auto server = std::make_unique<seastar::sharded<atsc3::gw::gw_server>>();

        co_await server->start(gcfg);
        co_await server->invoke_on_all(&atsc3::gw::gw_server::start);

        std::optional<seastar::httpd::http_server_control> admin_ctl;
        if (!admin_bind.empty()) {
            atsc3::gw::admin_listen_options admin_opts{};
            const std::string bearer = cfg["admin-bearer-token"].as<std::string>();
            if (!bearer.empty()) {
                admin_opts.bearer_token = bearer;
            }
            const std::string tls_cert = cfg["admin-tls-cert"].as<std::string>();
            const std::string tls_key = cfg["admin-tls-key"].as<std::string>();
            if (!tls_cert.empty() || !tls_key.empty()) {
                if (tls_cert.empty() || tls_key.empty()) {
                    mlog.error(
                        "admin HTTPS requires both --admin-tls-cert and --admin-tls-key");
                    co_await server->stop();
                    co_return 2;
                }
                seastar::tls::credentials_builder cb;
                co_await cb.set_x509_key_file(
                    tls_cert, tls_key, seastar::tls::x509_crt_format::PEM);
                try {
                    admin_opts.tls_credentials = cb.build_server_credentials();
                } catch (const std::exception& ex) {
                    mlog.error("admin TLS credential build failed: {}", ex.what());
                } catch (...) {
                    mlog.error("admin TLS credential build failed (unknown)");
                }
                if (!admin_opts.tls_credentials) {
                    mlog.error("admin TLS: build_server_credentials failed or returned null");
                    co_await server->stop();
                    co_return 2;
                }
            }

            admin_ctl.emplace();
            co_await admin_ctl->start("atsc3-admin");
            seastar::ipv4_addr aa(admin_bind);
            co_await atsc3::gw::admin_http_listen(*admin_ctl, *server,
                                                  seastar::socket_address(aa),
                                                  std::move(admin_opts));
        }

        mlog.info(
            "atsc3_gw ready: ingress={} sink={} prepend_mmtp_word0={} "
            "mmtp_payload_type={} mmtp_packet_id={} prepend_lct_word0={} "
            "lct_codepoint={} lct_include_tsi={} lct_tsi={} lct_include_toi={} "
            "lct_toi={} admin_http={} services_state={} smp={}",
            gcfg.ingress_addr,
            gcfg.sink_uri,
            prepend_mmtp ? "yes" : "no",
            static_cast<unsigned>(gcfg.encoder.mmtp_word0.payload_type),
            static_cast<unsigned>(gcfg.encoder.mmtp_word0.packet_id),
            prepend_lct ? "yes" : "no",
            static_cast<unsigned>(gcfg.encoder.lct_word0.codepoint),
            prepend_lct && gcfg.encoder.lct_word0.tsi_flag ? "yes" : "no",
            gcfg.encoder.lct_transport_session_identifier,
            prepend_lct && gcfg.encoder.lct_word0.toi_flag == 1 &&
                    !gcfg.encoder.lct_word0.half_word_flag
                ? "yes"
                : "no",
            gcfg.encoder.lct_transport_object_identifier,
            admin_bind.empty() ? std::string("(disabled)") : admin_bind,
            gcfg.services_state_file.has_value() ? *gcfg.services_state_file
                                                 : std::string("(none)"),
            seastar::smp::count);

        // Wait for SIGINT/SIGTERM. The promise is satisfied from the signal
        // handler; the future blocks the coro until then.
        seastar::promise<> stopped;
        seastar::handle_signal(SIGINT, [&stopped] {
            try { stopped.set_value(); } catch (...) {}
        });
        seastar::handle_signal(SIGTERM, [&stopped] {
            try { stopped.set_value(); } catch (...) {}
        });
        co_await stopped.get_future();

        if (admin_ctl) {
            co_await admin_ctl->stop();
        }

        // Aggregate stats across shards before tearing down for a final log.
        atsc3::gw::gw_server::stats_t total{};
        co_await server->invoke_on_all(
            [&total](atsc3::gw::gw_server& s)
                -> seastar::future<> {
                auto st = co_await s.get_stats();
                total.bytes_in       += st.bytes_in;
                total.bytes_out      += st.bytes_out;
                total.payloads       += st.payloads;
                total.encode_errors  += st.encode_errors;
                total.connections    += st.connections;
                co_return;
            });
        mlog.info(
            "totals: payloads={} bytes_in={} bytes_out={} encode_errors={} "
            "connections={}",
            total.payloads, total.bytes_in, total.bytes_out,
            total.encode_errors, total.connections);

        co_await server->stop();
        co_return 0;
    });
}

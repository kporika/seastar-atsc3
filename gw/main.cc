// SPDX-License-Identifier: Apache-2.0
//
// atsc3_gw entry point. Parses CLI, builds a sharded<gw_server>, and runs
// until SIGINT/SIGTERM.

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <string>

#include <boost/program_options.hpp>

#include <seastar/core/app-template.hh>
#include <seastar/core/distributed.hh>
#include <seastar/core/future.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/sleep.hh>
#include <seastar/util/later.hh>
#include <seastar/util/log.hh>

#include "atsc3_gw.h"

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
         "output sink URI (file:///path, stdout://)");

    return app.run(argc, argv, [&app]() -> seastar::future<int> {
        auto& cfg = app.configuration();

        atsc3::gw::gw_config gcfg{
            .ingress_addr = seastar::ipv4_addr(cfg["ingress"].as<std::string>()),
            .sink_uri     = cfg["sink"].as<std::string>(),
        };

        auto server = std::make_unique<seastar::sharded<atsc3::gw::gw_server>>();

        co_await server->start(gcfg);
        co_await server->invoke_on_all(&atsc3::gw::gw_server::start);

        mlog.info(
            "atsc3_gw ready: ingress={} sink={} smp={}",
            gcfg.ingress_addr, gcfg.sink_uri, seastar::smp::count);

        // Wait for SIGINT/SIGTERM. The promise is satisfied from the signal
        // handler; the future blocks the coro until then.
        seastar::promise<> stopped;
        seastar::engine().handle_signal(SIGINT,  [&stopped] {
            try { stopped.set_value(); } catch (...) {}
        });
        seastar::engine().handle_signal(SIGTERM, [&stopped] {
            try { stopped.set_value(); } catch (...) {}
        });
        co_await stopped.get_future();

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

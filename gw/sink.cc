// SPDX-License-Identifier: Apache-2.0

#include "sink.h"

#include <fcntl.h>
#include <unistd.h>

#include <stdexcept>
#include <string>
#include <utility>

#include <seastar/core/file.hh>
#include <seastar/core/fstream.hh>
#include <seastar/core/iostream.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/seastar.hh>
#include <seastar/core/sstring.hh>
#include <seastar/util/log.hh>

namespace atsc3::gw {

static seastar::logger slog("sink");

namespace {

// ============================================================================
// file:// — per-shard append-only file
// ============================================================================
class file_sink final : public sink {
public:
    explicit file_sink(seastar::output_stream<char> out, std::string path)
        : _out(std::move(out)), _path(std::move(path)) {}

    seastar::future<> write(seastar::temporary_buffer<char> buf) override {
        return _out.write(buf.get(), buf.size());
    }
    seastar::future<> flush() override { return _out.flush(); }
    seastar::future<> close() override { return _out.close(); }

    std::string describe() const override {
        return "file://" + _path;
    }

private:
    seastar::output_stream<char> _out;
    std::string _path;
};

seastar::future<std::unique_ptr<sink>> make_file_sink(std::string base_path) {
    auto shard_path =
        base_path + ".shard" + std::to_string(seastar::this_shard_id());

    seastar::open_flags flags =
        seastar::open_flags::wo |
        seastar::open_flags::create |
        seastar::open_flags::truncate;

    return seastar::open_file_dma(shard_path, flags)
        .then([shard_path](seastar::file f) {
            // 64 KiB buffer; tunable later for higher throughput sinks.
            auto out = seastar::make_file_output_stream(std::move(f), 64 * 1024)
                           .get();
            slog.info("shard {} sink: file://{}",
                      seastar::this_shard_id(), shard_path);
            return std::unique_ptr<sink>(
                new file_sink(std::move(out), shard_path));
        });
}

// ============================================================================
// stdout:// — write to fd 1
// NOTE: ::write blocks the reactor; acceptable for dev/demo workloads, not
// production. Replaced in a later cut with a proper Seastar output_stream
// over fd 1, or just removed once a real sink (DPDK) lands.
// ============================================================================
class stdout_sink final : public sink {
public:
    seastar::future<> write(seastar::temporary_buffer<char> buf) override {
        const char *p = buf.get();
        size_t left = buf.size();
        while (left > 0) {
            auto n = ::write(STDOUT_FILENO, p, left);
            if (n < 0) {
                if (errno == EINTR) continue;
                return seastar::make_exception_future<>(
                    std::system_error(errno, std::system_category(),
                                      "stdout_sink write"));
            }
            p += n;
            left -= static_cast<size_t>(n);
        }
        return seastar::make_ready_future<>();
    }
    seastar::future<> flush() override { return seastar::make_ready_future<>(); }
    seastar::future<> close() override { return seastar::make_ready_future<>(); }
    std::string describe() const override { return "stdout://"; }
};

// ============================================================================
// null:// — discard all writes; tracks bytes for stats only.
// Use for throughput soaks where the sink would otherwise be the bottleneck
// (or fill the disk).
// ============================================================================
class null_sink final : public sink {
public:
    seastar::future<> write(seastar::temporary_buffer<char> buf) override {
        _bytes += buf.size();
        return seastar::make_ready_future<>();
    }
    seastar::future<> flush() override { return seastar::make_ready_future<>(); }
    seastar::future<> close() override {
        slog.info("shard {} null sink discarded {} bytes",
                  seastar::this_shard_id(), _bytes);
        return seastar::make_ready_future<>();
    }
    std::string describe() const override { return "null://"; }

private:
    std::uint64_t _bytes = 0;
};

}  // namespace

seastar::future<std::unique_ptr<sink>> make_sink(std::string_view uri) {
    constexpr std::string_view kFile   = "file://";
    constexpr std::string_view kStdout = "stdout://";
    constexpr std::string_view kNull   = "null://";

    if (uri.starts_with(kStdout)) {
        return seastar::make_ready_future<std::unique_ptr<sink>>(
            std::make_unique<stdout_sink>());
    }
    if (uri.starts_with(kNull)) {
        return seastar::make_ready_future<std::unique_ptr<sink>>(
            std::make_unique<null_sink>());
    }
    if (uri.starts_with(kFile)) {
        std::string path(uri.substr(kFile.size()));
        if (path.empty()) {
            return seastar::make_exception_future<std::unique_ptr<sink>>(
                std::runtime_error("sink: file:// requires a path"));
        }
        return make_file_sink(std::move(path));
    }
    return seastar::make_exception_future<std::unique_ptr<sink>>(
        std::runtime_error("sink: unsupported URI scheme: " + std::string(uri)));
}

}  // namespace atsc3::gw

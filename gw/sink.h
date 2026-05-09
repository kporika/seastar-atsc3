// SPDX-License-Identifier: Apache-2.0
//
// Output sink abstraction for the atsc3_proto gateway.
//
// First-cut sinks:
//   - file://path        per-shard file at  <path>.shard<N>
//   - stdout://          all shards write to fd 1 (interleaved)
//   - null://            discard; useful for throughput soaks
//
// Future swap-in: dpdk://<port>/<queue> beyond M5.

#pragma once

#include <memory>
#include <string>
#include <string_view>

#include <seastar/core/future.hh>
#include <seastar/core/temporary_buffer.hh>

namespace atsc3::gw {

class sink {
public:
    virtual ~sink() = default;

    // Append `buf` to the sink. Implementations are expected to be
    // single-shard (no cross-shard locking).
    virtual seastar::future<> write(seastar::temporary_buffer<char> buf) = 0;

    // Flush any in-flight buffering.
    virtual seastar::future<> flush() = 0;

    // Tear down the sink (close fds, etc).
    virtual seastar::future<> close() = 0;

    // Human-readable description, used in startup logs.
    virtual std::string describe() const = 0;
};

// Build a per-shard sink from a URI.
//
// Recognised schemes:
//   file:///absolute/path         opens "<path>.shard<this_shard_id>"
//   stdout://                     writes to STDOUT_FILENO (blocking)
//   null://                       discards bytes (counts size for stats)
//
// Throws std::runtime_error on an unrecognised or malformed URI.
seastar::future<std::unique_ptr<sink>> make_sink(std::string_view uri);

}  // namespace atsc3::gw

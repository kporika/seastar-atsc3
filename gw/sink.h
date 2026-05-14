// SPDX-License-Identifier: Apache-2.0
//
// Output sink abstraction for the atsc3_proto gateway.
//
// First-cut sinks:
//   - file://path        per-shard file at  <path>.shard<N>
//   - stdout://          all shards write to fd 1 (interleaved)
//   - null://            discard; useful for throughput soaks
//   - stltp://host:port  UDP lab encapsulation toward an exciter (see docs/END_TO_END_GAPS.md)
//   - udp://host:port    plain UDP: TLV-mux bytes as payload (lab; MTU guard)
//   - ipv4udp-file://path?src=&dst=&srcport=&dstport=[&ttl=]  append M8 IPv4+UDP wire per frame (offline / Wireshark prep)
//   - lls://[host:port][?q]  A/331 LLS UDP (default 224.0.23.60:4937); Table 6.1 header + gzip XML; ?table=&group=&gcm1=
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
//   stltp://host:port             CTP-style RTP/UDP (PT=97) + minimal stubs + TLV-mux payload
//   udp://host:port               TLV-mux as UDP payload (kernel IP/UDP headers)
//   ipv4udp-file:///path?src=a.b.c.d&dst=e.f.g.h&srcport=N&dstport=M[&ttl=T]
//                                 per-shard <path>.shard<N>; each write appends one M8 datagram
//   lls://                        well-known multicast 224.0.23.60:4937
//   lls://host:port               custom UDP destination (multicast or unicast)
//   lls://?table=3&group=1        default multicast + Table 6.1 fields (table decimal or 0x hex)
//                                 keys: table, group, gcm1 | groups (group_count_minus1)
//
// Throws std::runtime_error on an unrecognised or malformed URI.
seastar::future<std::unique_ptr<sink>> make_sink(std::string_view uri);

}  // namespace atsc3::gw

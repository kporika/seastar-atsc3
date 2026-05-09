// SPDX-License-Identifier: Apache-2.0
//
// Length-prefix TCP-stream framer used by ingress_tcp.
//
// Wire format on the ingress socket:
//   [u32 length, big-endian] [length bytes of payload]
//
// `length_framer` is stateful per-connection: it accumulates partial reads
// and emits zero or more complete payloads from any feed. There is no
// resumable parser state inside a payload — once we have `length` bytes
// they're handed off whole.
//
// Single-shard, single-connection. Not thread-safe (intentionally —
// each per-connection coroutine owns its own framer).

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

#include <seastar/core/temporary_buffer.hh>

namespace atsc3::gw {

class length_framer {
public:
    // Hard cap on a single payload size, applied at frame-length read time
    // to avoid letting a hostile/malformed peer balloon the buffer.
    // 1 MiB is well above expected RTCM/ALP/TLV-mux payload sizes (which
    // are bounded to 65535 by the TLV-mux 16-bit length field anyway).
    static constexpr std::size_t k_max_payload = 1u << 20;

    // Append raw bytes from the socket.
    // Returns false (and stops accepting input) if a length field exceeded
    // k_max_payload — the caller should close the connection.
    bool feed(seastar::temporary_buffer<char> buf);

    // Pop one complete payload if available; otherwise nullopt.
    std::optional<seastar::temporary_buffer<char>> try_extract();

    // True if a previous feed() blew the size cap.
    bool poisoned() const noexcept { return _poisoned; }

private:
    std::string _buf;       // M4: simple appendable buffer; can be made zero-copy later
    bool _poisoned = false;
};

}  // namespace atsc3::gw

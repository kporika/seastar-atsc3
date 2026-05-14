// SPDX-License-Identifier: Apache-2.0
//
// M8 — minimal IPv4 + UDP encapsulation (RFC 791 / RFC 768) for lab multicast
// and future ROUTE/MMTP work. No IP options (IHL = 5). DF bit set.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace atsc3::runtime {

/// IPv4 address as `uint32_t` with **first octet in the most significant byte**
/// (e.g. `ipv4_quad(224, 0, 23, 60)` for 224.0.23.60).
constexpr std::uint32_t ipv4_quad(std::uint8_t a,
                                  std::uint8_t b,
                                  std::uint8_t c,
                                  std::uint8_t d) noexcept {
    return (static_cast<std::uint32_t>(a) << 24) |
           (static_cast<std::uint32_t>(b) << 16) |
           (static_cast<std::uint32_t>(c) << 8) |
           static_cast<std::uint32_t>(d);
}

/// IPv4 addresses in the same **quad** convention as `ipv4_quad` (not `in_addr_t` / `htonl`).
struct ipv4_addrs {
    std::uint32_t src{};
    std::uint32_t dst{};
};

/// Build one IPv4 datagram carrying a UDP packet: 20-byte IPv4 header + 8-byte UDP header + payload.
/// `src_port` / `dst_port` are **host** byte order (e.g. 4937, not swapped).
[[nodiscard]] std::vector<std::byte> encapsulate_ipv4_udp(ipv4_addrs addrs,
                                                         std::uint16_t src_port,
                                                         std::uint16_t dst_port,
                                                         std::span<const std::byte> payload,
                                                         std::uint8_t ttl = 64,
                                                         std::uint16_t identification = 0);

/// One's-complement IPv4 header checksum over the first 20 bytes (checksum field must be zero).
[[nodiscard]] std::uint16_t ipv4_header_checksum(std::span<const std::byte, 20> header);

}  // namespace atsc3::runtime

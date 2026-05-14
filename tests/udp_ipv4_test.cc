// SPDX-License-Identifier: Apache-2.0

#include <cassert>
#include <cstring>
#include <span>
#include <vector>

#include "runtime/ipv4_udp.hh"

namespace {

std::uint16_t rd16(const std::vector<std::byte>& p, std::size_t off) {
    return static_cast<std::uint16_t>(
        (static_cast<unsigned>(p[off]) << 8) |
        static_cast<unsigned>(p[off + 1]));
}

}  // namespace

int main() {
    using atsc3::runtime::encapsulate_ipv4_udp;
    using atsc3::runtime::ipv4_addrs;
    using atsc3::runtime::ipv4_header_checksum;
    using atsc3::runtime::ipv4_quad;

    const std::byte pl[] = {
        static_cast<std::byte>('h'),
        static_cast<std::byte>('i'),
    };
    const auto pkt = encapsulate_ipv4_udp(
        ipv4_addrs{.src = ipv4_quad(10, 0, 0, 2), .dst = ipv4_quad(224, 0, 23, 60)},
        49152,
        4937,
        std::span<const std::byte>(pl, 2),
        32,
        0x1234);
    assert(pkt.size() == 20 + 8 + 2);

    assert(static_cast<unsigned>(pkt[0]) == 0x45);
    assert(static_cast<unsigned>(pkt[8]) == 32);
    assert(static_cast<unsigned>(pkt[9]) == 17);

    std::byte hdr_copy[20];
    std::memcpy(hdr_copy, pkt.data(), 20);
    hdr_copy[10] = std::byte{};
    hdr_copy[11] = std::byte{};
    const std::uint16_t calc =
        ipv4_header_checksum(std::span<const std::byte, 20>(hdr_copy));
    assert(calc == rd16(pkt, 10));

    assert(rd16(pkt, 20) == 49152);
    assert(rd16(pkt, 22) == 4937);
    assert(rd16(pkt, 24) == 8 + 2);

    return 0;
}

// SPDX-License-Identifier: Apache-2.0

#include "ipv4_udp.hh"

#include <arpa/inet.h>
#include <cstring>

namespace atsc3::runtime {
namespace {

constexpr std::size_t k_ipv4_hdr = 20;
constexpr std::size_t k_udp_hdr = 8;

void put_be16(std::byte* p, std::uint16_t v) noexcept {
    p[0] = static_cast<std::byte>(static_cast<std::uint8_t>(v >> 8));
    p[1] = static_cast<std::byte>(static_cast<std::uint8_t>(v & 0xff));
}

void put_be32(std::byte* p, std::uint32_t v) noexcept {
    p[0] = static_cast<std::byte>(static_cast<std::uint8_t>(v >> 24));
    p[1] = static_cast<std::byte>(static_cast<std::uint8_t>(v >> 16));
    p[2] = static_cast<std::byte>(static_cast<std::uint8_t>(v >> 8));
    p[3] = static_cast<std::byte>(static_cast<std::uint8_t>(v & 0xff));
}

std::uint16_t be16_load(const std::byte* p) noexcept {
    const auto* u = reinterpret_cast<const unsigned char*>(p);
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(u[0]) << 8) | static_cast<std::uint16_t>(u[1]));
}

std::uint32_t fold32(std::uint32_t sum) noexcept {
    while (sum >> 16U) {
        sum = (sum & 0xffffU) + (sum >> 16U);
    }
    return sum;
}

std::uint16_t ones_complement_sum(std::span<const std::byte> data) noexcept {
    std::uint32_t sum = 0;
    std::size_t i = 0;
    for (; i + 1 < data.size(); i += 2) {
        sum += be16_load(data.data() + i);
        sum = fold32(sum);
    }
    if (i < data.size()) {
        sum += static_cast<std::uint32_t>(
                   static_cast<std::uint8_t>(data[i]))
               << 8;
        sum = fold32(sum);
    }
    const std::uint16_t folded = static_cast<std::uint16_t>(sum & 0xffffU);
    return static_cast<std::uint16_t>(~folded);
}

}  // namespace

std::uint16_t ipv4_header_checksum(std::span<const std::byte, 20> header) {
    return ones_complement_sum(header);
}

std::vector<std::byte> encapsulate_ipv4_udp(ipv4_addrs addrs,
                                            std::uint16_t src_port,
                                            std::uint16_t dst_port,
                                            std::span<const std::byte> payload,
                                            std::uint8_t ttl,
                                            std::uint16_t identification) {
    const auto plen = payload.size();
    if (plen > 65000u) {
        return {};
    }
    const std::uint32_t udp_len = static_cast<std::uint32_t>(k_udp_hdr + plen);
    const std::uint32_t total_len =
        static_cast<std::uint32_t>(k_ipv4_hdr + udp_len);

    std::vector<std::byte> out(total_len);
    std::byte* ip = out.data();
    std::byte* udp = out.data() + k_ipv4_hdr;
    std::byte* pl = out.data() + k_ipv4_hdr + k_udp_hdr;

    if (plen != 0) {
        std::memcpy(pl, payload.data(), plen);
    }

    ip[0] = static_cast<std::byte>(0x45);
    ip[1] = static_cast<std::byte>(0);
    put_be16(ip + 2, static_cast<std::uint16_t>(total_len));
    put_be16(ip + 4, identification);
    put_be16(ip + 6, 0x4000);  // DF, offset 0
    ip[8] = static_cast<std::byte>(ttl);
    ip[9] = static_cast<std::byte>(17);
    put_be16(ip + 10, 0);
    put_be32(ip + 12, addrs.src);
    put_be32(ip + 16, addrs.dst);
    put_be16(ip + 10, ipv4_header_checksum(std::span<const std::byte, 20>(ip, k_ipv4_hdr)));

    std::uint16_t sp = htons(src_port);
    std::uint16_t dp = htons(dst_port);
    std::uint16_t ul = htons(static_cast<std::uint16_t>(udp_len));
    std::memcpy(udp + 0, &sp, sizeof(sp));
    std::memcpy(udp + 2, &dp, sizeof(dp));
    std::memcpy(udp + 4, &ul, sizeof(ul));
    put_be16(udp + 6, 0);

    // UDP checksum: pseudo-header + UDP header (csum 0) + payload + pad
    std::vector<std::byte> chk;
    chk.resize(12 + k_udp_hdr + plen + (plen % 2));
    put_be32(chk.data() + 0, addrs.src);
    put_be32(chk.data() + 4, addrs.dst);
    chk[8] = static_cast<std::byte>(0);
    chk[9] = static_cast<std::byte>(17);
    put_be16(chk.data() + 10, static_cast<std::uint16_t>(udp_len));
    std::memcpy(chk.data() + 12, udp, k_udp_hdr);
    if (plen != 0) {
        std::memcpy(chk.data() + 12 + k_udp_hdr, pl, plen);
    }
    if ((plen % 2) != 0) {
        chk[12 + k_udp_hdr + plen] = static_cast<std::byte>(0);
    }

    std::uint16_t udp_csum = ones_complement_sum(chk);
    if (udp_csum == 0) {
        udp_csum = 0xffff;
    }
    put_be16(udp + 6, udp_csum);

    return out;
}

}  // namespace atsc3::runtime

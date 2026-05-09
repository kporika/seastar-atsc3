// SPDX-License-Identifier: Apache-2.0

#include "rtcm_v3.h"

namespace mmt_probe::rtcm_v3 {

namespace {
constexpr std::uint32_t k_crc24q_poly = 0x1864CFBu;
}  // namespace

std::uint32_t crc24q(std::span<const std::byte> data) noexcept {
    std::uint32_t crc = 0;
    for (auto x : data) {
        crc ^= static_cast<std::uint32_t>(static_cast<std::uint8_t>(x)) << 16;
        for (int i = 0; i < 8; ++i) {
            crc <<= 1;
            if (crc & 0x1000000u) {
                crc ^= k_crc24q_poly;
            }
        }
    }
    return crc & 0xFFFFFFu;
}

decode_result decode(std::span<const std::byte> input) noexcept {
    decode_result r;
    if (input.size() < k_overhead + 1) {
        r.error = "rtcm: short header (need >= 7 bytes, have " +
                  std::to_string(input.size()) + ")";
        return r;
    }
    if (static_cast<std::uint8_t>(input[0]) != k_preamble) {
        r.error = "rtcm: bad preamble 0x" +
                  std::to_string(static_cast<std::uint8_t>(input[0]));
        return r;
    }

    const auto b1 = static_cast<std::uint8_t>(input[1]);
    const auto b2 = static_cast<std::uint8_t>(input[2]);
    const auto reserved = static_cast<std::uint8_t>(b1 >> 2);
    const auto length =
        static_cast<std::uint16_t>(((b1 & 0x03u) << 8) | b2);

    if (reserved != 0) {
        // Spec says these MUST be zero. Tolerate but warn via error string;
        // many real-world frames keep them zero so this aids debugging.
    }
    if (length == 0 || length > k_max_payload) {
        r.error = "rtcm: invalid length " + std::to_string(length);
        return r;
    }
    const std::size_t total = k_overhead + length;
    if (input.size() < total) {
        r.error = "rtcm: truncated frame (need " +
                  std::to_string(total) + ", have " +
                  std::to_string(input.size()) + ")";
        return r;
    }

    auto frame_bytes = input.subspan(0, total);
    auto payload     = frame_bytes.subspan(k_header_len, length);
    auto crc_bytes   = frame_bytes.subspan(k_header_len + length, k_crc_len);

    const std::uint32_t got_crc =
        (static_cast<std::uint32_t>(static_cast<std::uint8_t>(crc_bytes[0])) << 16) |
        (static_cast<std::uint32_t>(static_cast<std::uint8_t>(crc_bytes[1])) <<  8) |
        (static_cast<std::uint32_t>(static_cast<std::uint8_t>(crc_bytes[2])));

    const std::uint32_t want_crc =
        crc24q(input.subspan(0, k_header_len + length));
    if (got_crc != want_crc) {
        r.error = "rtcm: CRC mismatch (got 0x" +
                  std::to_string(got_crc) + ", want 0x" +
                  std::to_string(want_crc) + ")";
        return r;
    }

    // First 12 bits of payload = DF002 message_type.
    std::uint16_t msg_type = 0;
    if (payload.size() >= 2) {
        const auto p0 = static_cast<std::uint8_t>(payload[0]);
        const auto p1 = static_cast<std::uint8_t>(payload[1]);
        msg_type = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(p0) << 4) |
            (static_cast<std::uint16_t>(p1) >> 4));
    }

    r.ok = true;
    r.value.length = length;
    r.value.message_type = msg_type;
    r.value.crc = got_crc;
    r.value.bytes = frame_bytes;
    r.value.payload = payload;
    r.bytes_consumed = total;
    return r;
}

std::size_t decode_all(std::span<const std::byte> buffer,
                       std::vector<frame> &out,
                       std::string *out_error) {
    std::size_t count = 0;
    auto cur = buffer;
    while (!cur.empty()) {
        auto d = decode(cur);
        if (!d.ok) {
            if (out_error) *out_error = d.error;
            break;
        }
        out.push_back(d.value);
        cur = cur.subspan(d.bytes_consumed);
        ++count;
    }
    return count;
}

std::vector<std::byte> build(std::uint16_t message_type,
                             std::span<const std::byte> tail) {
    const std::size_t payload_len = 2 + tail.size();
    if (payload_len > k_max_payload) {
        return {};  // caller should treat empty result as failure
    }
    std::vector<std::byte> frame_bytes(k_overhead + payload_len);

    frame_bytes[0] = static_cast<std::byte>(k_preamble);
    frame_bytes[1] = static_cast<std::byte>((payload_len >> 8) & 0x03u);
    frame_bytes[2] = static_cast<std::byte>(payload_len & 0xFFu);

    // Encode message_type as the first 12 bits of the payload; remaining
    // 4 bits of byte 1 of the payload are zero.
    frame_bytes[3] = static_cast<std::byte>((message_type >> 4) & 0xFFu);
    frame_bytes[4] = static_cast<std::byte>((message_type & 0x0Fu) << 4);
    if (!tail.empty()) {
        for (std::size_t i = 0; i < tail.size(); ++i) {
            frame_bytes[5 + i] = tail[i];
        }
    }

    const std::uint32_t crc = crc24q(
        std::span<const std::byte>(frame_bytes.data(),
                                   k_header_len + payload_len));
    frame_bytes[k_header_len + payload_len + 0] =
        static_cast<std::byte>((crc >> 16) & 0xFFu);
    frame_bytes[k_header_len + payload_len + 1] =
        static_cast<std::byte>((crc >>  8) & 0xFFu);
    frame_bytes[k_header_len + payload_len + 2] =
        static_cast<std::byte>(crc & 0xFFu);

    return frame_bytes;
}

}  // namespace mmt_probe::rtcm_v3

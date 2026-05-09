// SPDX-License-Identifier: Apache-2.0
//
// RTCM 3.x frame helpers used by mmt_probe.
//
// Frame layout (RTCM-STANDARDS-104 §3.1):
//
//   [Preamble 0xD3]            1 byte
//   [Reserved 6 bits | Length 10 bits]  2 bytes (big-endian)
//   [Payload]                  N bytes (1 ≤ N ≤ 1023)
//   [CRC-24Q]                  3 bytes
//
//   Total frame = 6 + N bytes.
//
// CRC-24Q polynomial: 0x1864CFB, computed over the 3 header bytes plus
// the payload. The 6 reserved bits in byte 1 are zero in standard frames.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace mmt_probe::rtcm_v3 {

inline constexpr std::uint8_t  k_preamble = 0xD3;
inline constexpr std::uint16_t k_max_payload = 1023;  // 10-bit length field
inline constexpr std::size_t   k_header_len = 3;
inline constexpr std::size_t   k_crc_len = 3;
inline constexpr std::size_t   k_overhead = k_header_len + k_crc_len;

// Polynomial used by RTCM CRC-24Q.
std::uint32_t crc24q(std::span<const std::byte> data) noexcept;

// One decoded frame. Spans point into the caller's input buffer; valid
// only as long as the input lives.
struct frame {
    std::uint16_t           length = 0;     // payload length in bytes
    std::uint16_t           message_type = 0;  // first 12 bits of payload
    std::uint32_t           crc = 0;
    std::span<const std::byte> bytes{};      // full frame: header + payload + CRC
    std::span<const std::byte> payload{};    // payload only
};

struct decode_result {
    bool ok = false;
    frame value{};
    std::size_t bytes_consumed = 0;
    std::string error;
};

// Decode a single RTCM frame from the start of `input`. Validates the
// preamble, length bound, and CRC. On success, bytes_consumed = total
// frame length (6 + payload length).
decode_result decode(std::span<const std::byte> input) noexcept;

// Walk `buffer` and append every successfully decoded frame to `out`.
// Stops at the first decode failure or end of input. Returns the number
// of frames decoded; if `out_error` is non-null and a failure occurred,
// it gets the error text.
std::size_t decode_all(std::span<const std::byte> buffer,
                       std::vector<frame> &out,
                       std::string *out_error = nullptr);

// Build a complete RTCM frame for a 12-bit message type and an opaque
// payload-tail. The message_type is encoded as the first 12 bits of the
// payload (RTCM DF002), with the next 4 bits zero — a common convention
// for synthetic test frames where the rest of the message body is opaque
// random data.
//
// Total payload size = 2 (msg_type prefix) + tail.size(). Must fit in
// the 10-bit length field.
std::vector<std::byte> build(std::uint16_t message_type,
                             std::span<const std::byte> tail);

}  // namespace mmt_probe::rtcm_v3

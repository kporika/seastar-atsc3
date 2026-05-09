// SPDX-License-Identifier: Apache-2.0
//
// MSB-first bit writer, inverse of msb_bit_reader. Used by the codegen-
// emitted encoders. Caller is responsible for sizing the output buffer
// (zero-initialized) to at least header_bytes; the writer ORs bits in,
// it does not clear.
//
// Bit ordering matches A/330 §3 — bit_offset 0 is the top bit of byte 0.
// To write a `width`-bit value at `offset`, the most-significant bit of
// `value` lands at `offset` and the least-significant bit at
// `offset + width - 1`.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace atsc3::runtime {

class msb_bit_writer {
public:
    explicit constexpr msb_bit_writer(std::span<std::byte> out) noexcept
        : out_(out) {}

    // OR `width` (1..64) bits of `value` into the buffer starting at
    // bit `offset`. Bits above `width` in `value` are ignored.
    constexpr void write(std::size_t offset,
                         std::size_t width,
                         std::uint64_t value) const noexcept {
        for (std::size_t i = 0; i < width; ++i) {
            const std::size_t bit = offset + i;
            const std::size_t byte = bit / 8;
            const std::size_t shift = 7u - (bit % 8u);
            const std::uint64_t b =
                (value >> (width - 1 - i)) & 0x1ULL;
            out_[byte] = static_cast<std::byte>(
                static_cast<std::uint8_t>(out_[byte]) |
                static_cast<std::uint8_t>(b << shift));
        }
    }

private:
    std::span<std::byte> out_;
};

}  // namespace atsc3::runtime

// SPDX-License-Identifier: Apache-2.0
//
// MSB-first bit reader used by codegen-emitted decoders.
//
// All ATSC 3.0 wire formats specify bit ordering as MSB-first within a
// byte (clause 3, A/330). This reader matches that convention exactly:
// bit_offset 0 == top bit of byte 0, bit_offset 7 == bottom bit of byte 0,
// bit_offset 8 == top bit of byte 1, and so on.
//
// Single-call read covers up to 64 bits, which is plenty for every TLV
// header field we model. The reader does no bounds checking — the caller
// (always generated code) confirms `in.size()` against a precomputed
// `header_bytes` constant before invoking. Keeping bounds checks out of
// the hot path is intentional; the generated code is the only caller and
// it is verified by `tools/codegen.py`.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace atsc3::runtime {

class msb_bit_reader {
public:
    explicit constexpr msb_bit_reader(std::span<const std::byte> in) noexcept
        : in_(in) {}

    // Read `width` (1..64) bits starting at `offset` (MSB-first).
    constexpr std::uint64_t read(std::size_t offset,
                                 std::size_t width) const noexcept {
        std::uint64_t v = 0;
        for (std::size_t i = 0; i < width; ++i) {
            const std::size_t bit = offset + i;
            const std::size_t byte = bit / 8;
            const std::size_t shift = 7u - (bit % 8u);
            const std::uint64_t b =
                (static_cast<std::uint64_t>(in_[byte]) >> shift) & 0x1ULL;
            v = (v << 1) | b;
        }
        return v;
    }

private:
    std::span<const std::byte> in_;
};

}  // namespace atsc3::runtime

// SPDX-License-Identifier: Apache-2.0

#include "length_framer.h"

#include <cstring>

namespace atsc3::gw {

namespace {
inline std::uint32_t read_be_u32(const char *p) noexcept {
    return (static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[0])) << 24) |
           (static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[1])) << 16) |
           (static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[2])) <<  8) |
           (static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[3])));
}
}  // namespace

bool length_framer::feed(seastar::temporary_buffer<char> buf) {
    if (_poisoned) {
        return false;
    }
    _buf.append(buf.get(), buf.size());

    // Spot-check the next length field if we already have enough bytes for it,
    // so that we reject oversized frames before reading their bodies.
    if (_buf.size() >= 4) {
        const auto declared = read_be_u32(_buf.data());
        if (declared > k_max_payload) {
            _poisoned = true;
            return false;
        }
    }
    return true;
}

std::optional<seastar::temporary_buffer<char>> length_framer::try_extract() {
    if (_poisoned || _buf.size() < 4) {
        return std::nullopt;
    }
    const auto length = read_be_u32(_buf.data());
    if (_buf.size() < 4 + length) {
        return std::nullopt;
    }

    seastar::temporary_buffer<char> out(length);
    if (length > 0) {
        std::memcpy(out.get_write(), _buf.data() + 4, length);
    }
    // Drop header + payload from the front; M4 keeps it simple with std::string,
    // a circular/ring buffer would be a future optimization.
    _buf.erase(0, 4 + length);
    return out;
}

}  // namespace atsc3::gw

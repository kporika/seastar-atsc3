// SPDX-License-Identifier: Apache-2.0
//
// M9 — A/331 Table 6.1 first four bytes of each LLS UDP payload (before gzip).
// The gateway `lls://` sink prepends these when given cleartext XML; see gw/sink.cc.

#pragma once

#include <cstddef>
#include <cstdint>

namespace atsc3::runtime {

/// Write the 4-byte LLS prefix (table id, group id, group_count_minus1, version).
inline void write_lls_table6_1_prefix(std::byte* out,
                                      std::uint8_t lls_table_id,
                                      std::uint8_t group_id,
                                      std::uint8_t group_count_minus1,
                                      std::uint8_t lls_table_version) noexcept {
    out[0] = static_cast<std::byte>(lls_table_id);
    out[1] = static_cast<std::byte>(group_id);
    out[2] = static_cast<std::byte>(group_count_minus1);
    out[3] = static_cast<std::byte>(lls_table_version);
}

}  // namespace atsc3::runtime

// SPDX-License-Identifier: Apache-2.0
//
// Two-stage encoder pipeline used by the gateway:
//
//   raw payload bytes
//       │  optional M8: prepend RFC 5651 word‑0 (see prepend_rfc5651_lct_word0)
//       ▼
//   ┌─────────────────────┐
//   │  ALP encode         │  packet_type = PACKET_TYPE_EXTENSION (default)
//   │  (A/330 §5.2)       │  payload_length = N
//   └─────────────────────┘
//       │  ALP packet bytes
//       ▼
//   ┌─────────────────────┐
//   │  TLV-mux encode     │  packet_type = SIGNALING (default)
//   │  (A/330 Annex A)    │  packet_length = M
//   └─────────────────────┘
//       │
//       ▼
//   wire bytes (handed to sink)
//
// Limits:
//   * Without LCT prepend: opaque payload ≤ 2047 bytes (ALP 11-bit length).
//   * With prepend_rfc5651_lct_word0: ALP opaque = [word‑0] [optional 32-bit TSI BE]
//     ∪ user octets ≤ 2047 total.
//     · word‑0 only (`header_length_words == 1`, default helper): ≤ 2043 user.
//     · word‑0 + TSI (`header_length_words == 2`, `tsi_flag`): ≤ 2039 user.
//   * TLV-mux packet_length is 16 bits → ALP packet must be ≤ 65535 bytes.
//
// Both upper bounds are checked; oversize input returns an error result
// rather than truncating.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "alp_types.h"
#include "lct_rfc5651_word0_decoder.h"
#include "tlv_mux_types.h"

namespace atsc3::gw {

class encoder_pipeline {
public:
    struct config {
        atsc3::alp::packet_type alp_type =
            atsc3::alp::packet_type::PACKET_TYPE_EXTENSION;
        atsc3::tlv_mux::packet_type tlv_type =
            atsc3::tlv_mux::packet_type::SIGNALING;

        /// M8 lab: prepend RFC 5651 §5.1 header fields before ingress bytes in
        /// the ALP opaque body. Implemented cases:
        ///   * `header_length_words == 1`, `tsi_flag == false`: word‑0 only.
        ///   * `header_length_words == 2`, `toi_flag == 0`, `half_word_flag ==
        ///     false`, `tsi_flag == true`: word‑0 + 32‑bit Transport Session Id
        ///     BE (`lct_transport_session_identifier`). TOI/extension paths are
        ///     not modeled here.
        bool prepend_rfc5651_lct_word0 = false;
        atsc3::lct_rfc5651_word0::decoded_t lct_word0{};
        /// Used only when prepend + lab TSI strip (see constraints above).
        std::uint32_t lct_transport_session_identifier = 0;
    };

    struct result {
        bool ok = false;
        std::vector<std::byte> bytes;
        std::string error;
    };

    encoder_pipeline() noexcept = default;
    explicit encoder_pipeline(config cfg) noexcept : _cfg(cfg) {}

    [[nodiscard]] const config& encoder_config() const noexcept { return _cfg; }

    // Wrap a single raw payload. Returns the wire bytes ready for the sink.
    result encode(std::span<const std::byte> payload) const;

private:
    config _cfg;
};

/// Wire pattern follows `minimal_v1_c0` in `protocol/lct_rfc5651_word0.yaml`
/// (`header_length_words = 1` ⇒ word‑0 only).
[[nodiscard]] inline encoder_pipeline::config with_prepended_lab_lct_word0(
    std::uint8_t codepoint,
    encoder_pipeline::config base = {}) noexcept {
    base.prepend_rfc5651_lct_word0 = true;
    auto& w                        = base.lct_word0;
    w.lct_version                  = 1;
    w.congestion_flag_c            = 0;
    w.protocol_specific_indication = 0;
    w.tsi_flag                     = false;
    w.toi_flag                     = 0;
    w.half_word_flag               = false;
    w.reserved_two                 = 0;
    w.close_session                = false;
    w.close_object                 = false;
    w.header_length_words          = 1;
    w.codepoint                    = codepoint;
    return base;
}

/// Like `minimal_v1_c0` but `tsi_flag=true`, appends **`tsi`** BE32 after word‑0
/// (`header_length_words = 2`; no TOI on the wire in this lab path).
[[nodiscard]] inline encoder_pipeline::config with_prepended_lab_lct_word0_tsi(
    std::uint8_t codepoint,
    std::uint32_t tsi,
    encoder_pipeline::config base = {}) noexcept {
    base.prepend_rfc5651_lct_word0               = true;
    base.lct_transport_session_identifier        = tsi;
    auto& w                                      = base.lct_word0;
    w.lct_version                                = 1;
    w.congestion_flag_c                          = 0;
    w.protocol_specific_indication               = 0;
    w.tsi_flag                                   = true;
    w.toi_flag                                   = 0;
    w.half_word_flag                             = false;
    w.reserved_two                               = 0;
    w.close_session                              = false;
    w.close_object                               = false;
    w.header_length_words                        = 2;
    w.codepoint                                  = codepoint;
    return base;
}

}  // namespace atsc3::gw

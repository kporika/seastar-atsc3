// SPDX-License-Identifier: Apache-2.0
//
// Two-stage encoder pipeline used by the gateway:
//
//   raw payload bytes
//       │  optional M8: prepend ISO/IEC 23008-1 MMTP packet header word‑0
//       │  (see prepend_mmtp_header_word0), then optional RFC 5651 LCT word‑0
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
//   * Without any prepend: opaque payload ≤ 2047 bytes (ALP 11-bit length).
//   * With prepend_mmtp_header_word0: ALP opaque = MMTP word‑0 (32b) ∪ user
//     (≤ 2043 user bytes). May be combined with LCT lab prefix below (prefix
//     order on the wire: **MMTP word‑0**, then **LCT** + optional TSI/TOI).
//   * With prepend_rfc5651_lct_word0: ALP opaque = word‑0 (32b) ∪ optional RFC
//     reorder fields ∪ user ≤ 2047 total (**CCI omitted** lab stitch).
//     · word‑0 only (`header_length_words == 1`): ≤ 2043 user.
//     · + 32‑bit **TSI** (`header_length_words == 2`, **S**=**1**, **O**=**0**):
//       ≤ 2039 user.
//     · + 32‑bit **TOI**, **O**=**1** (`header_length_words == 2`, **S**=**0**):
//       ≤ 2039 user.
//     · + **TSI** then **TOI** (**S**=**1**, **O**=**1**, `header_length_words == 3`):
//       ≤ 2035 user.

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
#include "mmtp_header_word0_decoder.h"
#include "tlv_mux_types.h"

namespace atsc3::gw {

class encoder_pipeline {
public:
    struct config {
        atsc3::alp::packet_type alp_type =
            atsc3::alp::packet_type::PACKET_TYPE_EXTENSION;
        atsc3::tlv_mux::packet_type tlv_type =
            atsc3::tlv_mux::packet_type::SIGNALING;

        /// M8 lab: prepend MMTP packet header **word‑0** (32b, `protocol/mmtp_header_word0.yaml`)
        /// before ingress inside the ALP opaque body. Encoded with codegen
        /// **`mmtp_header_word0::encode`**; may precede the LCT lab prefix when both
        /// flags are set.
        bool prepend_mmtp_header_word0 = false;
        atsc3::mmtp_header_word0::decoded_t mmtp_word0{};

        /// M8 lab: prepend RFC 5651 §5.1 fixed fields before ingress in the ALP
        /// opaque body (**no CCI** extension — `header_length_words` counts trailing
        /// fixed words after word‑0):
        ///   * `header_length_words == 1`, **S**=0 (`tsi_flag`), **O**=0 (`toi_flag`):
        ///     word‑0 only.
        ///   * `header_length_words == 2`, **S**=1, **O**=0,
        ///     `half_word_flag == false`: word‑0 + 32‑bit TSI BE
        ///     (`lct_transport_session_identifier`).
        ///   * `header_length_words == 2`, **S**=1, **O**=0,
        ///     `half_word_flag == false`: word‑0 + 32‑bit TSI BE
        ///     (`lct_transport_session_identifier`).
        ///   * `header_length_words == 2`, **S**=0, **O**=**1** (`toi_flag == 1`),
        ///     `half_word_flag == false`: word‑0 + 32‑bit TOI BE
        ///     (`lct_transport_object_identifier`).
        ///   * `header_length_words == 3`, **S**=**1**, **O**=**1** (`toi_flag == 1`),
        ///     `half_word_flag == false`: word‑0 + 32‑bit TSI BE + 32‑bit TOI BE
        ///     (**RFC Figure 1** order; **CCI** still omitted lab‑only).
        bool prepend_rfc5651_lct_word0 = false;

        atsc3::lct_rfc5651_word0::decoded_t lct_word0{};
        std::uint32_t lct_transport_session_identifier = 0;
        std::uint32_t lct_transport_object_identifier  = 0;
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

/// MMTP word‑0 only (defaults: V=0, C=0, FEC=0, no X/R extensions, **payload_type**
/// and **packet_id** supplied — see `mmtp_header_word0.yaml` fixtures).
[[nodiscard]] inline encoder_pipeline::config with_prepended_lab_mmtp_word0(
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    encoder_pipeline::config base = {}) noexcept {
    base.prepend_mmtp_header_word0 = true;
    auto& m                        = base.mmtp_word0;
    m.mmtp_version                 = 0;
    m.packet_counter_flag          = false;
    m.fec_type                     = 0;
    m.reserved_r                   = 0;
    m.extension_flag               = false;
    m.rap_flag                     = false;
    m.reserved_two                 = 0;
    m.payload_type =
        (payload_type > 63u) ? static_cast<std::uint8_t>(63) : payload_type;
    m.packet_id = packet_id;
    return base;
}

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

/// Word‑0 + 32‑bit **TSI** (**S**=**1**) + 32‑bit **TOI** (**O**=**1** in `toi_flag`).
/// **`header_length_words = 3`**, **CCI** omitted (same lab caveat as sibling helpers).
[[nodiscard]] inline encoder_pipeline::config with_prepended_lab_lct_word0_tsi_toi(
    std::uint8_t codepoint,
    std::uint32_t tsi,
    std::uint32_t toi,
    encoder_pipeline::config base = {}) noexcept {
    base.prepend_rfc5651_lct_word0               = true;
    base.lct_transport_session_identifier        = tsi;
    base.lct_transport_object_identifier         = toi;
    auto& w                                      = base.lct_word0;
    w.lct_version                                = 1;
    w.congestion_flag_c                          = 0;
    w.protocol_specific_indication               = 0;
    w.tsi_flag                                   = true;
    w.toi_flag                                   = 1;
    w.half_word_flag                             = false;
    w.reserved_two                               = 0;
    w.close_session                              = false;
    w.close_object                               = false;
    w.header_length_words                        = 3;
    w.codepoint                                  = codepoint;
    return base;
}

/// Word‑0 + **O**`=1`: one 32-bit TOI (**`header_length_words = 2`**; no **S** /
/// TSI bit; **H**`=0`; `toi_flag` member stores **two-bit O**, value **1**).
[[nodiscard]] inline encoder_pipeline::config with_prepended_lab_lct_word0_toi(
    std::uint8_t codepoint,
    std::uint32_t toi,
    encoder_pipeline::config base = {}) noexcept {
    base.prepend_rfc5651_lct_word0        = true;
    base.lct_transport_object_identifier  = toi;
    auto& w                               = base.lct_word0;
    w.lct_version                         = 1;
    w.congestion_flag_c                   = 0;
    w.protocol_specific_indication        = 0;
    w.tsi_flag                            = false;
    w.toi_flag                            = 1;
    w.half_word_flag                      = false;
    w.reserved_two                        = 0;
    w.close_session                       = false;
    w.close_object                        = false;
    w.header_length_words                 = 2;
    w.codepoint                           = codepoint;
    return base;
}

}  // namespace atsc3::gw

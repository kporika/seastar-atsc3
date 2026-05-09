// SPDX-License-Identifier: Apache-2.0
//
// Two-stage encoder pipeline used by the gateway:
//
//   raw payload bytes
//       │
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
//   * ALP payload_length is 11 bits → input payload must be ≤ 2047 bytes.
//   * TLV-mux packet_length is 16 bits → ALP packet must be ≤ 65535 bytes.
//
// Both upper bounds are checked; oversize input returns an error result
// rather than truncating.

#pragma once

#include <cstddef>
#include <span>
#include <string>
#include <vector>

#include "alp_types.h"
#include "tlv_mux_types.h"

namespace atsc3::gw {

class encoder_pipeline {
public:
    struct config {
        atsc3::alp::packet_type alp_type =
            atsc3::alp::packet_type::PACKET_TYPE_EXTENSION;
        atsc3::tlv_mux::packet_type tlv_type =
            atsc3::tlv_mux::packet_type::SIGNALING;
    };

    struct result {
        bool ok = false;
        std::vector<std::byte> bytes;
        std::string error;
    };

    encoder_pipeline() noexcept = default;
    explicit encoder_pipeline(config cfg) noexcept : _cfg(cfg) {}

    // Wrap a single raw payload. Returns the wire bytes ready for the sink.
    result encode(std::span<const std::byte> payload) const;

private:
    config _cfg;
};

}  // namespace atsc3::gw

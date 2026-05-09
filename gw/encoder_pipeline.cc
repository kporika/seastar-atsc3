// SPDX-License-Identifier: Apache-2.0

#include "encoder_pipeline.h"

#include "alp_decoder.h"
#include "alp_encoder.h"
#include "tlv_mux_decoder.h"
#include "tlv_mux_encoder.h"

namespace atsc3::gw {

namespace {
constexpr std::size_t k_alp_max_payload    = (1u << 11) - 1;  // 11-bit length
constexpr std::size_t k_tlv_mux_max_packet = (1u << 16) - 1;  // 16-bit length
}  // namespace

encoder_pipeline::result encoder_pipeline::encode(
    std::span<const std::byte> payload) const {
    result r;

    // -------- 1) ALP encode -------------------------------------------------
    if (payload.size() > k_alp_max_payload) {
        r.error = "encoder_pipeline: payload " +
                  std::to_string(payload.size()) +
                  " > ALP 11-bit max " +
                  std::to_string(k_alp_max_payload);
        return r;
    }

    atsc3::alp::decoded_t alp{};
    alp.packet_type    = _cfg.alp_type;
    alp.payload_config = false;
    alp.header_mode    = false;
    alp.payload_length = static_cast<std::uint16_t>(payload.size());
    alp.payload        = payload;

    auto alp_enc = atsc3::alp::encode(alp);
    if (!alp_enc.ok) {
        r.error = "encoder_pipeline: alp encode failed: " + alp_enc.error;
        return r;
    }

    // -------- 2) TLV-mux encode --------------------------------------------
    if (alp_enc.bytes.size() > k_tlv_mux_max_packet) {
        r.error = "encoder_pipeline: ALP packet " +
                  std::to_string(alp_enc.bytes.size()) +
                  " > TLV-mux 16-bit max " +
                  std::to_string(k_tlv_mux_max_packet);
        return r;
    }

    atsc3::tlv_mux::decoded_t tlv{};
    tlv.packet_type   = _cfg.tlv_type;
    tlv.packet_length = static_cast<std::uint16_t>(alp_enc.bytes.size());
    tlv.payload       = std::span<const std::byte>(
        alp_enc.bytes.data(), alp_enc.bytes.size());

    auto tlv_enc = atsc3::tlv_mux::encode(tlv);
    if (!tlv_enc.ok) {
        r.error = "encoder_pipeline: tlv_mux encode failed: " + tlv_enc.error;
        return r;
    }

    r.bytes = std::move(tlv_enc.bytes);
    r.ok = true;
    return r;
}

}  // namespace atsc3::gw

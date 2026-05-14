// SPDX-License-Identifier: Apache-2.0

#include "encoder_pipeline.h"

#include <vector>

#include "alp_decoder.h"
#include "alp_encoder.h"
#include "lct_rfc5651_word0_encoder.h"
#include "tlv_mux_decoder.h"
#include "tlv_mux_encoder.h"

namespace atsc3::gw {

namespace {
constexpr std::size_t k_alp_max_payload    = (1u << 11) - 1;  // 11-bit length
constexpr std::size_t k_tlv_mux_max_packet = (1u << 16) - 1;  // 16-bit length
constexpr std::size_t k_rfc5651_word0_octets =
    sizeof(std::uint32_t);  // codegen header is fixed 32 bits

inline void append_u32_be(std::vector<std::byte>* out, std::uint32_t x) noexcept {
    out->push_back(static_cast<std::byte>((x >> 24) & 0xFF));
    out->push_back(static_cast<std::byte>((x >> 16) & 0xFF));
    out->push_back(static_cast<std::byte>((x >>  8) & 0xFF));
    out->push_back(static_cast<std::byte>( x        & 0xFF));
}
}  // namespace

encoder_pipeline::result encoder_pipeline::encode(
    std::span<const std::byte> payload) const {
    result r;

    std::vector<std::byte> prefixed;
    std::span<const std::byte> alp_body = payload;
    if (_cfg.prepend_rfc5651_lct_word0) {
        const auto& w = _cfg.lct_word0;
        if (!w.tsi_flag) {
            if (w.header_length_words != 1) {
                r.error =
                    "encoder_pipeline: LCT lab (word‑0 only) requires "
                    "header_length_words==1";
                return r;
            }
        } else {
            if (w.header_length_words != 2 || w.toi_flag != 0 ||
                w.half_word_flag) {
                r.error =
                    "encoder_pipeline: LCT+32-bit TSI lab requires "
                    "header_length_words==2, toi_flag==0, half_word_flag=false";
                return r;
            }
        }

        auto lct = atsc3::lct_rfc5651_word0::encode(w);
        if (!lct.ok || lct.bytes.size() != k_rfc5651_word0_octets) {
            r.error = "encoder_pipeline: LCT word0 encode failed";
            return r;
        }

        prefixed.reserve(lct.bytes.size() +
                             (w.tsi_flag ? sizeof(std::uint32_t)
                                         : std::size_t{}) +
                         payload.size());
        prefixed.insert(prefixed.end(), lct.bytes.begin(), lct.bytes.end());
        if (w.tsi_flag) {
            append_u32_be(&prefixed, _cfg.lct_transport_session_identifier);
        }
        prefixed.insert(prefixed.end(), payload.begin(), payload.end());
        alp_body = prefixed;
    }

    // -------- 1) ALP encode -------------------------------------------------
    if (alp_body.size() > k_alp_max_payload) {
        r.error = "encoder_pipeline: payload " +
                  std::to_string(alp_body.size()) +
                  " > ALP 11-bit max " +
                  std::to_string(k_alp_max_payload) +
                  (_cfg.prepend_rfc5651_lct_word0
                       ? " (includes RFC 5651 LCT lab prefix above ingress; shrink "
                         "ingress)"
                       : "");
        return r;
    }

    atsc3::alp::decoded_t alp{};
    alp.packet_type    = _cfg.alp_type;
    alp.payload_config = false;
    alp.header_mode    = false;
    alp.payload_length = static_cast<std::uint16_t>(alp_body.size());
    alp.payload        = alp_body;

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

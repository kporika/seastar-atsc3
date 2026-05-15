// SPDX-License-Identifier: Apache-2.0

#include "encoder_pipeline.h"

#include <optional>
#include <vector>

#include "alp_decoder.h"
#include "alp_encoder.h"
#include "lct_rfc5651_word0_encoder.h"
#include "mmtp_header_counter32_encoder.h"
#include "mmtp_header_extension_encoder.h"
#include "mmtp_header_ts_psn_encoder.h"
#include "mmtp_header_word0_encoder.h"
#include "mmtp_payload_isobmff_du_header_non_timed_encoder.h"
#include "mmtp_payload_isobmff_du_header_timed_encoder.h"
#include "mmtp_payload_isobmff_prefix_encoder.h"
#include "mmtp_payload_signalling_prefix_encoder.h"
#include "tlv_mux_decoder.h"
#include "tlv_mux_encoder.h"

namespace atsc3::gw {

namespace {
constexpr std::size_t k_alp_max_payload    = (1u << 11) - 1;  // 11-bit length
constexpr std::size_t k_tlv_mux_max_packet = (1u << 16) - 1;  // 16-bit length
constexpr std::size_t k_rfc5651_word0_octets =
    sizeof(std::uint32_t);  // codegen header is fixed 32 bits
constexpr std::size_t k_mmtp_word0_octets =
    sizeof(std::uint32_t);  // MMTP packet header word‑0
constexpr std::size_t k_mmtp_ts_psn_octets = 8;  // timestamp + packet_sequence_number BE
constexpr std::size_t k_mmtp_counter32_octets = 4;  // packet_counter BE
constexpr std::size_t k_mmtp_signalling_prefix_octets = 2;  // §9.3.4 first 16 bits
constexpr std::size_t k_mmtp_isobmff_prefix_octets   = 8;  // Figure 3 first 64 bits
constexpr std::size_t k_isobmff_du_header_timed_octets   = 14;  // Figure 4
constexpr std::size_t k_isobmff_du_header_non_timed_octets = 4;   // Figure 5

inline void append_u16_be(std::vector<std::byte>* out, std::uint16_t x) noexcept {
    out->push_back(static_cast<std::byte>((x >> 8) & 0xFF));
    out->push_back(static_cast<std::byte>( x       & 0xFF));
}

inline void append_u32_be(std::vector<std::byte>* out, std::uint32_t x) noexcept {
    out->push_back(static_cast<std::byte>((x >> 24) & 0xFF));
    out->push_back(static_cast<std::byte>((x >> 16) & 0xFF));
    out->push_back(static_cast<std::byte>((x >>  8) & 0xFF));
    out->push_back(static_cast<std::byte>( x        & 0xFF));
}

/// Octets the LCT lab appends after MMTP (word‑0 + optional extensions + optional
/// ISOBMFF/signalling) and before TCP ingress. **`std::nullopt`** if the LCT lab
/// mode in **`cfg`** is unsupported (same rules as **`encode`**’s LCT branch).
[[nodiscard]] std::optional<std::size_t> lab_lct_trailing_octets(
    bool want_lct, const encoder_pipeline::config& cfg) noexcept {
    if (!want_lct) return std::size_t{0};
    const auto& w = cfg.lct_word0;
    if (!w.tsi_flag && w.toi_flag == 0) {
        if (w.header_length_words != 1) return std::nullopt;
        return k_rfc5651_word0_octets;
    }
    if (w.tsi_flag && w.toi_flag == 1 && !w.half_word_flag &&
        w.header_length_words == 3) {
        return k_rfc5651_word0_octets + sizeof(std::uint32_t) * 2;
    }
    if (w.tsi_flag && w.toi_flag == 0 && !w.half_word_flag &&
        w.header_length_words == 2) {
        return k_rfc5651_word0_octets + sizeof(std::uint32_t);
    }
    if (!w.tsi_flag && w.toi_flag == 1 && !w.half_word_flag &&
        w.header_length_words == 2) {
        return k_rfc5651_word0_octets + sizeof(std::uint32_t);
    }
    return std::nullopt;
}
}  // namespace

encoder_pipeline::result encoder_pipeline::encode(
    std::span<const std::byte> payload) const {
    result r;

    std::optional<std::vector<std::byte>> alp_storage;
    std::span<const std::byte> alp_body = payload;

    const bool want_mmtp = _cfg.prepend_mmtp_header_word0;
    const bool want_lct  = _cfg.prepend_rfc5651_lct_word0;

    if (!want_mmtp && _cfg.prepend_mmtp_ts_psn) {
        r.error =
            "encoder_pipeline: prepend_mmtp_ts_psn requires "
            "prepend_mmtp_header_word0";
        return r;
    }
    if (!want_mmtp && !_cfg.mmtp_extensions.empty()) {
        r.error =
            "encoder_pipeline: MMTP header extensions require "
            "prepend_mmtp_header_word0";
        return r;
    }
    if (!want_mmtp && _cfg.prepend_mmtp_packet_counter) {
        r.error =
            "encoder_pipeline: prepend_mmtp_packet_counter requires "
            "prepend_mmtp_header_word0";
        return r;
    }
    if (!want_mmtp && _cfg.prepend_mmtp_signalling_prefix) {
        r.error =
            "encoder_pipeline: prepend_mmtp_signalling_prefix requires "
            "prepend_mmtp_header_word0";
        return r;
    }
    if (!want_mmtp && _cfg.prepend_mmtp_isobmff_prefix) {
        r.error =
            "encoder_pipeline: prepend_mmtp_isobmff_prefix requires "
            "prepend_mmtp_header_word0";
        return r;
    }
    if (_cfg.prepend_mmtp_isobmff_prefix && _cfg.prepend_mmtp_signalling_prefix) {
        r.error =
            "encoder_pipeline: prepend_mmtp_isobmff_prefix and "
            "prepend_mmtp_signalling_prefix are mutually exclusive";
        return r;
    }
    if (_cfg.prepend_mmtp_isobmff_prefix &&
        _cfg.mmtp_word0.payload_type != 0u) {
        r.error =
            "encoder_pipeline: prepend_mmtp_isobmff_prefix requires MMTP "
            "payload_type 0 (ISOBMFF mode)";
        return r;
    }
    if (_cfg.prepend_mmtp_isobmff_du_header &&
        !_cfg.prepend_mmtp_isobmff_prefix) {
        r.error =
            "encoder_pipeline: prepend_mmtp_isobmff_du_header requires "
            "prepend_mmtp_isobmff_prefix";
        return r;
    }
    if (_cfg.prepend_mmtp_isobmff_du_header &&
        _cfg.mmtp_isobmff_prefix.fragment_type != 2u) {
        r.error =
            "encoder_pipeline: prepend_mmtp_isobmff_du_header requires "
            "mmtp_isobmff_prefix fragment_type 2 (data unit)";
        return r;
    }
    if (_cfg.prepend_mmtp_packet_counter && !_cfg.prepend_mmtp_ts_psn) {
        r.error =
            "encoder_pipeline: prepend_mmtp_packet_counter requires "
            "prepend_mmtp_ts_psn (ISO/IEC 23008-1 header order)";
        return r;
    }

    if (want_mmtp || want_lct) {
        alp_storage.emplace();
        std::vector<std::byte>& buf = *alp_storage;

        if (want_mmtp) {
            auto w0 = _cfg.mmtp_word0;
            if (!_cfg.mmtp_extensions.empty()) {
                w0.extension_flag = true;
            }
            if (_cfg.prepend_mmtp_packet_counter) {
                w0.packet_counter_flag = true;
            }
            auto mmtp = atsc3::mmtp_header_word0::encode(w0);
            if (!mmtp.ok || mmtp.bytes.size() != k_mmtp_word0_octets) {
                r.error = "encoder_pipeline: MMTP header word0 encode failed";
                return r;
            }
            buf.insert(buf.end(), mmtp.bytes.begin(), mmtp.bytes.end());
            if (_cfg.prepend_mmtp_ts_psn) {
                auto tspsn = atsc3::mmtp_header_ts_psn::encode(_cfg.mmtp_ts_psn);
                if (!tspsn.ok || tspsn.bytes.size() != k_mmtp_ts_psn_octets) {
                    r.error =
                        "encoder_pipeline: MMTP ts_psn encode failed";
                    return r;
                }
                buf.insert(buf.end(), tspsn.bytes.begin(), tspsn.bytes.end());
            }
            if (_cfg.prepend_mmtp_packet_counter) {
                atsc3::mmtp_header_counter32::decoded_t ctr{};
                ctr.packet_counter = _cfg.mmtp_packet_counter;
                auto cenc = atsc3::mmtp_header_counter32::encode(ctr);
                if (!cenc.ok ||
                    cenc.bytes.size() != k_mmtp_counter32_octets) {
                    r.error =
                        "encoder_pipeline: MMTP packet_counter encode failed";
                    return r;
                }
                buf.insert(buf.end(), cenc.bytes.begin(), cenc.bytes.end());
            }
            for (const auto& tlv : _cfg.mmtp_extensions) {
                atsc3::mmtp_header_extension::decoded_t ex{};
                ex.extension_type = tlv.extension_type;
                ex.extension_length_bytes = static_cast<std::uint16_t>(
                    tlv.value.size());
                ex.payload = std::span<const std::byte>(
                    tlv.value.data(), tlv.value.size());
                auto exenc = atsc3::mmtp_header_extension::encode(ex);
                if (!exenc.ok) {
                    r.error = "encoder_pipeline: MMTP extension encode failed: " +
                              exenc.error;
                    return r;
                }
                buf.insert(buf.end(), exenc.bytes.begin(), exenc.bytes.end());
            }
            if (_cfg.prepend_mmtp_signalling_prefix) {
                const auto& sp = _cfg.mmtp_signalling_prefix;
                if (!sp.aggregation_flag &&
                    !_cfg.mmtp_signalling_aggregate_bodies.empty()) {
                    r.error =
                        "encoder_pipeline: mmtp_signalling_aggregate_bodies requires "
                        "aggregation_flag (ISO/IEC 23008-1 9.3.4)";
                    return r;
                }
                auto sg = atsc3::mmtp_payload_signalling_prefix::encode(sp);
                if (!sg.ok ||
                    sg.bytes.size() != k_mmtp_signalling_prefix_octets) {
                    r.error =
                        "encoder_pipeline: MMTP signalling payload prefix encode failed";
                    return r;
                }
                buf.insert(buf.end(), sg.bytes.begin(), sg.bytes.end());
                if (sp.aggregation_flag) {
                    for (const auto& chunk : _cfg.mmtp_signalling_aggregate_bodies) {
                        const std::size_t n = chunk.size();
                        if (!sp.length_extension_flag) {
                            if (n > 65535u) {
                                r.error =
                                    "encoder_pipeline: signalling aggregate body "
                                    "exceeds 16-bit length field (length_extension_flag=0)";
                                return r;
                            }
                            append_u16_be(
                                &buf, static_cast<std::uint16_t>(n));
                        } else {
                            append_u32_be(
                                &buf, static_cast<std::uint32_t>(n));
                        }
                        buf.insert(buf.end(), chunk.begin(), chunk.end());
                    }
                }
            } else if (_cfg.prepend_mmtp_isobmff_prefix) {
                const auto& ip0 = _cfg.mmtp_isobmff_prefix;
                if (ip0.fragment_type > 15u) {
                    r.error =
                        "encoder_pipeline: mmtp_isobmff_prefix fragment_type must be <= 15";
                    return r;
                }
                if (ip0.fragmentation_indicator > 3u) {
                    r.error =
                        "encoder_pipeline: mmtp_isobmff_prefix fragmentation_indicator "
                        "must be <= 3";
                    return r;
                }
                const auto lct_tail = lab_lct_trailing_octets(want_lct, _cfg);
                if (!lct_tail) {
                    r.error =
                        "encoder_pipeline: ISOBMFF prefix + LCT lab: unsupported "
                        "LCT header_length_words / TSI / TOI combination";
                    return r;
                }
                const std::size_t duh_octets =
                    _cfg.prepend_mmtp_isobmff_du_header
                        ? (ip0.timed_flag ? k_isobmff_du_header_timed_octets
                                          : k_isobmff_du_header_non_timed_octets)
                        : 0u;
                std::size_t after_prefix = *lct_tail + payload.size();
                if (ip0.aggregation_flag) {
                    if (_cfg.mmtp_isobmff_aggregate_bodies.empty()) {
                        r.error =
                            "encoder_pipeline: mmtp_isobmff_aggregate_bodies requires "
                            "aggregation_flag (ISO/IEC 23008-1 ISOBMFF-mode A=1)";
                        return r;
                    }
                    for (const auto& chunk : _cfg.mmtp_isobmff_aggregate_bodies) {
                        const std::size_t du_wire = duh_octets + chunk.size();
                        if (du_wire > 65535u) {
                            r.error =
                                "encoder_pipeline: ISOBMFF aggregate DU exceeds "
                                "16-bit DU_length";
                            return r;
                        }
                        after_prefix += 2u + du_wire;
                    }
                } else if (!_cfg.mmtp_isobmff_aggregate_bodies.empty()) {
                    r.error =
                        "encoder_pipeline: mmtp_isobmff_aggregate_bodies requires "
                        "aggregation_flag (ISO/IEC 23008-1 ISOBMFF-mode)";
                    return r;
                } else {
                    after_prefix += duh_octets;
                }
                const std::size_t len_exc = 6u + after_prefix;
                if (len_exc > 65535u) {
                    r.error =
                        "encoder_pipeline: ISOBMFF payload length_excluding_length_field "
                        "would exceed 16 bits (shrink ingress / aggregates / LCT)";
                    return r;
                }
                auto iso = ip0;
                iso.payload_length_excluding_length_field =
                    static_cast<std::uint16_t>(len_exc);
                auto ienc = atsc3::mmtp_payload_isobmff_prefix::encode(iso);
                if (!ienc.ok ||
                    ienc.bytes.size() != k_mmtp_isobmff_prefix_octets) {
                    r.error =
                        "encoder_pipeline: MMTP ISOBMFF payload prefix encode failed: " +
                        ienc.error;
                    return r;
                }
                buf.insert(buf.end(), ienc.bytes.begin(), ienc.bytes.end());
                if (_cfg.prepend_mmtp_isobmff_du_header && !ip0.aggregation_flag) {
                    if (ip0.timed_flag) {
                        auto he = atsc3::mmtp_payload_isobmff_du_header_timed::encode(
                            _cfg.mmtp_isobmff_du_header_timed);
                        if (!he.ok ||
                            he.bytes.size() != k_isobmff_du_header_timed_octets) {
                            r.error =
                                "encoder_pipeline: MMTP ISOBMFF timed DU header encode failed: " +
                                he.error;
                            return r;
                        }
                        buf.insert(buf.end(), he.bytes.begin(), he.bytes.end());
                    } else {
                        auto he = atsc3::mmtp_payload_isobmff_du_header_non_timed::encode(
                            _cfg.mmtp_isobmff_du_header_non_timed);
                        if (!he.ok ||
                            he.bytes.size() != k_isobmff_du_header_non_timed_octets) {
                            r.error =
                                "encoder_pipeline: MMTP ISOBMFF non-timed DU header encode failed: " +
                                he.error;
                            return r;
                        }
                        buf.insert(buf.end(), he.bytes.begin(), he.bytes.end());
                    }
                }
                if (ip0.aggregation_flag) {
                    for (const auto& chunk : _cfg.mmtp_isobmff_aggregate_bodies) {
                        if (_cfg.prepend_mmtp_isobmff_du_header) {
                            std::vector<std::byte> hdr_bytes;
                            if (ip0.timed_flag) {
                                auto he = atsc3::mmtp_payload_isobmff_du_header_timed::encode(
                                    _cfg.mmtp_isobmff_du_header_timed);
                                if (!he.ok ||
                                    he.bytes.size() !=
                                        k_isobmff_du_header_timed_octets) {
                                    r.error =
                                        "encoder_pipeline: MMTP ISOBMFF timed DU header "
                                        "(aggregate) encode failed: " +
                                        he.error;
                                    return r;
                                }
                                hdr_bytes = std::move(he.bytes);
                            } else {
                                auto he =
                                    atsc3::mmtp_payload_isobmff_du_header_non_timed::encode(
                                        _cfg.mmtp_isobmff_du_header_non_timed);
                                if (!he.ok ||
                                    he.bytes.size() !=
                                        k_isobmff_du_header_non_timed_octets) {
                                    r.error =
                                        "encoder_pipeline: MMTP ISOBMFF non-timed DU header "
                                        "(aggregate) encode failed: " +
                                        he.error;
                                    return r;
                                }
                                hdr_bytes = std::move(he.bytes);
                            }
                            const std::size_t du_total = hdr_bytes.size() + chunk.size();
                            append_u16_be(
                                &buf, static_cast<std::uint16_t>(du_total));
                            buf.insert(buf.end(), hdr_bytes.begin(), hdr_bytes.end());
                            buf.insert(buf.end(), chunk.begin(), chunk.end());
                        } else {
                            append_u16_be(
                                &buf, static_cast<std::uint16_t>(chunk.size()));
                            buf.insert(buf.end(), chunk.begin(), chunk.end());
                        }
                    }
                }
            }
        }

        if (want_lct) {
            const auto& w = _cfg.lct_word0;
            enum class lab_prefix_mode { none, tsi_word32, toi_o1_word32,
                                        tsi_then_toi_o1_word64 };

            lab_prefix_mode mode;
            if (!w.tsi_flag && w.toi_flag == 0) {
                if (w.header_length_words != 1) {
                    r.error =
                        "encoder_pipeline: LCT lab (word‑0 only) requires "
                        "header_length_words==1";
                    return r;
                }
                mode = lab_prefix_mode::none;
            } else if (w.tsi_flag && w.toi_flag == 1 && !w.half_word_flag &&
                       w.header_length_words == 3) {
                mode = lab_prefix_mode::tsi_then_toi_o1_word64;
            } else if (w.tsi_flag && w.toi_flag == 0 && !w.half_word_flag &&
                       w.header_length_words == 2) {
                mode = lab_prefix_mode::tsi_word32;
            } else if (!w.tsi_flag && w.toi_flag == 1 && !w.half_word_flag &&
                       w.header_length_words == 2) {
                mode = lab_prefix_mode::toi_o1_word32;
            } else {
                r.error =
                    "encoder_pipeline: unsupported LCT lab prefix (supports word‑0; "
                    "word‑0+32b TSI; word‑0+32b TOI with O==1; "
                    "word‑0+32b TSI+32b TOI with O==1, header_length_words==3)";
                return r;
            }

            auto lct = atsc3::lct_rfc5651_word0::encode(w);
            if (!lct.ok || lct.bytes.size() != k_rfc5651_word0_octets) {
                r.error = "encoder_pipeline: LCT word0 encode failed";
                return r;
            }

            const std::size_t extra =
                (mode == lab_prefix_mode::none)
                    ? 0
                    : (mode == lab_prefix_mode::tsi_then_toi_o1_word64
                           ? sizeof(std::uint32_t) * 2
                           : sizeof(std::uint32_t));
            buf.reserve(buf.size() + lct.bytes.size() + extra + payload.size());
            buf.insert(buf.end(), lct.bytes.begin(), lct.bytes.end());
            if (mode == lab_prefix_mode::tsi_word32) {
                append_u32_be(&buf, _cfg.lct_transport_session_identifier);
            } else if (mode == lab_prefix_mode::toi_o1_word32) {
                append_u32_be(&buf, _cfg.lct_transport_object_identifier);
            } else if (mode == lab_prefix_mode::tsi_then_toi_o1_word64) {
                append_u32_be(&buf, _cfg.lct_transport_session_identifier);
                append_u32_be(&buf, _cfg.lct_transport_object_identifier);
            }
        } else {
            buf.reserve(buf.size() + payload.size());
        }

        buf.insert(buf.end(), payload.begin(), payload.end());
        alp_body = std::span<const std::byte>(buf.data(), buf.size());
    }

    // -------- 1) ALP encode -------------------------------------------------
    if (alp_body.size() > k_alp_max_payload) {
        r.error = "encoder_pipeline: payload " +
                  std::to_string(alp_body.size()) +
                  " > ALP 11-bit max " +
                  std::to_string(k_alp_max_payload) +
                  ((want_mmtp || want_lct)
                       ? " (includes lab prefix(es) before ingress; shrink ingress)"
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

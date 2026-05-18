// SPDX-License-Identifier: Apache-2.0

#include "encoder_pipeline.h"

#include <optional>
#include <vector>

#include "alp_decoder.h"
#include "alp_encoder.h"
#include "lct_rfc5651_word0_encoder.h"
#include "mmt_si_length32_envelope_encoder.h"
#include "mmt_si_message_header_len32_encoder.h"
#include "mmt_si_mpt_asset_decoder.h"
#include "mmt_si_mpt_asset_descriptors4_decoder.h"
#include "mmt_si_mpt_asset_id8_decoder.h"
#include "mmt_si_mpt_asset_id16_decoder.h"
#include "mmt_si_mpt_asset_location0_decoder.h"
#include "mmt_si_mpt_asset_location_ipv4_decoder.h"
#include "mmt_si_mpt_asset_location_ipv4_nz_decoder.h"
#include "mmt_si_mpt_asset_location_ipv6_decoder.h"
#include "mmt_si_mpt_asset_location_ipv6_nz_decoder.h"
#include "mmt_si_mpt_asset_id8_location_ipv4_decoder.h"
#include "mmt_si_mpt_asset_id8_location_ipv4_nz_decoder.h"
#include "mmt_si_mpt_asset_id8_location_ipv6_nz_decoder.h"
#include "mmt_si_mpt_asset_id8_location_ipv6_decoder.h"
#include "mmt_si_mpt_asset_id16_location_ipv4_decoder.h"
#include "mmt_si_mpt_asset_id16_location_ipv4_nz_decoder.h"
#include "mmt_si_mpt_asset_id16_location_ipv6_decoder.h"
#include "mmt_si_mpt_asset_id16_location_ipv6_nz_decoder.h"
#include "mmt_si_mpt_asset_id16_descriptors4_decoder.h"
#include "mmt_si_mpt_asset_id8_descriptors4_decoder.h"
#include "mmt_si_mpt_table_body_prefix_decoder.h"
#include "mmt_si_mpt_table_decoder.h"
#include "mmt_si_pa_table_headers_decoder.h"
#include "mmt_si_pa_table_headers_encoder.h"
#include "mmt_si_plt_delivery_info_decoder.h"
#include "mmt_si_plt_delivery_info_ipv4_decoder.h"
#include "mmt_si_plt_delivery_info_ipv4_nz_decoder.h"
#include "mmt_si_plt_delivery_info_ipv6_decoder.h"
#include "mmt_si_plt_delivery_info_url_decoder.h"
#include "mmt_si_plt_delivery_info_url_3_decoder.h"
#include "mmt_si_plt_delivery_info_url_4_decoder.h"
#include "mmt_si_plt_package_entry_decoder.h"
#include "mmt_si_plt_package_entry_id8_decoder.h"
#include "mmt_si_plt_package_entry_ipv4_decoder.h"
#include "mmt_si_plt_package_entry_ipv4_nz_decoder.h"
#include "mmt_si_plt_package_entry_id8_location_ipv4_decoder.h"
#include "mmt_si_plt_package_entry_id8_location_ipv4_nz_decoder.h"
#include "mmt_si_plt_package_entry_id8_location_ipv6_decoder.h"
#include "mmt_si_plt_package_entry_id8_location_ipv6_nz_decoder.h"
#include "mmt_si_plt_package_entry_ipv6_decoder.h"
#include "mmt_si_plt_package_entry_ipv6_nz_decoder.h"
#include "mmt_si_plt_table_body_prefix_decoder.h"
#include "mmt_si_plt_table_decoder.h"
#include "mmtp_header_counter32_encoder.h"
#include "mmtp_header_extension_encoder.h"
#include "mmtp_header_ts_psn_encoder.h"
#include "mmtp_header_word0_encoder.h"
#include "mmtp_payload_isobmff_du_header_non_timed_encoder.h"
#include "mmtp_payload_isobmff_du_header_timed_encoder.h"
#include "mmtp_payload_gfd_header_encoder.h"
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
constexpr std::size_t k_mmtp_gfd_header_octets = 12;  // Figure 6 (96 bits)

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
/// ISOBMFF/GFD/signalling) and before TCP ingress. **`std::nullopt`** if the LCT lab
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

/// **`validate_mmt_si_*_table_body`** on a **§10.3** consumption message: ingress
/// may be **table-only** (gateway does not prepend PA) or **PA index || table**
/// (ACN-style lab). Try a full-span table decode first; peel PA only when that
/// fails and a **PA || table** composite decodes cleanly.
struct ingress_table_validate_view {
    std::span<const std::byte> table_bytes;
    bool                         ok = true;
    std::string                  error;
};

using si_table_ingress_probe = bool (*)(std::span<const std::byte>);

[[nodiscard]] bool mpt_table_fully_decodes(std::span<const std::byte> s) {
    const auto d = atsc3::mmt_si_mpt_table::decode(s);
    return d.ok && d.bytes_consumed == s.size();
}

[[nodiscard]] bool plt_table_fully_decodes(std::span<const std::byte> s) {
    const auto d = atsc3::mmt_si_plt_table::decode(s);
    return d.ok && d.bytes_consumed == s.size();
}

[[nodiscard]] ingress_table_validate_view ingress_for_si_table_validate(
    std::span<const std::byte>        payload,
    const encoder_pipeline::config& cfg,
    si_table_ingress_probe            probe) {
    ingress_table_validate_view view{payload, true, {}};
    if (cfg.prepend_mmt_si_pa_table_headers || probe(payload)) {
        return view;
    }
    if (!cfg.prepend_mmt_si_message_header_len32) {
        return view;
    }
    const auto pah = atsc3::mmt_si_pa_table_headers::decode(payload);
    if (!pah.ok) {
        view.ok    = false;
        view.error = pah.error;
        return view;
    }
    if (pah.bytes_consumed >= payload.size()) {
        view.ok    = false;
        view.error = "PA table index consumed entire ingress";
        return view;
    }
    const auto after = payload.subspan(pah.bytes_consumed);
    if (!probe(after)) {
        view.ok    = false;
        view.error =
            "ingress is neither a sole MMT-SI table nor PA index + table body";
        return view;
    }
    view.table_bytes = after;
    return view;
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
    if (!want_mmtp && _cfg.prepend_mmtp_gfd_header) {
        r.error =
            "encoder_pipeline: prepend_mmtp_gfd_header requires "
            "prepend_mmtp_header_word0";
        return r;
    }
    if (_cfg.prepend_mmtp_isobmff_prefix && _cfg.prepend_mmtp_signalling_prefix) {
        r.error =
            "encoder_pipeline: prepend_mmtp_isobmff_prefix and "
            "prepend_mmtp_signalling_prefix are mutually exclusive";
        return r;
    }
    if (_cfg.prepend_mmtp_gfd_header && _cfg.prepend_mmtp_signalling_prefix) {
        r.error =
            "encoder_pipeline: prepend_mmtp_gfd_header and "
            "prepend_mmtp_signalling_prefix are mutually exclusive";
        return r;
    }
    if (_cfg.prepend_mmtp_gfd_header && _cfg.prepend_mmtp_isobmff_prefix) {
        r.error =
            "encoder_pipeline: prepend_mmtp_gfd_header and "
            "prepend_mmtp_isobmff_prefix are mutually exclusive";
        return r;
    }
    if (_cfg.prepend_mmtp_isobmff_prefix &&
        _cfg.mmtp_word0.payload_type != 0u) {
        r.error =
            "encoder_pipeline: prepend_mmtp_isobmff_prefix requires MMTP "
            "payload_type 0 (ISOBMFF mode)";
        return r;
    }
    if (_cfg.prepend_mmtp_gfd_header && _cfg.mmtp_word0.payload_type != 1u) {
        r.error =
            "encoder_pipeline: prepend_mmtp_gfd_header requires MMTP "
            "payload_type 1 (GFD mode)";
        return r;
    }
    if (_cfg.prepend_mmtp_gfd_header && _cfg.mmtp_gfd_header.reserved > 31u) {
        r.error =
            "encoder_pipeline: mmtp_gfd_header.reserved must be <= 31 (5 bits)";
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
    if (_cfg.prepend_mmt_si_length32_envelope ||
        _cfg.prepend_mmt_si_descriptor_loop_u32 ||
        _cfg.prepend_mmt_si_message_header_len32 ||
        _cfg.prepend_mmt_si_pa_table_headers) {
        if (!_cfg.prepend_mmtp_signalling_prefix) {
            r.error =
                "encoder_pipeline: MMT-SI lab suffix (message header and/or "
                "descriptor loop and/or length32 envelope) requires "
                "prepend_mmtp_signalling_prefix";
            return r;
        }
        if (!_cfg.prepend_mmtp_header_word0) {
            r.error =
                "encoder_pipeline: MMT-SI lab suffix requires prepend_mmtp_header_word0";
            return r;
        }
        if (_cfg.mmtp_word0.payload_type != 2u) {
            r.error =
                "encoder_pipeline: MMT-SI lab suffix requires MMTP payload_type 2 "
                "(signalling)";
            return r;
        }
        if (_cfg.mmtp_signalling_prefix.aggregation_flag) {
            r.error =
                "encoder_pipeline: MMT-SI lab suffix requires signalling "
                "aggregation_flag 0 (ISO/IEC 23008-1 9.3.4 lab)";
            return r;
        }
        if (!_cfg.mmtp_signalling_aggregate_bodies.empty()) {
            r.error =
                "encoder_pipeline: MMT-SI lab suffix is incompatible with "
                "non-empty mmtp_signalling_aggregate_bodies";
            return r;
        }
    }

    if (_cfg.validate_mmt_si_mpt_table_body &&
        _cfg.validate_mmt_si_plt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_table_body and "
            "validate_mmt_si_plt_table_body are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_table_body) {
        const auto view =
            ingress_for_si_table_validate(payload, _cfg, mpt_table_fully_decodes);
        if (!view.ok) {
            r.error = "encoder_pipeline: mmt_si_mpt_table ingress layout: " +
                      view.error;
            return r;
        }
        const auto table_payload = view.table_bytes;
        auto       mpt           = atsc3::mmt_si_mpt_table::decode(table_payload);
        if (!mpt.ok) {
            r.error = "encoder_pipeline: mmt_si_mpt_table decode failed: " +
                      mpt.error;
            return r;
        }
        if (mpt.bytes_consumed != table_payload.size()) {
            r.error =
                "encoder_pipeline: mmt_si_mpt_table decode consumed " +
                std::to_string(mpt.bytes_consumed) + " of " +
                std::to_string(table_payload.size()) + " ingress octets";
            return r;
        }
        if (mpt.value.table_id != 32u) {
            r.error =
                "encoder_pipeline: mmt_si_mpt_table table_id must be 0x20 (32)";
            return r;
        }
        if (_cfg.validate_mmt_si_mpt_table_body_prefix) {
            if (mpt.value.table_length != 5u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix lab requires "
                    "table_length 5 (minimal MPT prefix)";
                return r;
            }
            auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(
                mpt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.bytes_consumed != mpt.value.payload.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix consumed " +
                    std::to_string(pref.bytes_consumed) + " of " +
                    std::to_string(mpt.value.payload.size()) +
                    " MPT table_length octets";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_mpt_asset) {
            if (mpt.value.table_length != 19u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset lab requires "
                    "table_length 19 (5-byte prefix + 14-byte asset)";
                return r;
            }
            auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(
                mpt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.number_of_assets != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset lab requires "
                    "number_of_assets 1";
                return r;
            }
            if (pref.bytes_consumed != 5u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix must be 5 octets "
                    "before mmt_si_mpt_asset";
                return r;
            }
            const auto asset_span =
                mpt.value.payload.subspan(pref.bytes_consumed);
            auto asset = atsc3::mmt_si_mpt_asset::decode(asset_span);
            if (!asset.ok) {
                r.error = "encoder_pipeline: mmt_si_mpt_asset decode failed: " +
                          asset.error;
                return r;
            }
            if (asset.bytes_consumed != asset_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset consumed " +
                    std::to_string(asset.bytes_consumed) + " of " +
                    std::to_string(asset_span.size()) +
                    " asset octets after MPT prefix";
                return r;
            }
            if (asset.value.asset_id_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset lab requires "
                    "asset_id_length 0";
                return r;
            }
            if (asset.value.location_count != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset lab requires "
                    "location_count 0";
                return r;
            }
            if (asset.value.asset_descriptors_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset lab requires "
                    "asset_descriptors_length 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_mpt_asset_id8) {
            if (mpt.value.table_length != 20u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8 lab requires "
                    "table_length 20 (5-byte prefix + 15-byte asset)";
                return r;
            }
            auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(
                mpt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.number_of_assets != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8 lab requires "
                    "number_of_assets 1";
                return r;
            }
            if (pref.bytes_consumed != 5u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix must be 5 octets "
                    "before mmt_si_mpt_asset_id8";
                return r;
            }
            const auto asset_span =
                mpt.value.payload.subspan(pref.bytes_consumed);
            auto asset = atsc3::mmt_si_mpt_asset_id8::decode(asset_span);
            if (!asset.ok) {
                r.error = "encoder_pipeline: mmt_si_mpt_asset_id8 decode failed: " +
                          asset.error;
                return r;
            }
            if (asset.bytes_consumed != asset_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8 consumed " +
                    std::to_string(asset.bytes_consumed) + " of " +
                    std::to_string(asset_span.size()) +
                    " asset octets after MPT prefix";
                return r;
            }
            if (asset.value.asset_id_length != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8 lab requires "
                    "asset_id_length 1";
                return r;
            }
            if (asset.value.asset_id != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8 lab requires "
                    "asset_id 1";
                return r;
            }
            if (asset.value.location_count != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8 lab requires "
                    "location_count 0";
                return r;
            }
            if (asset.value.asset_descriptors_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8 lab requires "
                    "asset_descriptors_length 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_mpt_asset_id16) {
            if (mpt.value.table_length != 21u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16 lab requires "
                    "table_length 21 (5-byte prefix + 16-byte asset)";
                return r;
            }
            auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(
                mpt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.number_of_assets != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16 lab requires "
                    "number_of_assets 1";
                return r;
            }
            if (pref.bytes_consumed != 5u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix must be 5 octets "
                    "before mmt_si_mpt_asset_id16";
                return r;
            }
            const auto asset_span =
                mpt.value.payload.subspan(pref.bytes_consumed);
            auto asset = atsc3::mmt_si_mpt_asset_id16::decode(asset_span);
            if (!asset.ok) {
                r.error = "encoder_pipeline: mmt_si_mpt_asset_id16 decode failed: " +
                          asset.error;
                return r;
            }
            if (asset.bytes_consumed != asset_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16 consumed " +
                    std::to_string(asset.bytes_consumed) + " of " +
                    std::to_string(asset_span.size()) +
                    " asset octets after MPT prefix";
                return r;
            }
            if (asset.value.asset_id_length != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16 lab requires "
                    "asset_id_length 2";
                return r;
            }
            if (asset.value.asset_id_byte0 != 0x01u ||
                asset.value.asset_id_byte1 != 0x02u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16 lab requires "
                    "asset_id octets 0x01 0x02";
                return r;
            }
            if (asset.value.location_count != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16 lab requires "
                    "location_count 0";
                return r;
            }
            if (asset.value.asset_descriptors_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16 lab requires "
                    "asset_descriptors_length 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_mpt_asset_location0) {
            if (mpt.value.table_length != 22u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location0 lab requires "
                    "table_length 22 (5-byte prefix + 17-byte asset)";
                return r;
            }
            auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(
                mpt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.number_of_assets != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location0 lab requires "
                    "number_of_assets 1";
                return r;
            }
            if (pref.bytes_consumed != 5u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix must be 5 octets "
                    "before mmt_si_mpt_asset_location0";
                return r;
            }
            const auto asset_span =
                mpt.value.payload.subspan(pref.bytes_consumed);
            auto asset =
                atsc3::mmt_si_mpt_asset_location0::decode(asset_span);
            if (!asset.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location0 decode failed: " +
                    asset.error;
                return r;
            }
            if (asset.bytes_consumed != asset_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location0 consumed " +
                    std::to_string(asset.bytes_consumed) + " of " +
                    std::to_string(asset_span.size()) +
                    " asset octets after MPT prefix";
                return r;
            }
            if (asset.value.asset_id_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location0 lab requires "
                    "asset_id_length 0";
                return r;
            }
            if (asset.value.location_count != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location0 lab requires "
                    "location_count 1";
                return r;
            }
            if (asset.value.location_type != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location0 lab requires "
                    "location_type 0";
                return r;
            }
            if (asset.value.packet_id != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location0 lab requires "
                    "packet_id 0";
                return r;
            }
            if (asset.value.asset_descriptors_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location0 lab requires "
                    "asset_descriptors_length 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_mpt_asset_location_ipv4) {
            if (mpt.value.table_length != 30u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv4 lab requires "
                    "table_length 30 (5-byte prefix + 25-byte asset)";
                return r;
            }
            auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(
                mpt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.number_of_assets != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv4 lab requires "
                    "number_of_assets 1";
                return r;
            }
            if (pref.bytes_consumed != 5u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix must be 5 octets "
                    "before mmt_si_mpt_asset_location_ipv4";
                return r;
            }
            const auto asset_span =
                mpt.value.payload.subspan(pref.bytes_consumed);
            auto asset =
                atsc3::mmt_si_mpt_asset_location_ipv4::decode(asset_span);
            if (!asset.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv4 decode failed: " +
                    asset.error;
                return r;
            }
            if (asset.bytes_consumed != asset_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv4 consumed " +
                    std::to_string(asset.bytes_consumed) + " of " +
                    std::to_string(asset_span.size()) +
                    " asset octets after MPT prefix";
                return r;
            }
            if (asset.value.asset_id_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv4 lab requires "
                    "asset_id_length 0";
                return r;
            }
            if (asset.value.location_count != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv4 lab requires "
                    "location_count 1";
                return r;
            }
            if (asset.value.location_type != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv4 lab requires "
                    "location_type 1";
                return r;
            }
            if (asset.value.ipv4_src_addr != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv4 lab requires "
                    "ipv4_src_addr 0";
                return r;
            }
            if (asset.value.ipv4_dst_addr != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv4 lab requires "
                    "ipv4_dst_addr 0";
                return r;
            }
            if (asset.value.dst_port != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv4 lab requires "
                    "dst_port 0";
                return r;
            }
            if (asset.value.asset_descriptors_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv4 lab requires "
                    "asset_descriptors_length 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_mpt_asset_location_ipv4_nz) {
            if (mpt.value.table_length != 30u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv4_nz lab requires "
                    "table_length 30 (5-byte prefix + 25-byte asset)";
                return r;
            }
            auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(
                mpt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.number_of_assets != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv4_nz lab requires "
                    "number_of_assets 1";
                return r;
            }
            if (pref.bytes_consumed != 5u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix must be 5 octets "
                    "before mmt_si_mpt_asset_location_ipv4_nz";
                return r;
            }
            const auto asset_span =
                mpt.value.payload.subspan(pref.bytes_consumed);
            auto asset =
                atsc3::mmt_si_mpt_asset_location_ipv4_nz::decode(asset_span);
            if (!asset.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv4_nz decode failed: " +
                    asset.error;
                return r;
            }
            if (asset.bytes_consumed != asset_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv4_nz consumed " +
                    std::to_string(asset.bytes_consumed) + " of " +
                    std::to_string(asset_span.size()) +
                    " asset octets after MPT prefix";
                return r;
            }
            if (asset.value.asset_id_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv4_nz lab requires "
                    "asset_id_length 0";
                return r;
            }
            if (asset.value.location_count != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv4_nz lab requires "
                    "location_count 1";
                return r;
            }
            if (asset.value.location_type != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv4_nz lab requires "
                    "location_type 1";
                return r;
            }
            if (asset.value.ipv4_src_addr != 0x0A000001u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv4_nz lab requires "
                    "ipv4_src_addr 10.0.0.1";
                return r;
            }
            if (asset.value.ipv4_dst_addr != 0xE0000001u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv4_nz lab requires "
                    "ipv4_dst_addr 224.0.0.1";
                return r;
            }
            if (asset.value.dst_port != 5000u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv4_nz lab requires "
                    "dst_port 5000";
                return r;
            }
            if (asset.value.asset_descriptors_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv4_nz lab requires "
                    "asset_descriptors_length 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_mpt_asset_id8_location_ipv4_nz) {
            if (mpt.value.table_length != 31u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv4_nz lab requires "
                    "table_length 31 (5-byte prefix + 26-byte asset)";
                return r;
            }
            auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(
                mpt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.number_of_assets != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv4_nz lab requires "
                    "number_of_assets 1";
                return r;
            }
            if (pref.bytes_consumed != 5u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix must be 5 octets "
                    "before mmt_si_mpt_asset_id8_location_ipv4_nz";
                return r;
            }
            const auto asset_span =
                mpt.value.payload.subspan(pref.bytes_consumed);
            auto asset =
                atsc3::mmt_si_mpt_asset_id8_location_ipv4_nz::decode(asset_span);
            if (!asset.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv4_nz decode failed: " +
                    asset.error;
                return r;
            }
            if (asset.bytes_consumed != asset_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv4_nz consumed " +
                    std::to_string(asset.bytes_consumed) + " of " +
                    std::to_string(asset_span.size()) +
                    " asset octets after MPT prefix";
                return r;
            }
            if (asset.value.asset_id_length != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv4_nz lab requires "
                    "asset_id_length 1";
                return r;
            }
            if (asset.value.asset_id != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv4_nz lab requires "
                    "asset_id 1";
                return r;
            }
            if (asset.value.location_count != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv4_nz lab requires "
                    "location_count 1";
                return r;
            }
            if (asset.value.location_type != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv4_nz lab requires "
                    "location_type 1";
                return r;
            }
            if (asset.value.ipv4_src_addr != 0x0A000001u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv4_nz lab requires "
                    "ipv4_src_addr 10.0.0.1";
                return r;
            }
            if (asset.value.ipv4_dst_addr != 0xE0000001u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv4_nz lab requires "
                    "ipv4_dst_addr 224.0.0.1";
                return r;
            }
            if (asset.value.dst_port != 5000u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv4_nz lab requires "
                    "dst_port 5000";
                return r;
            }
            if (asset.value.asset_descriptors_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv4_nz lab requires "
                    "asset_descriptors_length 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
            if (mpt.value.table_length != 55u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv6_nz lab requires "
                    "table_length 55 (5-byte prefix + 50-byte asset)";
                return r;
            }
            auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(
                mpt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.number_of_assets != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv6_nz lab requires "
                    "number_of_assets 1";
                return r;
            }
            if (pref.bytes_consumed != 5u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix must be 5 octets "
                    "before mmt_si_mpt_asset_id8_location_ipv6_nz";
                return r;
            }
            const auto asset_span =
                mpt.value.payload.subspan(pref.bytes_consumed);
            auto asset =
                atsc3::mmt_si_mpt_asset_id8_location_ipv6_nz::decode(asset_span);
            if (!asset.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv6_nz decode failed: " +
                    asset.error;
                return r;
            }
            if (asset.bytes_consumed != asset_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv6_nz consumed " +
                    std::to_string(asset.bytes_consumed) + " of " +
                    std::to_string(asset_span.size()) +
                    " asset octets after MPT prefix";
                return r;
            }
            if (asset.value.asset_id_length != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv6_nz lab requires "
                    "asset_id_length 1";
                return r;
            }
            if (asset.value.asset_id != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv6_nz lab requires "
                    "asset_id 1";
                return r;
            }
            if (asset.value.location_count != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv6_nz lab requires "
                    "location_count 1";
                return r;
            }
            if (asset.value.location_type != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv6_nz lab requires "
                    "location_type 2";
                return r;
            }
            if (asset.value.ipv6_src_addr_0 != 0u ||
                asset.value.ipv6_src_addr_1 != 0u ||
                asset.value.ipv6_src_addr_2 != 65535u ||
                asset.value.ipv6_src_addr_3 != 167772161u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv6_nz lab requires "
                    "ipv6_src_addr ::ffff:10.0.0.1";
                return r;
            }
            if (asset.value.ipv6_dst_addr_0 != 0u ||
                asset.value.ipv6_dst_addr_1 != 0u ||
                asset.value.ipv6_dst_addr_2 != 65535u ||
                asset.value.ipv6_dst_addr_3 != 3758096385u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv6_nz lab requires "
                    "ipv6_dst_addr ::ffff:224.0.0.1";
                return r;
            }
            if (asset.value.dst_port != 5000u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv6_nz lab requires "
                    "dst_port 5000";
                return r;
            }
            if (asset.value.asset_descriptors_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv6_nz lab requires "
                    "asset_descriptors_length 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4) {
            if (mpt.value.table_length != 32u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv4 lab requires "
                    "table_length 32 (5-byte prefix + 27-byte asset)";
                return r;
            }
            auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(
                mpt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.number_of_assets != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv4 lab requires "
                    "number_of_assets 1";
                return r;
            }
            if (pref.bytes_consumed != 5u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix must be 5 octets "
                    "before mmt_si_mpt_asset_id16_location_ipv4";
                return r;
            }
            const auto asset_span =
                mpt.value.payload.subspan(pref.bytes_consumed);
            auto asset =
                atsc3::mmt_si_mpt_asset_id16_location_ipv4::decode(asset_span);
            if (!asset.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv4 decode failed: " +
                    asset.error;
                return r;
            }
            if (asset.bytes_consumed != asset_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv4 consumed " +
                    std::to_string(asset.bytes_consumed) + " of " +
                    std::to_string(asset_span.size()) +
                    " asset octets after MPT prefix";
                return r;
            }
            if (asset.value.asset_id_length != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv4 lab requires "
                    "asset_id_length 2";
                return r;
            }
            if (asset.value.asset_id_byte0 != 1u || asset.value.asset_id_byte1 != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv4 lab requires "
                    "asset_id 0x01 0x02";
                return r;
            }
            if (asset.value.location_count != 1u || asset.value.location_type != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv4 lab requires "
                    "location_count 1 and location_type 1";
                return r;
            }
            if (asset.value.ipv4_src_addr != 0u || asset.value.ipv4_dst_addr != 0u ||
                asset.value.dst_port != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv4 lab requires "
                    "zero IPv4 addresses and dst_port";
                return r;
            }
            if (asset.value.asset_descriptors_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv4 lab requires "
                    "asset_descriptors_length 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz) {
            if (mpt.value.table_length != 32u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv4_nz lab requires "
                    "table_length 32 (5-byte prefix + 27-byte asset)";
                return r;
            }
            auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(
                mpt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.number_of_assets != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv4_nz lab requires "
                    "number_of_assets 1";
                return r;
            }
            if (pref.bytes_consumed != 5u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix must be 5 octets "
                    "before mmt_si_mpt_asset_id16_location_ipv4_nz";
                return r;
            }
            const auto asset_span =
                mpt.value.payload.subspan(pref.bytes_consumed);
            auto asset =
                atsc3::mmt_si_mpt_asset_id16_location_ipv4_nz::decode(asset_span);
            if (!asset.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv4_nz decode failed: " +
                    asset.error;
                return r;
            }
            if (asset.bytes_consumed != asset_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv4_nz consumed " +
                    std::to_string(asset.bytes_consumed) + " of " +
                    std::to_string(asset_span.size()) +
                    " asset octets after MPT prefix";
                return r;
            }
            if (asset.value.asset_id_length != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv4_nz lab requires "
                    "asset_id_length 2";
                return r;
            }
            if (asset.value.asset_id_byte0 != 1u || asset.value.asset_id_byte1 != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv4_nz lab requires "
                    "asset_id 0x01 0x02";
                return r;
            }
            if (asset.value.location_count != 1u || asset.value.location_type != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv4_nz lab requires "
                    "location_count 1 and location_type 1";
                return r;
            }
            if (asset.value.ipv4_src_addr != 0x0A000001u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv4_nz lab requires "
                    "ipv4_src_addr 10.0.0.1";
                return r;
            }
            if (asset.value.ipv4_dst_addr != 0xE0000001u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv4_nz lab requires "
                    "ipv4_dst_addr 224.0.0.1";
                return r;
            }
            if (asset.value.dst_port != 5000u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv4_nz lab requires "
                    "dst_port 5000";
                return r;
            }
            if (asset.value.asset_descriptors_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv4_nz lab requires "
                    "asset_descriptors_length 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6) {
            if (mpt.value.table_length != 55u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv6 lab requires "
                    "table_length 55 (5-byte prefix + 50-byte asset)";
                return r;
            }
            auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(
                mpt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.number_of_assets != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv6 lab requires "
                    "number_of_assets 1";
                return r;
            }
            if (pref.bytes_consumed != 5u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix must be 5 octets "
                    "before mmt_si_mpt_asset_id16_location_ipv6";
                return r;
            }
            const auto asset_span =
                mpt.value.payload.subspan(pref.bytes_consumed);
            std::vector<std::byte> asset_buf(asset_span.begin(), asset_span.end());
            if (asset_buf.size() == 50u) {
                asset_buf.push_back(std::byte{0});
            }
            auto asset =
                atsc3::mmt_si_mpt_asset_id16_location_ipv6::decode(asset_buf);
            if (!asset.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv6 decode failed: " +
                    asset.error;
                return r;
            }
            if (asset.bytes_consumed != asset_buf.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv6 consumed " +
                    std::to_string(asset.bytes_consumed) + " of " +
                    std::to_string(asset_buf.size()) +
                    " asset octets after MPT prefix";
                return r;
            }
            if (asset.value.asset_id_length != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv6 lab requires "
                    "asset_id_length 2";
                return r;
            }
            if (asset.value.asset_id_byte0 != 1u || asset.value.asset_id_byte1 != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv6 lab requires "
                    "asset_id 0x01 0x02";
                return r;
            }
            if (asset.value.location_count != 1u || asset.value.location_type != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv6 lab requires "
                    "location_count 1 and location_type 2";
                return r;
            }
            if (asset.value.ipv6_src_addr_0 != 0u || asset.value.ipv6_src_addr_1 != 0u ||
                asset.value.ipv6_src_addr_2 != 0u || asset.value.ipv6_src_addr_3 != 0u ||
                asset.value.ipv6_dst_addr_0 != 0u || asset.value.ipv6_dst_addr_1 != 0u ||
                asset.value.ipv6_dst_addr_2 != 0u || asset.value.ipv6_dst_addr_3 != 0u ||
                asset.value.dst_port != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv6 lab requires "
                    "zero IPv6 addresses and dst_port";
                return r;
            }
            if (asset.value.asset_descriptors_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv6 lab requires "
                    "asset_descriptors_length 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz) {
            if (mpt.value.table_length != 56u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv6_nz lab requires "
                    "table_length 56 (5-byte prefix + 51-byte asset)";
                return r;
            }
            auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(
                mpt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.number_of_assets != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv6_nz lab requires "
                    "number_of_assets 1";
                return r;
            }
            if (pref.bytes_consumed != 5u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix must be 5 octets "
                    "before mmt_si_mpt_asset_id16_location_ipv6_nz";
                return r;
            }
            const auto asset_span =
                mpt.value.payload.subspan(pref.bytes_consumed);
            auto asset =
                atsc3::mmt_si_mpt_asset_id16_location_ipv6_nz::decode(asset_span);
            if (!asset.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv6_nz decode failed: " +
                    asset.error;
                return r;
            }
            if (asset.bytes_consumed != asset_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv6_nz consumed " +
                    std::to_string(asset.bytes_consumed) + " of " +
                    std::to_string(asset_span.size()) +
                    " asset octets after MPT prefix";
                return r;
            }
            if (asset.value.asset_id_length != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv6_nz lab requires "
                    "asset_id_length 2";
                return r;
            }
            if (asset.value.asset_id_byte0 != 1u || asset.value.asset_id_byte1 != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv6_nz lab requires "
                    "asset_id 0x01 0x02";
                return r;
            }
            if (asset.value.location_count != 1u || asset.value.location_type != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv6_nz lab requires "
                    "location_count 1 and location_type 2";
                return r;
            }
            if (asset.value.ipv6_src_addr_0 != 0u ||
                asset.value.ipv6_src_addr_1 != 0u ||
                asset.value.ipv6_src_addr_2 != 65535u ||
                asset.value.ipv6_src_addr_3 != 167772161u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv6_nz lab requires "
                    "ipv6_src_addr ::ffff:10.0.0.1";
                return r;
            }
            if (asset.value.ipv6_dst_addr_0 != 0u ||
                asset.value.ipv6_dst_addr_1 != 0u ||
                asset.value.ipv6_dst_addr_2 != 65535u ||
                asset.value.ipv6_dst_addr_3 != 3758096385u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv6_nz lab requires "
                    "ipv6_dst_addr ::ffff:224.0.0.1";
                return r;
            }
            if (asset.value.dst_port != 5000u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv6_nz lab requires "
                    "dst_port 5000";
                return r;
            }
            if (asset.value.asset_descriptors_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_location_ipv6_nz lab requires "
                    "asset_descriptors_length 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_mpt_asset_id16_descriptors4) {
            if (mpt.value.table_length != 25u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_descriptors4 lab requires "
                    "table_length 25 (5-byte prefix + 20-byte asset)";
                return r;
            }
            auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(
                mpt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.number_of_assets != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_descriptors4 lab requires "
                    "number_of_assets 1";
                return r;
            }
            if (pref.bytes_consumed != 5u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix must be 5 octets "
                    "before mmt_si_mpt_asset_id16_descriptors4";
                return r;
            }
            const auto asset_span =
                mpt.value.payload.subspan(pref.bytes_consumed);
            auto asset =
                atsc3::mmt_si_mpt_asset_id16_descriptors4::decode(asset_span);
            if (!asset.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_descriptors4 decode failed: " +
                    asset.error;
                return r;
            }
            if (asset.bytes_consumed != asset_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_descriptors4 consumed " +
                    std::to_string(asset.bytes_consumed) + " of " +
                    std::to_string(asset_span.size()) +
                    " asset octets after MPT prefix";
                return r;
            }
            if (asset.value.asset_id_length != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_descriptors4 lab requires "
                    "asset_id_length 2";
                return r;
            }
            if (asset.value.asset_id_byte0 != 1u || asset.value.asset_id_byte1 != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_descriptors4 lab requires "
                    "asset_id 0x01 0x02";
                return r;
            }
            if (asset.value.location_count != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_descriptors4 lab requires "
                    "location_count 0";
                return r;
            }
            if (asset.value.asset_descriptors_length != 4u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_descriptors4 lab requires "
                    "asset_descriptors_length 4";
                return r;
            }
            if (asset.value.descriptor_byte0 != 0xDEu ||
                asset.value.descriptor_byte1 != 0xADu ||
                asset.value.descriptor_byte2 != 0xBEu ||
                asset.value.descriptor_byte3 != 0xEFu) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id16_descriptors4 lab requires "
                    "descriptor octets DE AD BE EF";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_mpt_asset_id8_descriptors4) {
            if (mpt.value.table_length != 24u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_descriptors4 lab requires "
                    "table_length 24 (5-byte prefix + 19-byte asset)";
                return r;
            }
            auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(
                mpt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.number_of_assets != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_descriptors4 lab requires "
                    "number_of_assets 1";
                return r;
            }
            if (pref.bytes_consumed != 5u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix must be 5 octets "
                    "before mmt_si_mpt_asset_id8_descriptors4";
                return r;
            }
            const auto asset_span =
                mpt.value.payload.subspan(pref.bytes_consumed);
            auto asset =
                atsc3::mmt_si_mpt_asset_id8_descriptors4::decode(asset_span);
            if (!asset.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_descriptors4 decode failed: " +
                    asset.error;
                return r;
            }
            if (asset.bytes_consumed != asset_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_descriptors4 consumed " +
                    std::to_string(asset.bytes_consumed) + " of " +
                    std::to_string(asset_span.size()) +
                    " asset octets after MPT prefix";
                return r;
            }
            if (asset.value.asset_id_length != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_descriptors4 lab requires "
                    "asset_id_length 1";
                return r;
            }
            if (asset.value.asset_id != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_descriptors4 lab requires "
                    "asset_id 1";
                return r;
            }
            if (asset.value.location_count != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_descriptors4 lab requires "
                    "location_count 0";
                return r;
            }
            if (asset.value.asset_descriptors_length != 4u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_descriptors4 lab requires "
                    "asset_descriptors_length 4";
                return r;
            }
            if (asset.value.descriptor_byte0 != 0xDEu ||
                asset.value.descriptor_byte1 != 0xADu ||
                asset.value.descriptor_byte2 != 0xBEu ||
                asset.value.descriptor_byte3 != 0xEFu) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_descriptors4 lab requires "
                    "descriptor octets DE AD BE EF";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_mpt_asset_location_ipv6) {
            if (mpt.value.table_length != 54u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv6 lab requires "
                    "table_length 54 (5-byte prefix + 49-byte asset)";
                return r;
            }
            auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(
                mpt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.number_of_assets != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv6 lab requires "
                    "number_of_assets 1";
                return r;
            }
            if (pref.bytes_consumed != 5u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix must be 5 octets "
                    "before mmt_si_mpt_asset_location_ipv6";
                return r;
            }
            const auto asset_span =
                mpt.value.payload.subspan(pref.bytes_consumed);
            auto asset =
                atsc3::mmt_si_mpt_asset_location_ipv6::decode(asset_span);
            if (!asset.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv6 decode failed: " +
                    asset.error;
                return r;
            }
            if (asset.bytes_consumed != asset_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv6 consumed " +
                    std::to_string(asset.bytes_consumed) + " of " +
                    std::to_string(asset_span.size()) +
                    " asset octets after MPT prefix";
                return r;
            }
            if (asset.value.asset_id_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv6 lab requires "
                    "asset_id_length 0";
                return r;
            }
            if (asset.value.location_count != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv6 lab requires "
                    "location_count 1";
                return r;
            }
            if (asset.value.location_type != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv6 lab requires "
                    "location_type 2";
                return r;
            }
            if (asset.value.ipv6_src_addr_0 != 0u ||
                asset.value.ipv6_src_addr_1 != 0u ||
                asset.value.ipv6_src_addr_2 != 0u ||
                asset.value.ipv6_src_addr_3 != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv6 lab requires "
                    "zero ipv6_src_addr words";
                return r;
            }
            if (asset.value.ipv6_dst_addr_0 != 0u ||
                asset.value.ipv6_dst_addr_1 != 0u ||
                asset.value.ipv6_dst_addr_2 != 0u ||
                asset.value.ipv6_dst_addr_3 != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv6 lab requires "
                    "zero ipv6_dst_addr words";
                return r;
            }
            if (asset.value.dst_port != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv6 lab requires "
                    "dst_port 0";
                return r;
            }
            if (asset.value.asset_descriptors_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv6 lab requires "
                    "asset_descriptors_length 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_mpt_asset_location_ipv6_nz) {
            if (mpt.value.table_length != 54u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv6_nz lab requires "
                    "table_length 54 (5-byte prefix + 49-byte asset)";
                return r;
            }
            auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(
                mpt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.number_of_assets != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv6_nz lab requires "
                    "number_of_assets 1";
                return r;
            }
            if (pref.bytes_consumed != 5u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix must be 5 octets "
                    "before mmt_si_mpt_asset_location_ipv6_nz";
                return r;
            }
            const auto asset_span =
                mpt.value.payload.subspan(pref.bytes_consumed);
            auto asset =
                atsc3::mmt_si_mpt_asset_location_ipv6_nz::decode(asset_span);
            if (!asset.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv6_nz decode failed: " +
                    asset.error;
                return r;
            }
            if (asset.bytes_consumed != asset_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv6_nz consumed " +
                    std::to_string(asset.bytes_consumed) + " of " +
                    std::to_string(asset_span.size()) +
                    " asset octets after MPT prefix";
                return r;
            }
            if (asset.value.asset_id_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv6_nz lab requires "
                    "asset_id_length 0";
                return r;
            }
            if (asset.value.location_count != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv6_nz lab requires "
                    "location_count 1";
                return r;
            }
            if (asset.value.location_type != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv6_nz lab requires "
                    "location_type 2";
                return r;
            }
            if (asset.value.ipv6_src_addr_0 != 0u ||
                asset.value.ipv6_src_addr_1 != 0u ||
                asset.value.ipv6_src_addr_2 != 0x0000FFFFu ||
                asset.value.ipv6_src_addr_3 != 0x0A000001u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv6_nz lab requires "
                    "ipv6_src_addr ::ffff:10.0.0.1";
                return r;
            }
            if (asset.value.ipv6_dst_addr_0 != 0u ||
                asset.value.ipv6_dst_addr_1 != 0u ||
                asset.value.ipv6_dst_addr_2 != 0x0000FFFFu ||
                asset.value.ipv6_dst_addr_3 != 0xE0000001u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv6_nz lab requires "
                    "ipv6_dst_addr ::ffff:224.0.0.1";
                return r;
            }
            if (asset.value.dst_port != 5000u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv6_nz lab requires "
                    "dst_port 5000";
                return r;
            }
            if (asset.value.asset_descriptors_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_location_ipv6_nz lab requires "
                    "asset_descriptors_length 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_mpt_asset_id8_location_ipv4) {
            if (mpt.value.table_length != 31u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv4 lab requires "
                    "table_length 31 (5-byte prefix + 26-byte asset)";
                return r;
            }
            auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(
                mpt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.number_of_assets != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv4 lab requires "
                    "number_of_assets 1";
                return r;
            }
            if (pref.bytes_consumed != 5u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix must be 5 octets "
                    "before mmt_si_mpt_asset_id8_location_ipv4";
                return r;
            }
            const auto asset_span =
                mpt.value.payload.subspan(pref.bytes_consumed);
            auto asset =
                atsc3::mmt_si_mpt_asset_id8_location_ipv4::decode(asset_span);
            if (!asset.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv4 decode failed: " +
                    asset.error;
                return r;
            }
            if (asset.bytes_consumed != asset_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv4 consumed " +
                    std::to_string(asset.bytes_consumed) + " of " +
                    std::to_string(asset_span.size()) +
                    " asset octets after MPT prefix";
                return r;
            }
            if (asset.value.asset_id_length != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv4 lab requires "
                    "asset_id_length 1";
                return r;
            }
            if (asset.value.asset_id != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv4 lab requires "
                    "asset_id 1";
                return r;
            }
            if (asset.value.location_count != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv4 lab requires "
                    "location_count 1";
                return r;
            }
            if (asset.value.location_type != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv4 lab requires "
                    "location_type 1";
                return r;
            }
            if (asset.value.ipv4_src_addr != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv4 lab requires "
                    "ipv4_src_addr 0";
                return r;
            }
            if (asset.value.ipv4_dst_addr != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv4 lab requires "
                    "ipv4_dst_addr 0";
                return r;
            }
            if (asset.value.dst_port != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv4 lab requires "
                    "dst_port 0";
                return r;
            }
            if (asset.value.asset_descriptors_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv4 lab requires "
                    "asset_descriptors_length 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_mpt_asset_id8_location_ipv6) {
            if (mpt.value.table_length != 55u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv6 lab requires "
                    "table_length 55 (5-byte prefix + 50-byte asset)";
                return r;
            }
            auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(
                mpt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.number_of_assets != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv6 lab requires "
                    "number_of_assets 1";
                return r;
            }
            if (pref.bytes_consumed != 5u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix must be 5 octets "
                    "before mmt_si_mpt_asset_id8_location_ipv6";
                return r;
            }
            const auto asset_span =
                mpt.value.payload.subspan(pref.bytes_consumed);
            auto asset =
                atsc3::mmt_si_mpt_asset_id8_location_ipv6::decode(asset_span);
            if (!asset.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv6 decode failed: " +
                    asset.error;
                return r;
            }
            if (asset.bytes_consumed != asset_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv6 consumed " +
                    std::to_string(asset.bytes_consumed) + " of " +
                    std::to_string(asset_span.size()) +
                    " asset octets after MPT prefix";
                return r;
            }
            if (asset.value.asset_id_length != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv6 lab requires "
                    "asset_id_length 1";
                return r;
            }
            if (asset.value.asset_id != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv6 lab requires "
                    "asset_id 1";
                return r;
            }
            if (asset.value.location_count != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv6 lab requires "
                    "location_count 1";
                return r;
            }
            if (asset.value.location_type != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv6 lab requires "
                    "location_type 2";
                return r;
            }
            if (asset.value.ipv6_src_addr_0 != 0u ||
                asset.value.ipv6_src_addr_1 != 0u ||
                asset.value.ipv6_src_addr_2 != 0u ||
                asset.value.ipv6_src_addr_3 != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv6 lab requires "
                    "zero ipv6_src_addr words";
                return r;
            }
            if (asset.value.ipv6_dst_addr_0 != 0u ||
                asset.value.ipv6_dst_addr_1 != 0u ||
                asset.value.ipv6_dst_addr_2 != 0u ||
                asset.value.ipv6_dst_addr_3 != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv6 lab requires "
                    "zero ipv6_dst_addr words";
                return r;
            }
            if (asset.value.dst_port != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv6 lab requires "
                    "dst_port 0";
                return r;
            }
            if (asset.value.asset_descriptors_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_id8_location_ipv6 lab requires "
                    "asset_descriptors_length 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_mpt_asset_descriptors4) {
            if (mpt.value.table_length != 23u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_descriptors4 lab requires "
                    "table_length 23 (5-byte prefix + 18-byte asset)";
                return r;
            }
            auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(
                mpt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.number_of_assets != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_descriptors4 lab requires "
                    "number_of_assets 1";
                return r;
            }
            if (pref.bytes_consumed != 5u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_table_body_prefix must be 5 octets "
                    "before mmt_si_mpt_asset_descriptors4";
                return r;
            }
            const auto asset_span =
                mpt.value.payload.subspan(pref.bytes_consumed);
            auto asset =
                atsc3::mmt_si_mpt_asset_descriptors4::decode(asset_span);
            if (!asset.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_descriptors4 decode failed: " +
                    asset.error;
                return r;
            }
            if (asset.bytes_consumed != asset_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_descriptors4 consumed " +
                    std::to_string(asset.bytes_consumed) + " of " +
                    std::to_string(asset_span.size()) +
                    " asset octets after MPT prefix";
                return r;
            }
            if (asset.value.asset_id_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_descriptors4 lab requires "
                    "asset_id_length 0";
                return r;
            }
            if (asset.value.location_count != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_descriptors4 lab requires "
                    "location_count 0";
                return r;
            }
            if (asset.value.asset_descriptors_length != 4u) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_descriptors4 lab requires "
                    "asset_descriptors_length 4";
                return r;
            }
            if (asset.value.descriptor_byte0 != 0xDEu ||
                asset.value.descriptor_byte1 != 0xADu ||
                asset.value.descriptor_byte2 != 0xBEu ||
                asset.value.descriptor_byte3 != 0xEFu) {
                r.error =
                    "encoder_pipeline: mmt_si_mpt_asset_descriptors4 lab requires "
                    "descriptor octets DE AD BE EF";
                return r;
            }
        }
    }

    if (_cfg.validate_mmt_si_mpt_table_body_prefix &&
        !_cfg.validate_mmt_si_mpt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_table_body_prefix requires "
            "validate_mmt_si_mpt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset && !_cfg.validate_mmt_si_mpt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset requires "
            "validate_mmt_si_mpt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset &&
        _cfg.validate_mmt_si_mpt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset and "
            "validate_mmt_si_mpt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8 &&
        !_cfg.validate_mmt_si_mpt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8 requires "
            "validate_mmt_si_mpt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id16 &&
        !_cfg.validate_mmt_si_mpt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16 requires "
            "validate_mmt_si_mpt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id16 &&
        _cfg.validate_mmt_si_mpt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16 and "
            "validate_mmt_si_mpt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8 &&
        _cfg.validate_mmt_si_mpt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8 and "
            "validate_mmt_si_mpt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset &&
        _cfg.validate_mmt_si_mpt_asset_id8) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset and "
            "validate_mmt_si_mpt_asset_id8 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset &&
        _cfg.validate_mmt_si_mpt_asset_id16) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset and "
            "validate_mmt_si_mpt_asset_id16 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location0 &&
        !_cfg.validate_mmt_si_mpt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location0 requires "
            "validate_mmt_si_mpt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location0 &&
        _cfg.validate_mmt_si_mpt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location0 and "
            "validate_mmt_si_mpt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset &&
        _cfg.validate_mmt_si_mpt_asset_location0) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset and "
            "validate_mmt_si_mpt_asset_location0 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8 &&
        _cfg.validate_mmt_si_mpt_asset_location0) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8 and "
            "validate_mmt_si_mpt_asset_location0 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8 &&
        _cfg.validate_mmt_si_mpt_asset_id16) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8 and "
            "validate_mmt_si_mpt_asset_id16 are mutually exclusive";
        return r;
    }


    if (_cfg.validate_mmt_si_mpt_asset_location_ipv4 &&
        !_cfg.validate_mmt_si_mpt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location_ipv4 requires "
            "validate_mmt_si_mpt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location_ipv4_nz &&
        !_cfg.validate_mmt_si_mpt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location_ipv4_nz requires "
            "validate_mmt_si_mpt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location_ipv4_nz and "
            "validate_mmt_si_mpt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location_ipv4 and "
            "validate_mmt_si_mpt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset and "
            "validate_mmt_si_mpt_asset_location_ipv4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset and "
            "validate_mmt_si_mpt_asset_location_ipv4_nz are mutually exclusive";
        return r;
    }


    if (_cfg.validate_mmt_si_mpt_asset_id8 &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8 and "
            "validate_mmt_si_mpt_asset_location_ipv4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id8 &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8 and "
            "validate_mmt_si_mpt_asset_location_ipv4_nz are mutually exclusive";
        return r;
    }


    if (_cfg.validate_mmt_si_mpt_asset_location0 &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location0 and "
            "validate_mmt_si_mpt_asset_location_ipv4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_location0 &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location0 and "
            "validate_mmt_si_mpt_asset_location_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8_location_ipv4_nz &&
        !_cfg.validate_mmt_si_mpt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_location_ipv4_nz requires "
            "validate_mmt_si_mpt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_location_ipv4_nz and "
            "validate_mmt_si_mpt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset and "
            "validate_mmt_si_mpt_asset_id8_location_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location0 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location0 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location_ipv4 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location_ipv4_nz and "
            "validate_mmt_si_mpt_asset_id8_location_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_location_ipv4 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8_location_ipv6_nz &&
        !_cfg.validate_mmt_si_mpt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_location_ipv6_nz requires "
            "validate_mmt_si_mpt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8_location_ipv6_nz &&
        _cfg.validate_mmt_si_mpt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_location_ipv6_nz and "
            "validate_mmt_si_mpt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location0 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location0 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location_ipv4 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location_ipv4_nz and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_location_ipv4_nz and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location_ipv6 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location_ipv6_nz &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location_ipv6_nz and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_location_ipv6 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8_location_ipv4 &&
        !_cfg.validate_mmt_si_mpt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_location_ipv4 requires "
            "validate_mmt_si_mpt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_location_ipv4 and "
            "validate_mmt_si_mpt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset and "
            "validate_mmt_si_mpt_asset_id8_location_ipv4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location0 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location0 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location_ipv4 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location_ipv6 &&
        !_cfg.validate_mmt_si_mpt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location_ipv6 requires "
            "validate_mmt_si_mpt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location_ipv6 and "
            "validate_mmt_si_mpt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset and "
            "validate_mmt_si_mpt_asset_location_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8 &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8 and "
            "validate_mmt_si_mpt_asset_location_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location0 &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location0 and "
            "validate_mmt_si_mpt_asset_location_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location_ipv4 and "
            "validate_mmt_si_mpt_asset_location_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location_ipv4 and "
            "validate_mmt_si_mpt_asset_location_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location_ipv6_nz &&
        !_cfg.validate_mmt_si_mpt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location_ipv6_nz requires "
            "validate_mmt_si_mpt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location_ipv6_nz &&
        _cfg.validate_mmt_si_mpt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location_ipv6_nz and "
            "validate_mmt_si_mpt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset and "
            "validate_mmt_si_mpt_asset_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8 &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8 and "
            "validate_mmt_si_mpt_asset_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location0 &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location0 and "
            "validate_mmt_si_mpt_asset_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location_ipv6 and "
            "validate_mmt_si_mpt_asset_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location_ipv4_nz and "
            "validate_mmt_si_mpt_asset_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_location_ipv4_nz and "
            "validate_mmt_si_mpt_asset_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location_ipv6 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8_location_ipv6 &&
        !_cfg.validate_mmt_si_mpt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_location_ipv6 requires "
            "validate_mmt_si_mpt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_location_ipv6 and "
            "validate_mmt_si_mpt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location0 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location0 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location_ipv4 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location_ipv6 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_location_ipv4 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_location_ipv4_nz and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_location_ipv4_nz and "
            "validate_mmt_si_mpt_asset_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_location_ipv4_nz and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8_location_ipv6_nz &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_location_ipv6_nz and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location_ipv6 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_descriptors4 &&
        !_cfg.validate_mmt_si_mpt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_descriptors4 requires "
            "validate_mmt_si_mpt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_descriptors4 &&
        _cfg.validate_mmt_si_mpt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_descriptors4 and "
            "validate_mmt_si_mpt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset &&
        _cfg.validate_mmt_si_mpt_asset_descriptors4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset and "
            "validate_mmt_si_mpt_asset_descriptors4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8 &&
        _cfg.validate_mmt_si_mpt_asset_descriptors4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8 and "
            "validate_mmt_si_mpt_asset_descriptors4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location0 &&
        _cfg.validate_mmt_si_mpt_asset_descriptors4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location0 and "
            "validate_mmt_si_mpt_asset_descriptors4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset_descriptors4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location_ipv4 and "
            "validate_mmt_si_mpt_asset_descriptors4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_asset_descriptors4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_location_ipv6 and "
            "validate_mmt_si_mpt_asset_descriptors4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset_descriptors4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_location_ipv4 and "
            "validate_mmt_si_mpt_asset_descriptors4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_asset_descriptors4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_location_ipv4_nz and "
            "validate_mmt_si_mpt_asset_descriptors4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8_location_ipv6_nz &&
        _cfg.validate_mmt_si_mpt_asset_descriptors4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_location_ipv6_nz and "
            "validate_mmt_si_mpt_asset_descriptors4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4 &&
        !_cfg.validate_mmt_si_mpt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4 requires "
            "validate_mmt_si_mpt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4 and "
            "validate_mmt_si_mpt_table_body_prefix are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz &&
        !_cfg.validate_mmt_si_mpt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4_nz requires "
            "validate_mmt_si_mpt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4_nz and "
            "validate_mmt_si_mpt_table_body_prefix are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6 &&
        !_cfg.validate_mmt_si_mpt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6 requires "
            "validate_mmt_si_mpt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6 and "
            "validate_mmt_si_mpt_table_body_prefix are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz &&
        !_cfg.validate_mmt_si_mpt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6_nz requires "
            "validate_mmt_si_mpt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz &&
        _cfg.validate_mmt_si_mpt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6_nz and "
            "validate_mmt_si_mpt_table_body_prefix are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_descriptors4 &&
        !_cfg.validate_mmt_si_mpt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_descriptors4 requires "
            "validate_mmt_si_mpt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id16_descriptors4 &&
        _cfg.validate_mmt_si_mpt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_descriptors4 and "
            "validate_mmt_si_mpt_table_body_prefix are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id8_descriptors4 &&
        !_cfg.validate_mmt_si_mpt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_descriptors4 requires "
            "validate_mmt_si_mpt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_mpt_asset_id8_descriptors4 &&
        _cfg.validate_mmt_si_mpt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_descriptors4 and "
            "validate_mmt_si_mpt_table_body_prefix are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4 and "
            "validate_mmt_si_mpt_asset are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset_descriptors4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4 and "
            "validate_mmt_si_mpt_asset_descriptors4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset_id8) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4 and "
            "validate_mmt_si_mpt_asset_id8 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset_id16) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4 and "
            "validate_mmt_si_mpt_asset_id16 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset_location0) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4 and "
            "validate_mmt_si_mpt_asset_location0 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4 and "
            "validate_mmt_si_mpt_asset_location_ipv4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4 and "
            "validate_mmt_si_mpt_asset_location_ipv4_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4 and "
            "validate_mmt_si_mpt_asset_location_ipv6 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4 and "
            "validate_mmt_si_mpt_asset_location_ipv6_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv4_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4 and "
            "validate_mmt_si_mpt_asset_id16_location_ipv4_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset_id16_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4 and "
            "validate_mmt_si_mpt_asset_id16_location_ipv6 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4 and "
            "validate_mmt_si_mpt_asset_id16_location_ipv6_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset_id16_descriptors4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4 and "
            "validate_mmt_si_mpt_asset_id16_descriptors4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4 &&
        _cfg.validate_mmt_si_mpt_asset_id8_descriptors4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4 and "
            "validate_mmt_si_mpt_asset_id8_descriptors4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_asset) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4_nz and "
            "validate_mmt_si_mpt_asset are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_asset_descriptors4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4_nz and "
            "validate_mmt_si_mpt_asset_descriptors4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_asset_id8) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4_nz and "
            "validate_mmt_si_mpt_asset_id8 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_asset_id16) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4_nz and "
            "validate_mmt_si_mpt_asset_id16 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_asset_location0) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4_nz and "
            "validate_mmt_si_mpt_asset_location0 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4_nz and "
            "validate_mmt_si_mpt_asset_location_ipv4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4_nz and "
            "validate_mmt_si_mpt_asset_location_ipv4_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4_nz and "
            "validate_mmt_si_mpt_asset_location_ipv6 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4_nz and "
            "validate_mmt_si_mpt_asset_location_ipv6_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4_nz and "
            "validate_mmt_si_mpt_asset_id8_location_ipv4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4_nz and "
            "validate_mmt_si_mpt_asset_id8_location_ipv4_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4_nz and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4_nz and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_asset_id16_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4_nz and "
            "validate_mmt_si_mpt_asset_id16_location_ipv4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_asset_id16_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4_nz and "
            "validate_mmt_si_mpt_asset_id16_location_ipv6 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4_nz and "
            "validate_mmt_si_mpt_asset_id16_location_ipv6_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_asset_id16_descriptors4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4_nz and "
            "validate_mmt_si_mpt_asset_id16_descriptors4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz &&
        _cfg.validate_mmt_si_mpt_asset_id8_descriptors4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv4_nz and "
            "validate_mmt_si_mpt_asset_id8_descriptors4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_asset) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6 and "
            "validate_mmt_si_mpt_asset are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_asset_descriptors4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6 and "
            "validate_mmt_si_mpt_asset_descriptors4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_asset_id8) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6 and "
            "validate_mmt_si_mpt_asset_id8 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_asset_id16) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6 and "
            "validate_mmt_si_mpt_asset_id16 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_asset_location0) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6 and "
            "validate_mmt_si_mpt_asset_location0 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6 and "
            "validate_mmt_si_mpt_asset_location_ipv4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6 and "
            "validate_mmt_si_mpt_asset_location_ipv4_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6 and "
            "validate_mmt_si_mpt_asset_location_ipv6 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6 and "
            "validate_mmt_si_mpt_asset_location_ipv6_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv4_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_asset_id16_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6 and "
            "validate_mmt_si_mpt_asset_id16_location_ipv4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6 and "
            "validate_mmt_si_mpt_asset_id16_location_ipv4_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6 and "
            "validate_mmt_si_mpt_asset_id16_location_ipv6_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_asset_id16_descriptors4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6 and "
            "validate_mmt_si_mpt_asset_id16_descriptors4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6 &&
        _cfg.validate_mmt_si_mpt_asset_id8_descriptors4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6 and "
            "validate_mmt_si_mpt_asset_id8_descriptors4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz &&
        _cfg.validate_mmt_si_mpt_asset) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6_nz and "
            "validate_mmt_si_mpt_asset are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz &&
        _cfg.validate_mmt_si_mpt_asset_descriptors4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6_nz and "
            "validate_mmt_si_mpt_asset_descriptors4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz &&
        _cfg.validate_mmt_si_mpt_asset_id8) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6_nz and "
            "validate_mmt_si_mpt_asset_id8 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz &&
        _cfg.validate_mmt_si_mpt_asset_id16) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6_nz and "
            "validate_mmt_si_mpt_asset_id16 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz &&
        _cfg.validate_mmt_si_mpt_asset_location0) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6_nz and "
            "validate_mmt_si_mpt_asset_location0 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6_nz and "
            "validate_mmt_si_mpt_asset_location_ipv4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6_nz and "
            "validate_mmt_si_mpt_asset_location_ipv4_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6_nz and "
            "validate_mmt_si_mpt_asset_location_ipv6 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6_nz and "
            "validate_mmt_si_mpt_asset_location_ipv6_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6_nz and "
            "validate_mmt_si_mpt_asset_id8_location_ipv4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6_nz and "
            "validate_mmt_si_mpt_asset_id8_location_ipv4_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6_nz and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6_nz and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz &&
        _cfg.validate_mmt_si_mpt_asset_id16_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6_nz and "
            "validate_mmt_si_mpt_asset_id16_location_ipv4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz &&
        _cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6_nz and "
            "validate_mmt_si_mpt_asset_id16_location_ipv4_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz &&
        _cfg.validate_mmt_si_mpt_asset_id16_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6_nz and "
            "validate_mmt_si_mpt_asset_id16_location_ipv6 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz &&
        _cfg.validate_mmt_si_mpt_asset_id16_descriptors4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6_nz and "
            "validate_mmt_si_mpt_asset_id16_descriptors4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz &&
        _cfg.validate_mmt_si_mpt_asset_id8_descriptors4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_location_ipv6_nz and "
            "validate_mmt_si_mpt_asset_id8_descriptors4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_descriptors4 and "
            "validate_mmt_si_mpt_asset are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_descriptors4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_descriptors4 and "
            "validate_mmt_si_mpt_asset_descriptors4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_id8) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_descriptors4 and "
            "validate_mmt_si_mpt_asset_id8 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_id16) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_descriptors4 and "
            "validate_mmt_si_mpt_asset_id16 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_location0) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_descriptors4 and "
            "validate_mmt_si_mpt_asset_location0 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_descriptors4 and "
            "validate_mmt_si_mpt_asset_location_ipv4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_descriptors4 and "
            "validate_mmt_si_mpt_asset_location_ipv4_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_descriptors4 and "
            "validate_mmt_si_mpt_asset_location_ipv6 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_descriptors4 and "
            "validate_mmt_si_mpt_asset_location_ipv6_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_descriptors4 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_descriptors4 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv4_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_descriptors4 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_descriptors4 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_id16_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_descriptors4 and "
            "validate_mmt_si_mpt_asset_id16_location_ipv4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_descriptors4 and "
            "validate_mmt_si_mpt_asset_id16_location_ipv4_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_id16_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_descriptors4 and "
            "validate_mmt_si_mpt_asset_id16_location_ipv6 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_descriptors4 and "
            "validate_mmt_si_mpt_asset_id16_location_ipv6_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id16_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_id8_descriptors4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id16_descriptors4 and "
            "validate_mmt_si_mpt_asset_id8_descriptors4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id8_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_descriptors4 and "
            "validate_mmt_si_mpt_asset are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id8_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_descriptors4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_descriptors4 and "
            "validate_mmt_si_mpt_asset_descriptors4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id8_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_id8) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_descriptors4 and "
            "validate_mmt_si_mpt_asset_id8 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id8_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_id16) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_descriptors4 and "
            "validate_mmt_si_mpt_asset_id16 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id8_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_location0) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_descriptors4 and "
            "validate_mmt_si_mpt_asset_location0 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id8_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_descriptors4 and "
            "validate_mmt_si_mpt_asset_location_ipv4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id8_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_descriptors4 and "
            "validate_mmt_si_mpt_asset_location_ipv4_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id8_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_descriptors4 and "
            "validate_mmt_si_mpt_asset_location_ipv6 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id8_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_descriptors4 and "
            "validate_mmt_si_mpt_asset_location_ipv6_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id8_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_descriptors4 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id8_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_descriptors4 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv4_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id8_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_descriptors4 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id8_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_descriptors4 and "
            "validate_mmt_si_mpt_asset_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id8_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_id16_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_descriptors4 and "
            "validate_mmt_si_mpt_asset_id16_location_ipv4 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id8_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_descriptors4 and "
            "validate_mmt_si_mpt_asset_id16_location_ipv4_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id8_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_id16_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_descriptors4 and "
            "validate_mmt_si_mpt_asset_id16_location_ipv6 are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id8_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_descriptors4 and "
            "validate_mmt_si_mpt_asset_id16_location_ipv6_nz are mutually exclusive";
        return r;
    }
    if (_cfg.validate_mmt_si_mpt_asset_id8_descriptors4 &&
        _cfg.validate_mmt_si_mpt_asset_id16_descriptors4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_mpt_asset_id8_descriptors4 and "
            "validate_mmt_si_mpt_asset_id16_descriptors4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_table_body) {
        const auto view =
            ingress_for_si_table_validate(payload, _cfg, plt_table_fully_decodes);
        if (!view.ok) {
            r.error = "encoder_pipeline: mmt_si_plt_table ingress layout: " +
                      view.error;
            return r;
        }
        const auto table_payload = view.table_bytes;
        auto       plt           = atsc3::mmt_si_plt_table::decode(table_payload);
        if (!plt.ok) {
            r.error = "encoder_pipeline: mmt_si_plt_table decode failed: " +
                      plt.error;
            return r;
        }
        if (plt.bytes_consumed != table_payload.size()) {
            r.error =
                "encoder_pipeline: mmt_si_plt_table decode consumed " +
                std::to_string(plt.bytes_consumed) + " of " +
                std::to_string(table_payload.size()) + " ingress octets";
            return r;
        }
        if (plt.value.table_id != 128u) {
            r.error =
                "encoder_pipeline: mmt_si_plt_table table_id must be 0x80 (128)";
            return r;
        }
        if (_cfg.validate_mmt_si_plt_table_body_prefix) {
            if (plt.value.table_length != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix lab requires "
                    "table_length 2 (minimal PLT prefix)";
                return r;
            }
            auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(
                plt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.bytes_consumed != plt.value.payload.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix consumed " +
                    std::to_string(pref.bytes_consumed) + " of " +
                    std::to_string(plt.value.payload.size()) +
                    " PLT table_length octets";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_plt_delivery_info) {
            if (plt.value.table_length != 9u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info lab requires "
                    "table_length 9 (2-byte prefix + 7-byte DeliveryInfo)";
                return r;
            }
            auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(
                plt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.num_of_packages != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info lab requires "
                    "num_of_packages 0";
                return r;
            }
            if (pref.value.num_of_ip_delivery != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info lab requires "
                    "num_of_ip_delivery 1";
                return r;
            }
            if (pref.bytes_consumed != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix must be 2 octets "
                    "before mmt_si_plt_delivery_info";
                return r;
            }
            const auto delivery_span =
                plt.value.payload.subspan(pref.bytes_consumed);
            auto delivery = atsc3::mmt_si_plt_delivery_info::decode(delivery_span);
            if (!delivery.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info decode failed: " +
                    delivery.error;
                return r;
            }
            if (delivery.bytes_consumed != delivery_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info consumed " +
                    std::to_string(delivery.bytes_consumed) + " of " +
                    std::to_string(delivery_span.size()) +
                    " DeliveryInfo octets after PLT prefix";
                return r;
            }
            if (delivery.value.location_type != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info lab requires "
                    "location_type 0";
                return r;
            }
            if (delivery.value.descripor_loop_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info lab requires "
                    "descripor_loop_length 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_plt_delivery_info_ipv4) {
            if (plt.value.table_length != 19u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_ipv4 lab requires "
                    "table_length 19 (2-byte prefix + 17-byte IPv4 DeliveryInfo)";
                return r;
            }
            auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(
                plt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.num_of_packages != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_ipv4 lab requires "
                    "num_of_packages 0";
                return r;
            }
            if (pref.value.num_of_ip_delivery != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_ipv4 lab requires "
                    "num_of_ip_delivery 1";
                return r;
            }
            if (pref.bytes_consumed != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix must be 2 octets "
                    "before mmt_si_plt_delivery_info_ipv4";
                return r;
            }
            const auto delivery_span =
                plt.value.payload.subspan(pref.bytes_consumed);
            auto delivery =
                atsc3::mmt_si_plt_delivery_info_ipv4::decode(delivery_span);
            if (!delivery.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_ipv4 decode failed: " +
                    delivery.error;
                return r;
            }
            if (delivery.bytes_consumed != delivery_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_ipv4 consumed " +
                    std::to_string(delivery.bytes_consumed) + " of " +
                    std::to_string(delivery_span.size()) +
                    " IPv4 DeliveryInfo octets after PLT prefix";
                return r;
            }
            if (delivery.value.location_type != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_ipv4 lab requires "
                    "location_type 1";
                return r;
            }
            if (delivery.value.descripor_loop_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_ipv4 lab requires "
                    "descripor_loop_length 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_plt_delivery_info_ipv4_nz) {
            if (plt.value.table_length != 19u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_ipv4_nz lab requires "
                    "table_length 19 (2-byte prefix + 17-byte IPv4 DeliveryInfo)";
                return r;
            }
            auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(
                plt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.num_of_packages != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_ipv4_nz lab requires "
                    "num_of_packages 0";
                return r;
            }
            if (pref.value.num_of_ip_delivery != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_ipv4_nz lab requires "
                    "num_of_ip_delivery 1";
                return r;
            }
            if (pref.bytes_consumed != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix must be 2 octets "
                    "before mmt_si_plt_delivery_info_ipv4_nz";
                return r;
            }
            const auto delivery_span =
                plt.value.payload.subspan(pref.bytes_consumed);
            auto delivery =
                atsc3::mmt_si_plt_delivery_info_ipv4_nz::decode(delivery_span);
            if (!delivery.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_ipv4_nz decode failed: " +
                    delivery.error;
                return r;
            }
            if (delivery.bytes_consumed != delivery_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_ipv4_nz consumed " +
                    std::to_string(delivery.bytes_consumed) + " of " +
                    std::to_string(delivery_span.size()) +
                    " IPv4 DeliveryInfo octets after PLT prefix";
                return r;
            }
            if (delivery.value.location_type != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_ipv4_nz lab requires "
                    "location_type 1";
                return r;
            }
            if (delivery.value.ipv4_src_addr != 0x0A000001u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_ipv4_nz lab requires "
                    "ipv4_src_addr 10.0.0.1";
                return r;
            }
            if (delivery.value.ipv4_dst_addr != 0xE0000001u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_ipv4_nz lab requires "
                    "ipv4_dst_addr 224.0.0.1";
                return r;
            }
            if (delivery.value.dst_port != 5000u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_ipv4_nz lab requires "
                    "dst_port 5000";
                return r;
            }
            if (delivery.value.descripor_loop_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_ipv4_nz lab requires "
                    "descripor_loop_length 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_plt_delivery_info_ipv6) {
            if (plt.value.table_length != 43u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_ipv6 lab requires "
                    "table_length 43 (2-byte prefix + 41-byte IPv6 DeliveryInfo)";
                return r;
            }
            auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(
                plt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.num_of_packages != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_ipv6 lab requires "
                    "num_of_packages 0";
                return r;
            }
            if (pref.value.num_of_ip_delivery != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_ipv6 lab requires "
                    "num_of_ip_delivery 1";
                return r;
            }
            if (pref.bytes_consumed != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix must be 2 octets "
                    "before mmt_si_plt_delivery_info_ipv6";
                return r;
            }
            const auto delivery_span =
                plt.value.payload.subspan(pref.bytes_consumed);
            auto delivery =
                atsc3::mmt_si_plt_delivery_info_ipv6::decode(delivery_span);
            if (!delivery.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_ipv6 decode failed: " +
                    delivery.error;
                return r;
            }
            if (delivery.bytes_consumed != delivery_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_ipv6 consumed " +
                    std::to_string(delivery.bytes_consumed) + " of " +
                    std::to_string(delivery_span.size()) +
                    " IPv6 DeliveryInfo octets after PLT prefix";
                return r;
            }
            if (delivery.value.location_type != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_ipv6 lab requires "
                    "location_type 2";
                return r;
            }
            if (delivery.value.descripor_loop_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_ipv6 lab requires "
                    "descripor_loop_length 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_plt_delivery_info_url) {
            if (plt.value.table_length != 10u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_url lab requires "
                    "table_length 10 (2-byte prefix + 8-byte URL DeliveryInfo)";
                return r;
            }
            auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(
                plt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.num_of_packages != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_url lab requires "
                    "num_of_packages 0";
                return r;
            }
            if (pref.value.num_of_ip_delivery != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_url lab requires "
                    "num_of_ip_delivery 1";
                return r;
            }
            if (pref.bytes_consumed != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix must be 2 octets "
                    "before mmt_si_plt_delivery_info_url";
                return r;
            }
            const auto delivery_span =
                plt.value.payload.subspan(pref.bytes_consumed);
            auto delivery = atsc3::mmt_si_plt_delivery_info_url::decode(delivery_span);
            if (!delivery.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_url decode failed: " +
                    delivery.error;
                return r;
            }
            if (delivery.bytes_consumed != delivery_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_url consumed " +
                    std::to_string(delivery.bytes_consumed) + " of " +
                    std::to_string(delivery_span.size()) +
                    " URL DeliveryInfo octets after PLT prefix";
                return r;
            }
            if (delivery.value.location_type != 5u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_url lab requires "
                    "location_type 5";
                return r;
            }
            if (delivery.value.url_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_url lab requires "
                    "url_length 0";
                return r;
            }
            if (delivery.value.descripor_loop_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_url lab requires "
                    "descripor_loop_length 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_plt_delivery_info_url_3) {
            if (plt.value.table_length != 13u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_url_3 lab requires "
                    "table_length 13 (2-byte prefix + 11-byte URL DeliveryInfo)";
                return r;
            }
            auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(
                plt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.num_of_packages != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_url_3 lab requires "
                    "num_of_packages 0";
                return r;
            }
            if (pref.value.num_of_ip_delivery != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_url_3 lab requires "
                    "num_of_ip_delivery 1";
                return r;
            }
            if (pref.bytes_consumed != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix must be 2 octets "
                    "before mmt_si_plt_delivery_info_url_3";
                return r;
            }
            const auto delivery_span =
                plt.value.payload.subspan(pref.bytes_consumed);
            auto delivery =
                atsc3::mmt_si_plt_delivery_info_url_3::decode(delivery_span);
            if (!delivery.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_url_3 decode failed: " +
                    delivery.error;
                return r;
            }
            if (delivery.bytes_consumed != delivery_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_url_3 consumed " +
                    std::to_string(delivery.bytes_consumed) + " of " +
                    std::to_string(delivery_span.size()) +
                    " URL DeliveryInfo octets after PLT prefix";
                return r;
            }
            if (delivery.value.location_type != 5u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_url_3 lab requires "
                    "location_type 5";
                return r;
            }
            if (delivery.value.url_length != 3u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_url_3 lab requires "
                    "url_length 3";
                return r;
            }
            if (delivery.value.url_byte0 != 0x6Cu || delivery.value.url_byte1 != 0x61u ||
                delivery.value.url_byte2 != 0x62u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_url_3 lab requires "
                    "URL octets 6c 61 62 (lab)";
                return r;
            }
            if (delivery.value.descripor_loop_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_url_3 lab requires "
                    "descripor_loop_length 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_plt_delivery_info_url_4) {
            if (plt.value.table_length != 14u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_url_4 lab requires "
                    "table_length 14 (2-byte prefix + 12-byte URL DeliveryInfo)";
                return r;
            }
            auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(
                plt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.num_of_packages != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_url_4 lab requires "
                    "num_of_packages 0";
                return r;
            }
            if (pref.value.num_of_ip_delivery != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_url_4 lab requires "
                    "num_of_ip_delivery 1";
                return r;
            }
            if (pref.bytes_consumed != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix must be 2 octets "
                    "before mmt_si_plt_delivery_info_url_4";
                return r;
            }
            const auto delivery_span =
                plt.value.payload.subspan(pref.bytes_consumed);
            auto delivery =
                atsc3::mmt_si_plt_delivery_info_url_4::decode(delivery_span);
            if (!delivery.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_url_4 decode failed: " +
                    delivery.error;
                return r;
            }
            if (delivery.bytes_consumed != delivery_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_url_4 consumed " +
                    std::to_string(delivery.bytes_consumed) + " of " +
                    std::to_string(delivery_span.size()) +
                    " URL DeliveryInfo octets after PLT prefix";
                return r;
            }
            if (delivery.value.location_type != 5u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_url_4 lab requires "
                    "location_type 5";
                return r;
            }
            if (delivery.value.url_length != 4u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_url_4 lab requires "
                    "url_length 4";
                return r;
            }
            if (delivery.value.url_byte0 != 0x68u ||
                delivery.value.url_byte1 != 0x74u ||
                delivery.value.url_byte2 != 0x74u ||
                delivery.value.url_byte3 != 0x70u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_url_4 lab requires "
                    "URL octets 68 74 74 70 (http)";
                return r;
            }
            if (delivery.value.descripor_loop_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_delivery_info_url_4 lab requires "
                    "descripor_loop_length 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_plt_package_entry) {
            if (plt.value.table_length != 6u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry lab requires "
                    "table_length 6 (2-byte prefix + 4-byte package entry)";
                return r;
            }
            auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(
                plt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.num_of_packages != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry lab requires "
                    "num_of_packages 1";
                return r;
            }
            if (pref.value.num_of_ip_delivery != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry lab requires "
                    "num_of_ip_delivery 0";
                return r;
            }
            if (pref.bytes_consumed != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix must be 2 octets "
                    "before mmt_si_plt_package_entry";
                return r;
            }
            const auto entry_span =
                plt.value.payload.subspan(pref.bytes_consumed);
            auto entry = atsc3::mmt_si_plt_package_entry::decode(entry_span);
            if (!entry.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry decode failed: " +
                    entry.error;
                return r;
            }
            if (entry.bytes_consumed != entry_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry consumed " +
                    std::to_string(entry.bytes_consumed) + " of " +
                    std::to_string(entry_span.size()) +
                    " package entry octets after PLT prefix";
                return r;
            }
            if (entry.value.MMT_package_id_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry lab requires "
                    "MMT_package_id_length 0";
                return r;
            }
            if (entry.value.location_type != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry lab requires "
                    "location_type 0";
                return r;
            }
            if (entry.value.packet_id != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry lab requires "
                    "packet_id 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_plt_package_entry_id8) {
            if (plt.value.table_length != 7u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8 lab requires "
                    "table_length 7 (2-byte prefix + 5-byte package entry)";
                return r;
            }
            auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(
                plt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.num_of_packages != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8 lab requires "
                    "num_of_packages 1";
                return r;
            }
            if (pref.value.num_of_ip_delivery != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8 lab requires "
                    "num_of_ip_delivery 0";
                return r;
            }
            if (pref.bytes_consumed != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix must be 2 octets "
                    "before mmt_si_plt_package_entry_id8";
                return r;
            }
            const auto entry_span =
                plt.value.payload.subspan(pref.bytes_consumed);
            auto entry =
                atsc3::mmt_si_plt_package_entry_id8::decode(entry_span);
            if (!entry.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8 decode failed: " +
                    entry.error;
                return r;
            }
            if (entry.bytes_consumed != entry_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8 consumed " +
                    std::to_string(entry.bytes_consumed) + " of " +
                    std::to_string(entry_span.size()) +
                    " package entry octets after PLT prefix";
                return r;
            }
            if (entry.value.MMT_package_id_length != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8 lab requires "
                    "MMT_package_id_length 1";
                return r;
            }
            if (entry.value.MMT_package_id != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8 lab requires "
                    "MMT_package_id 1";
                return r;
            }
            if (entry.value.location_type != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8 lab requires "
                    "location_type 0";
                return r;
            }
            if (entry.value.packet_id != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8 lab requires "
                    "packet_id 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_plt_package_entry_ipv4) {
            if (plt.value.table_length != 14u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv4 lab requires "
                    "table_length 14 (2-byte prefix + 12-byte package entry)";
                return r;
            }
            auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(
                plt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.num_of_packages != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv4 lab requires "
                    "num_of_packages 1";
                return r;
            }
            if (pref.value.num_of_ip_delivery != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv4 lab requires "
                    "num_of_ip_delivery 0";
                return r;
            }
            if (pref.bytes_consumed != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix must be 2 octets "
                    "before mmt_si_plt_package_entry_ipv4";
                return r;
            }
            const auto entry_span =
                plt.value.payload.subspan(pref.bytes_consumed);
            auto entry =
                atsc3::mmt_si_plt_package_entry_ipv4::decode(entry_span);
            if (!entry.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv4 decode failed: " +
                    entry.error;
                return r;
            }
            if (entry.bytes_consumed != entry_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv4 consumed " +
                    std::to_string(entry.bytes_consumed) + " of " +
                    std::to_string(entry_span.size()) +
                    " package entry octets after PLT prefix";
                return r;
            }
            if (entry.value.MMT_package_id_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv4 lab requires "
                    "MMT_package_id_length 0";
                return r;
            }
            if (entry.value.location_type != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv4 lab requires "
                    "location_type 1";
                return r;
            }
            if (entry.value.ipv4_src_addr != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv4 lab requires "
                    "ipv4_src_addr 0";
                return r;
            }
            if (entry.value.ipv4_dst_addr != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv4 lab requires "
                    "ipv4_dst_addr 0";
                return r;
            }
            if (entry.value.dst_port != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv4 lab requires "
                    "dst_port 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_plt_package_entry_ipv4_nz) {
            if (plt.value.table_length != 14u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv4_nz lab requires "
                    "table_length 14 (2-byte prefix + 12-byte package entry)";
                return r;
            }
            auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(
                plt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.num_of_packages != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv4_nz lab requires "
                    "num_of_packages 1";
                return r;
            }
            if (pref.value.num_of_ip_delivery != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv4_nz lab requires "
                    "num_of_ip_delivery 0";
                return r;
            }
            if (pref.bytes_consumed != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix must be 2 octets "
                    "before mmt_si_plt_package_entry_ipv4_nz";
                return r;
            }
            const auto entry_span =
                plt.value.payload.subspan(pref.bytes_consumed);
            auto entry =
                atsc3::mmt_si_plt_package_entry_ipv4_nz::decode(entry_span);
            if (!entry.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv4_nz decode failed: " +
                    entry.error;
                return r;
            }
            if (entry.bytes_consumed != entry_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv4_nz consumed " +
                    std::to_string(entry.bytes_consumed) + " of " +
                    std::to_string(entry_span.size()) +
                    " package entry octets after PLT prefix";
                return r;
            }
            if (entry.value.MMT_package_id_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv4_nz lab requires "
                    "MMT_package_id_length 0";
                return r;
            }
            if (entry.value.location_type != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv4_nz lab requires "
                    "location_type 1";
                return r;
            }
            if (entry.value.ipv4_src_addr != 0x0A000001u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv4_nz lab requires "
                    "ipv4_src_addr 10.0.0.1";
                return r;
            }
            if (entry.value.ipv4_dst_addr != 0xE0000001u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv4_nz lab requires "
                    "ipv4_dst_addr 224.0.0.1";
                return r;
            }
            if (entry.value.dst_port != 5000u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv4_nz lab requires "
                    "dst_port 5000";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4_nz) {
            if (plt.value.table_length != 15u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv4_nz lab "
                    "requires table_length 15 (2-byte prefix + 13-byte package entry)";
                return r;
            }
            auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(
                plt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.num_of_packages != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv4_nz lab "
                    "requires num_of_packages 1";
                return r;
            }
            if (pref.value.num_of_ip_delivery != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv4_nz lab "
                    "requires num_of_ip_delivery 0";
                return r;
            }
            if (pref.bytes_consumed != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix must be 2 octets "
                    "before mmt_si_plt_package_entry_id8_location_ipv4_nz";
                return r;
            }
            const auto entry_span =
                plt.value.payload.subspan(pref.bytes_consumed);
            auto entry =
                atsc3::mmt_si_plt_package_entry_id8_location_ipv4_nz::decode(entry_span);
            if (!entry.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv4_nz "
                    "decode failed: " +
                    entry.error;
                return r;
            }
            if (entry.bytes_consumed != entry_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv4_nz "
                    "consumed " +
                    std::to_string(entry.bytes_consumed) + " of " +
                    std::to_string(entry_span.size()) +
                    " package entry octets after PLT prefix";
                return r;
            }
            if (entry.value.MMT_package_id_length != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv4_nz lab "
                    "requires MMT_package_id_length 1";
                return r;
            }
            if (entry.value.MMT_package_id != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv4_nz lab "
                    "requires MMT_package_id 1";
                return r;
            }
            if (entry.value.location_type != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv4_nz lab "
                    "requires location_type 1";
                return r;
            }
            if (entry.value.ipv4_src_addr != 0x0A000001u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv4_nz lab "
                    "requires ipv4_src_addr 10.0.0.1";
                return r;
            }
            if (entry.value.ipv4_dst_addr != 0xE0000001u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv4_nz lab "
                    "requires ipv4_dst_addr 224.0.0.1";
                return r;
            }
            if (entry.value.dst_port != 5000u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv4_nz lab "
                    "requires dst_port 5000";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6_nz) {
            if (plt.value.table_length != 39u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv6_nz lab "
                    "requires table_length 39 (2-byte prefix + 37-byte package entry)";
                return r;
            }
            auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(
                plt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.num_of_packages != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv6_nz lab "
                    "requires num_of_packages 1";
                return r;
            }
            if (pref.value.num_of_ip_delivery != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv6_nz lab "
                    "requires num_of_ip_delivery 0";
                return r;
            }
            if (pref.bytes_consumed != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix must be 2 octets "
                    "before mmt_si_plt_package_entry_id8_location_ipv6_nz";
                return r;
            }
            const auto entry_span =
                plt.value.payload.subspan(pref.bytes_consumed);
            auto entry =
                atsc3::mmt_si_plt_package_entry_id8_location_ipv6_nz::decode(entry_span);
            if (!entry.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv6_nz "
                    "decode failed: " +
                    entry.error;
                return r;
            }
            if (entry.bytes_consumed != entry_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv6_nz "
                    "consumed " +
                    std::to_string(entry.bytes_consumed) + " of " +
                    std::to_string(entry_span.size()) +
                    " package entry octets after PLT prefix";
                return r;
            }
            if (entry.value.MMT_package_id_length != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv6_nz lab "
                    "requires MMT_package_id_length 1";
                return r;
            }
            if (entry.value.MMT_package_id != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv6_nz lab "
                    "requires MMT_package_id 1";
                return r;
            }
            if (entry.value.location_type != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv6_nz lab "
                    "requires location_type 2";
                return r;
            }
            if (entry.value.ipv6_src_addr_0 != 0u ||
                entry.value.ipv6_src_addr_1 != 0u ||
                entry.value.ipv6_src_addr_2 != 0x0000FFFFu ||
                entry.value.ipv6_src_addr_3 != 0x0A000001u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv6_nz lab "
                    "requires ipv6_src_addr ::ffff:10.0.0.1";
                return r;
            }
            if (entry.value.ipv6_dst_addr_0 != 0u ||
                entry.value.ipv6_dst_addr_1 != 0u ||
                entry.value.ipv6_dst_addr_2 != 0x0000FFFFu ||
                entry.value.ipv6_dst_addr_3 != 0xE0000001u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv6_nz lab "
                    "requires ipv6_dst_addr ::ffff:224.0.0.1";
                return r;
            }
            if (entry.value.dst_port != 5000u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv6_nz lab "
                    "requires dst_port 5000";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4) {
            if (plt.value.table_length != 15u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv4 lab "
                    "requires table_length 15 (2-byte prefix + 13-byte package entry)";
                return r;
            }
            auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(
                plt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.num_of_packages != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv4 lab "
                    "requires num_of_packages 1";
                return r;
            }
            if (pref.value.num_of_ip_delivery != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv4 lab "
                    "requires num_of_ip_delivery 0";
                return r;
            }
            if (pref.bytes_consumed != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix must be 2 octets "
                    "before mmt_si_plt_package_entry_id8_location_ipv4";
                return r;
            }
            const auto entry_span =
                plt.value.payload.subspan(pref.bytes_consumed);
            auto entry =
                atsc3::mmt_si_plt_package_entry_id8_location_ipv4::decode(entry_span);
            if (!entry.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv4 "
                    "decode failed: " +
                    entry.error;
                return r;
            }
            if (entry.bytes_consumed != entry_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv4 "
                    "consumed " +
                    std::to_string(entry.bytes_consumed) + " of " +
                    std::to_string(entry_span.size()) +
                    " package entry octets after PLT prefix";
                return r;
            }
            if (entry.value.MMT_package_id_length != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv4 lab "
                    "requires MMT_package_id_length 1";
                return r;
            }
            if (entry.value.MMT_package_id != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv4 lab "
                    "requires MMT_package_id 1";
                return r;
            }
            if (entry.value.location_type != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv4 lab "
                    "requires location_type 1";
                return r;
            }
            if (entry.value.ipv4_src_addr != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv4 lab "
                    "requires ipv4_src_addr 0";
                return r;
            }
            if (entry.value.ipv4_dst_addr != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv4 lab "
                    "requires ipv4_dst_addr 0";
                return r;
            }
            if (entry.value.dst_port != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv4 lab "
                    "requires dst_port 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6) {
            if (plt.value.table_length != 39u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv6 lab "
                    "requires table_length 39 (2-byte prefix + 37-byte package entry)";
                return r;
            }
            auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(
                plt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.num_of_packages != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv6 lab "
                    "requires num_of_packages 1";
                return r;
            }
            if (pref.value.num_of_ip_delivery != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv6 lab "
                    "requires num_of_ip_delivery 0";
                return r;
            }
            if (pref.bytes_consumed != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix must be 2 octets "
                    "before mmt_si_plt_package_entry_id8_location_ipv6";
                return r;
            }
            const auto entry_span =
                plt.value.payload.subspan(pref.bytes_consumed);
            auto entry =
                atsc3::mmt_si_plt_package_entry_id8_location_ipv6::decode(entry_span);
            if (!entry.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv6 "
                    "decode failed: " +
                    entry.error;
                return r;
            }
            if (entry.bytes_consumed != entry_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv6 "
                    "consumed " +
                    std::to_string(entry.bytes_consumed) + " of " +
                    std::to_string(entry_span.size()) +
                    " package entry octets after PLT prefix";
                return r;
            }
            if (entry.value.MMT_package_id_length != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv6 lab "
                    "requires MMT_package_id_length 1";
                return r;
            }
            if (entry.value.MMT_package_id != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv6 lab "
                    "requires MMT_package_id 1";
                return r;
            }
            if (entry.value.location_type != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv6 lab "
                    "requires location_type 2";
                return r;
            }
            if (entry.value.ipv6_src_addr_0 != 0u ||
                entry.value.ipv6_src_addr_1 != 0u ||
                entry.value.ipv6_src_addr_2 != 0u ||
                entry.value.ipv6_src_addr_3 != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv6 lab "
                    "requires zero ipv6_src_addr words";
                return r;
            }
            if (entry.value.ipv6_dst_addr_0 != 0u ||
                entry.value.ipv6_dst_addr_1 != 0u ||
                entry.value.ipv6_dst_addr_2 != 0u ||
                entry.value.ipv6_dst_addr_3 != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv6 lab "
                    "requires zero ipv6_dst_addr words";
                return r;
            }
            if (entry.value.dst_port != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_id8_location_ipv6 lab "
                    "requires dst_port 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_plt_package_entry_ipv6) {
            if (plt.value.table_length != 38u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv6 lab requires "
                    "table_length 38 (2-byte prefix + 36-byte package entry)";
                return r;
            }
            auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(
                plt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.num_of_packages != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv6 lab requires "
                    "num_of_packages 1";
                return r;
            }
            if (pref.value.num_of_ip_delivery != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv6 lab requires "
                    "num_of_ip_delivery 0";
                return r;
            }
            if (pref.bytes_consumed != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix must be 2 octets "
                    "before mmt_si_plt_package_entry_ipv6";
                return r;
            }
            const auto entry_span =
                plt.value.payload.subspan(pref.bytes_consumed);
            auto entry =
                atsc3::mmt_si_plt_package_entry_ipv6::decode(entry_span);
            if (!entry.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv6 decode failed: " +
                    entry.error;
                return r;
            }
            if (entry.bytes_consumed != entry_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv6 consumed " +
                    std::to_string(entry.bytes_consumed) + " of " +
                    std::to_string(entry_span.size()) +
                    " package entry octets after PLT prefix";
                return r;
            }
            if (entry.value.MMT_package_id_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv6 lab requires "
                    "MMT_package_id_length 0";
                return r;
            }
            if (entry.value.location_type != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv6 lab requires "
                    "location_type 2";
                return r;
            }
            if (entry.value.ipv6_src_addr_0 != 0u ||
                entry.value.ipv6_src_addr_1 != 0u ||
                entry.value.ipv6_src_addr_2 != 0u ||
                entry.value.ipv6_src_addr_3 != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv6 lab requires "
                    "zero ipv6_src_addr words";
                return r;
            }
            if (entry.value.ipv6_dst_addr_0 != 0u ||
                entry.value.ipv6_dst_addr_1 != 0u ||
                entry.value.ipv6_dst_addr_2 != 0u ||
                entry.value.ipv6_dst_addr_3 != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv6 lab requires "
                    "zero ipv6_dst_addr words";
                return r;
            }
            if (entry.value.dst_port != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv6 lab requires "
                    "dst_port 0";
                return r;
            }
        }
        if (_cfg.validate_mmt_si_plt_package_entry_ipv6_nz) {
            if (plt.value.table_length != 38u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv6_nz lab requires "
                    "table_length 38 (2-byte prefix + 36-byte package entry)";
                return r;
            }
            auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(
                plt.value.payload);
            if (!pref.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix decode failed: " +
                    pref.error;
                return r;
            }
            if (pref.value.num_of_packages != 1u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv6_nz lab requires "
                    "num_of_packages 1";
                return r;
            }
            if (pref.value.num_of_ip_delivery != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv6_nz lab requires "
                    "num_of_ip_delivery 0";
                return r;
            }
            if (pref.bytes_consumed != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_table_body_prefix must be 2 octets "
                    "before mmt_si_plt_package_entry_ipv6_nz";
                return r;
            }
            const auto entry_span =
                plt.value.payload.subspan(pref.bytes_consumed);
            auto entry =
                atsc3::mmt_si_plt_package_entry_ipv6_nz::decode(entry_span);
            if (!entry.ok) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv6_nz decode failed: " +
                    entry.error;
                return r;
            }
            if (entry.bytes_consumed != entry_span.size()) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv6_nz consumed " +
                    std::to_string(entry.bytes_consumed) + " of " +
                    std::to_string(entry_span.size()) +
                    " package entry octets after PLT prefix";
                return r;
            }
            if (entry.value.MMT_package_id_length != 0u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv6_nz lab requires "
                    "MMT_package_id_length 0";
                return r;
            }
            if (entry.value.location_type != 2u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv6_nz lab requires "
                    "location_type 2";
                return r;
            }
            if (entry.value.ipv6_src_addr_0 != 0u ||
                entry.value.ipv6_src_addr_1 != 0u ||
                entry.value.ipv6_src_addr_2 != 0x0000FFFFu ||
                entry.value.ipv6_src_addr_3 != 0x0A000001u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv6_nz lab requires "
                    "ipv6_src_addr ::ffff:10.0.0.1";
                return r;
            }
            if (entry.value.ipv6_dst_addr_0 != 0u ||
                entry.value.ipv6_dst_addr_1 != 0u ||
                entry.value.ipv6_dst_addr_2 != 0x0000FFFFu ||
                entry.value.ipv6_dst_addr_3 != 0xE0000001u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv6_nz lab requires "
                    "ipv6_dst_addr ::ffff:224.0.0.1";
                return r;
            }
            if (entry.value.dst_port != 5000u) {
                r.error =
                    "encoder_pipeline: mmt_si_plt_package_entry_ipv6_nz lab requires "
                    "dst_port 5000";
                return r;
            }
        }
    }

    if (_cfg.validate_mmt_si_plt_table_body_prefix &&
        !_cfg.validate_mmt_si_plt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_table_body_prefix requires "
            "validate_mmt_si_plt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info &&
        !_cfg.validate_mmt_si_plt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info requires "
            "validate_mmt_si_plt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info &&
        _cfg.validate_mmt_si_plt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info and "
            "validate_mmt_si_plt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv4 &&
        !_cfg.validate_mmt_si_plt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv4 requires "
            "validate_mmt_si_plt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv4 &&
        _cfg.validate_mmt_si_plt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv4 and "
            "validate_mmt_si_plt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info &&
        _cfg.validate_mmt_si_plt_delivery_info_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info and "
            "validate_mmt_si_plt_delivery_info_ipv4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv6 &&
        !_cfg.validate_mmt_si_plt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv6 requires "
            "validate_mmt_si_plt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv6 &&
        _cfg.validate_mmt_si_plt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv6 and "
            "validate_mmt_si_plt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info &&
        _cfg.validate_mmt_si_plt_delivery_info_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info and "
            "validate_mmt_si_plt_delivery_info_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv4 &&
        _cfg.validate_mmt_si_plt_delivery_info_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv4 and "
            "validate_mmt_si_plt_delivery_info_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url &&
        !_cfg.validate_mmt_si_plt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url requires "
            "validate_mmt_si_plt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url &&
        _cfg.validate_mmt_si_plt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url and "
            "validate_mmt_si_plt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info &&
        _cfg.validate_mmt_si_plt_delivery_info_url) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info and "
            "validate_mmt_si_plt_delivery_info_url are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv4 &&
        _cfg.validate_mmt_si_plt_delivery_info_url) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv4 and "
            "validate_mmt_si_plt_delivery_info_url are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv6 &&
        _cfg.validate_mmt_si_plt_delivery_info_url) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv6 and "
            "validate_mmt_si_plt_delivery_info_url are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry &&
        !_cfg.validate_mmt_si_plt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry requires "
            "validate_mmt_si_plt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry &&
        _cfg.validate_mmt_si_plt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry and "
            "validate_mmt_si_plt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info &&
        _cfg.validate_mmt_si_plt_package_entry) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info and "
            "validate_mmt_si_plt_package_entry are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv4 &&
        _cfg.validate_mmt_si_plt_package_entry) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv4 and "
            "validate_mmt_si_plt_package_entry are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv6 &&
        _cfg.validate_mmt_si_plt_package_entry) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv6 and "
            "validate_mmt_si_plt_package_entry are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url &&
        _cfg.validate_mmt_si_plt_package_entry) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url and "
            "validate_mmt_si_plt_package_entry are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url_3 &&
        !_cfg.validate_mmt_si_plt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url_3 requires "
            "validate_mmt_si_plt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url_3 &&
        _cfg.validate_mmt_si_plt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url_3 and "
            "validate_mmt_si_plt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info &&
        _cfg.validate_mmt_si_plt_delivery_info_url_3) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info and "
            "validate_mmt_si_plt_delivery_info_url_3 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv4 &&
        _cfg.validate_mmt_si_plt_delivery_info_url_3) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv4 and "
            "validate_mmt_si_plt_delivery_info_url_3 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv6 &&
        _cfg.validate_mmt_si_plt_delivery_info_url_3) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv6 and "
            "validate_mmt_si_plt_delivery_info_url_3 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url &&
        _cfg.validate_mmt_si_plt_delivery_info_url_3) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url and "
            "validate_mmt_si_plt_delivery_info_url_3 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url_4 &&
        !_cfg.validate_mmt_si_plt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url_4 requires "
            "validate_mmt_si_plt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv4_nz &&
        !_cfg.validate_mmt_si_plt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv4_nz requires "
            "validate_mmt_si_plt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv4_nz &&
        _cfg.validate_mmt_si_plt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv4_nz and "
            "validate_mmt_si_plt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url_4 &&
        _cfg.validate_mmt_si_plt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url_4 and "
            "validate_mmt_si_plt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info &&
        _cfg.validate_mmt_si_plt_delivery_info_url_4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info and "
            "validate_mmt_si_plt_delivery_info_url_4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info &&
        _cfg.validate_mmt_si_plt_delivery_info_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info and "
            "validate_mmt_si_plt_delivery_info_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv4 &&
        _cfg.validate_mmt_si_plt_delivery_info_url_4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv4 and "
            "validate_mmt_si_plt_delivery_info_url_4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv4 &&
        _cfg.validate_mmt_si_plt_delivery_info_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv4 and "
            "validate_mmt_si_plt_delivery_info_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv6 &&
        _cfg.validate_mmt_si_plt_delivery_info_url_4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv6 and "
            "validate_mmt_si_plt_delivery_info_url_4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv6 &&
        _cfg.validate_mmt_si_plt_delivery_info_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv6 and "
            "validate_mmt_si_plt_delivery_info_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url &&
        _cfg.validate_mmt_si_plt_delivery_info_url_4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url and "
            "validate_mmt_si_plt_delivery_info_url_4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url &&
        _cfg.validate_mmt_si_plt_delivery_info_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url and "
            "validate_mmt_si_plt_delivery_info_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url_3 &&
        _cfg.validate_mmt_si_plt_delivery_info_url_4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url_3 and "
            "validate_mmt_si_plt_delivery_info_url_4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url_3 &&
        _cfg.validate_mmt_si_plt_delivery_info_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url_3 and "
            "validate_mmt_si_plt_delivery_info_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url_4 &&
        _cfg.validate_mmt_si_plt_package_entry) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url_4 and "
            "validate_mmt_si_plt_package_entry are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url_3 &&
        _cfg.validate_mmt_si_plt_package_entry) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url_3 and "
            "validate_mmt_si_plt_package_entry are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8 &&
        !_cfg.validate_mmt_si_plt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8 requires "
            "validate_mmt_si_plt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8 &&
        _cfg.validate_mmt_si_plt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8 and "
            "validate_mmt_si_plt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info &&
        _cfg.validate_mmt_si_plt_package_entry_id8) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info and "
            "validate_mmt_si_plt_package_entry_id8 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv4 &&
        _cfg.validate_mmt_si_plt_package_entry_id8) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv4 and "
            "validate_mmt_si_plt_package_entry_id8 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv6 &&
        _cfg.validate_mmt_si_plt_package_entry_id8) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv6 and "
            "validate_mmt_si_plt_package_entry_id8 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url &&
        _cfg.validate_mmt_si_plt_package_entry_id8) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url and "
            "validate_mmt_si_plt_package_entry_id8 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url_3 &&
        _cfg.validate_mmt_si_plt_package_entry_id8) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url_3 and "
            "validate_mmt_si_plt_package_entry_id8 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url_4 &&
        _cfg.validate_mmt_si_plt_package_entry_id8) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url_4 and "
            "validate_mmt_si_plt_package_entry_id8 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry &&
        _cfg.validate_mmt_si_plt_package_entry_id8) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry and "
            "validate_mmt_si_plt_package_entry_id8 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_ipv4 &&
        !_cfg.validate_mmt_si_plt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_ipv4 requires "
            "validate_mmt_si_plt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_ipv4 &&
        _cfg.validate_mmt_si_plt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_ipv4 and "
            "validate_mmt_si_plt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info &&
        _cfg.validate_mmt_si_plt_package_entry_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info and "
            "validate_mmt_si_plt_package_entry_ipv4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv4 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv4 and "
            "validate_mmt_si_plt_package_entry_ipv4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv6 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv6 and "
            "validate_mmt_si_plt_package_entry_ipv4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url &&
        _cfg.validate_mmt_si_plt_package_entry_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url and "
            "validate_mmt_si_plt_package_entry_ipv4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url_3 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url_3 and "
            "validate_mmt_si_plt_package_entry_ipv4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url_4 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url_4 and "
            "validate_mmt_si_plt_package_entry_ipv4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry &&
        _cfg.validate_mmt_si_plt_package_entry_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry and "
            "validate_mmt_si_plt_package_entry_ipv4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8 and "
            "validate_mmt_si_plt_package_entry_ipv4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_ipv4_nz &&
        !_cfg.validate_mmt_si_plt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_ipv4_nz requires "
            "validate_mmt_si_plt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_ipv4_nz &&
        _cfg.validate_mmt_si_plt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_ipv4_nz and "
            "validate_mmt_si_plt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info &&
        _cfg.validate_mmt_si_plt_package_entry_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info and "
            "validate_mmt_si_plt_package_entry_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv4 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv4 and "
            "validate_mmt_si_plt_package_entry_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv6 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv6 and "
            "validate_mmt_si_plt_package_entry_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url &&
        _cfg.validate_mmt_si_plt_package_entry_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url and "
            "validate_mmt_si_plt_package_entry_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url_3 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url_3 and "
            "validate_mmt_si_plt_package_entry_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url_4 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url_4 and "
            "validate_mmt_si_plt_package_entry_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv4_nz &&
        _cfg.validate_mmt_si_plt_package_entry_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv4_nz and "
            "validate_mmt_si_plt_package_entry_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry &&
        _cfg.validate_mmt_si_plt_package_entry_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry and "
            "validate_mmt_si_plt_package_entry_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8 and "
            "validate_mmt_si_plt_package_entry_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_ipv4 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_ipv4 and "
            "validate_mmt_si_plt_package_entry_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8_location_ipv4 and "
            "validate_mmt_si_plt_package_entry_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4_nz &&
        !_cfg.validate_mmt_si_plt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8_location_ipv4_nz "
            "requires validate_mmt_si_plt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4_nz &&
        _cfg.validate_mmt_si_plt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8_location_ipv4_nz "
            "and validate_mmt_si_plt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv4 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv4 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv6 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv6 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url_3 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url_3 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url_4 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url_4 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv4_nz &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv4_nz and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_ipv4 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_ipv4 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_ipv4_nz &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_ipv4_nz and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8_location_ipv4 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv4_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6_nz &&
        !_cfg.validate_mmt_si_plt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8_location_ipv6_nz "
            "requires validate_mmt_si_plt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6_nz &&
        _cfg.validate_mmt_si_plt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8_location_ipv6_nz "
            "and validate_mmt_si_plt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv4 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv4 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv6 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv6 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url_3 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url_3 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url_4 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url_4 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv4_nz &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv4_nz and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_ipv4 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_ipv4 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_ipv4_nz &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_ipv4_nz and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8_location_ipv4 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4_nz &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8_location_ipv4_nz and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8_location_ipv6 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4 &&
        !_cfg.validate_mmt_si_plt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8_location_ipv4 "
            "requires validate_mmt_si_plt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4 &&
        _cfg.validate_mmt_si_plt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8_location_ipv4 "
            "and validate_mmt_si_plt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv4 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv4 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv6 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv6 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url_3 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url_3 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url_4 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url_4 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_ipv4 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_ipv4 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_ipv4_nz &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_ipv4_nz and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv4 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_ipv6 &&
        !_cfg.validate_mmt_si_plt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_ipv6 requires "
            "validate_mmt_si_plt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_ipv6 &&
        _cfg.validate_mmt_si_plt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_ipv6 and "
            "validate_mmt_si_plt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info &&
        _cfg.validate_mmt_si_plt_package_entry_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info and "
            "validate_mmt_si_plt_package_entry_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv4 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv4 and "
            "validate_mmt_si_plt_package_entry_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv6 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv6 and "
            "validate_mmt_si_plt_package_entry_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url &&
        _cfg.validate_mmt_si_plt_package_entry_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url and "
            "validate_mmt_si_plt_package_entry_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url_3 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url_3 and "
            "validate_mmt_si_plt_package_entry_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url_4 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url_4 and "
            "validate_mmt_si_plt_package_entry_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry &&
        _cfg.validate_mmt_si_plt_package_entry_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry and "
            "validate_mmt_si_plt_package_entry_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8 and "
            "validate_mmt_si_plt_package_entry_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_ipv4 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_ipv4 and "
            "validate_mmt_si_plt_package_entry_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8_location_ipv4 and "
            "validate_mmt_si_plt_package_entry_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4_nz &&
        _cfg.validate_mmt_si_plt_package_entry_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8_location_ipv4_nz and "
            "validate_mmt_si_plt_package_entry_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6_nz &&
        _cfg.validate_mmt_si_plt_package_entry_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8_location_ipv6_nz and "
            "validate_mmt_si_plt_package_entry_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6 &&
        !_cfg.validate_mmt_si_plt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8_location_ipv6 "
            "requires validate_mmt_si_plt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6 &&
        _cfg.validate_mmt_si_plt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8_location_ipv6 "
            "and validate_mmt_si_plt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv4 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv4 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv6 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv6 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url_3 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url_3 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url_4 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url_4 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_ipv4 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_ipv4 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8_location_ipv4 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4_nz &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8_location_ipv4_nz and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6_nz &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8_location_ipv6_nz and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_ipv6 &&
        _cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_ipv6 and "
            "validate_mmt_si_plt_package_entry_id8_location_ipv6 are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_ipv6_nz &&
        !_cfg.validate_mmt_si_plt_table_body) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_ipv6_nz requires "
            "validate_mmt_si_plt_table_body";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_ipv6_nz &&
        _cfg.validate_mmt_si_plt_table_body_prefix) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_ipv6_nz and "
            "validate_mmt_si_plt_table_body_prefix are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info &&
        _cfg.validate_mmt_si_plt_package_entry_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info and "
            "validate_mmt_si_plt_package_entry_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv4 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv4 and "
            "validate_mmt_si_plt_package_entry_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_ipv6 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_ipv6 and "
            "validate_mmt_si_plt_package_entry_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url &&
        _cfg.validate_mmt_si_plt_package_entry_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url and "
            "validate_mmt_si_plt_package_entry_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url_3 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url_3 and "
            "validate_mmt_si_plt_package_entry_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_delivery_info_url_4 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_delivery_info_url_4 and "
            "validate_mmt_si_plt_package_entry_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry &&
        _cfg.validate_mmt_si_plt_package_entry_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry and "
            "validate_mmt_si_plt_package_entry_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8 and "
            "validate_mmt_si_plt_package_entry_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_ipv4 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_ipv4 and "
            "validate_mmt_si_plt_package_entry_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_ipv4_nz &&
        _cfg.validate_mmt_si_plt_package_entry_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_ipv4_nz and "
            "validate_mmt_si_plt_package_entry_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_ipv6 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_ipv6 and "
            "validate_mmt_si_plt_package_entry_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8_location_ipv4 and "
            "validate_mmt_si_plt_package_entry_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4_nz &&
        _cfg.validate_mmt_si_plt_package_entry_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8_location_ipv4_nz and "
            "validate_mmt_si_plt_package_entry_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6_nz &&
        _cfg.validate_mmt_si_plt_package_entry_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8_location_ipv6_nz and "
            "validate_mmt_si_plt_package_entry_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6 &&
        _cfg.validate_mmt_si_plt_package_entry_ipv6_nz) {
        r.error =
            "encoder_pipeline: validate_mmt_si_plt_package_entry_id8_location_ipv6 and "
            "validate_mmt_si_plt_package_entry_ipv6_nz are mutually exclusive";
        return r;
    }

    if (_cfg.prepend_mmt_si_pa_table_headers) {
        if (!_cfg.prepend_mmt_si_message_header_len32) {
            r.error =
                "encoder_pipeline: prepend_mmt_si_pa_table_headers requires "
                "prepend_mmt_si_message_header_len32";
            return r;
        }
        if (_cfg.mmt_si_message_id != 0u) {
            r.error =
                "encoder_pipeline: prepend_mmt_si_pa_table_headers requires "
                "mmt_si_message_id 0 (PA message lab)";
            return r;
        }
        if (_cfg.mmt_si_pa_table_header_rows.size() > 255u) {
            r.error =
                "encoder_pipeline: mmt_si_pa_table_header_rows size must be <= 255";
            return r;
        }
        if (_cfg.mmt_si_pa_table_header_rows.empty()) {
            r.error =
                "encoder_pipeline: prepend_mmt_si_pa_table_headers requires "
                "at least one mmt_si_pa_table_header_row";
            return r;
        }
        std::size_t body_total = 0;
        bool any_zero_len    = false;
        bool any_nonzero_len = false;
        for (const auto& row : _cfg.mmt_si_pa_table_header_rows) {
            body_total += row.table_length;
            if (row.table_length == 0u) {
                any_zero_len = true;
            } else {
                any_nonzero_len = true;
            }
            if (_cfg.validate_mmt_si_mpt_table_body && row.table_id == 32u &&
                row.table_length != 0u &&
                static_cast<std::size_t>(row.table_length) != payload.size()) {
                r.error =
                    "encoder_pipeline: PA MPT row table_length must match "
                    "mmt_si_mpt_table ingress size";
                return r;
            }
            if (_cfg.validate_mmt_si_plt_table_body && row.table_id == 128u &&
                row.table_length != 0u &&
                static_cast<std::size_t>(row.table_length) != payload.size()) {
                r.error =
                    "encoder_pipeline: PA PLT row table_length must match "
                    "mmt_si_plt_table ingress size";
                return r;
            }
        }
        if (body_total > payload.size()) {
            r.error =
                "encoder_pipeline: sum of PA table_length (" +
                std::to_string(body_total) +
                ") exceeds ingress octet length (" +
                std::to_string(payload.size()) + ")";
            return r;
        }
        const auto& rows = _cfg.mmt_si_pa_table_header_rows;
        if (rows.size() == 1u) {
            const auto& row = rows.front();
            if (row.table_length != 0u &&
                static_cast<std::size_t>(row.table_length) != payload.size()) {
                r.error =
                    "encoder_pipeline: single PA table row table_length (" +
                    std::to_string(row.table_length) +
                    ") must equal ingress octet length (" +
                    std::to_string(payload.size()) +
                    ") when non-zero (§10.3 table-body lab)";
                return r;
            }
        } else if (any_nonzero_len && !any_zero_len &&
                   body_total != payload.size()) {
            r.error =
                "encoder_pipeline: multi-table PA rows (all table_length > 0): "
                "sum(table_length) (" +
                std::to_string(body_total) +
                ") must equal ingress octet length (" +
                std::to_string(payload.size()) +
                ") (§10.3 concatenated table bodies)";
            return r;
        }
    }

    if (want_mmtp || want_lct) {
        alp_storage.emplace();
        std::vector<std::byte>& buf = *alp_storage;
        bool mmtp_si_lab_suffix_consumed_payload = false;

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
                if (_cfg.prepend_mmt_si_length32_envelope ||
                    _cfg.prepend_mmt_si_descriptor_loop_u32 ||
                    _cfg.prepend_mmt_si_message_header_len32 ||
                    _cfg.prepend_mmt_si_pa_table_headers) {
                    std::vector<std::byte> si_blob;
                    si_blob.assign(payload.begin(), payload.end());
                    if (_cfg.prepend_mmt_si_pa_table_headers) {
                        atsc3::mmt_si_pa_table_headers::decoded_t ph{};
                        ph.number_of_tables = static_cast<std::uint8_t>(
                            _cfg.mmt_si_pa_table_header_rows.size());
                        ph.table_headers_byte_length = 0;
                        for (const auto& row : _cfg.mmt_si_pa_table_header_rows) {
                            atsc3::mmt_si_table_header_word32::decoded_t el{};
                            el.table_id      = row.table_id;
                            el.table_version = row.table_version;
                            el.table_length  = row.table_length;
                            ph.elements.push_back(el);
                        }
                        auto phe = atsc3::mmt_si_pa_table_headers::encode(ph);
                        if (!phe.ok) {
                            r.error =
                                "encoder_pipeline: mmt_si_pa_table_headers encode failed: " +
                                phe.error;
                            return r;
                        }
                        std::vector<std::byte> tmp;
                        tmp.reserve(phe.bytes.size() + si_blob.size());
                        tmp.insert(tmp.end(), phe.bytes.begin(), phe.bytes.end());
                        tmp.insert(tmp.end(), si_blob.begin(), si_blob.end());
                        si_blob = std::move(tmp);
                    }
                    if (_cfg.prepend_mmt_si_descriptor_loop_u32) {
                        std::vector<std::byte> tmp;
                        tmp.reserve(sizeof(std::uint32_t) + si_blob.size());
                        append_u32_be(
                            &tmp,
                            static_cast<std::uint32_t>(si_blob.size()));
                        tmp.insert(tmp.end(), si_blob.begin(), si_blob.end());
                        si_blob = std::move(tmp);
                    }
                    if (_cfg.prepend_mmt_si_length32_envelope) {
                        atsc3::mmt_si_length32_envelope::decoded_t env{};
                        env.body_byte_length =
                            static_cast<std::uint32_t>(si_blob.size());
                        env.payload = std::span<const std::byte>(
                            si_blob.data(), si_blob.size());
                        auto eenc =
                            atsc3::mmt_si_length32_envelope::encode(env);
                        if (!eenc.ok) {
                            r.error =
                                "encoder_pipeline: mmt_si_length32_envelope encode failed: " +
                                eenc.error;
                            return r;
                        }
                        si_blob.assign(eenc.bytes.begin(), eenc.bytes.end());
                    }
                    if (_cfg.prepend_mmt_si_message_header_len32) {
                        atsc3::mmt_si_message_header_len32::decoded_t mh{};
                        mh.message_id = _cfg.mmt_si_message_id;
                        mh.message_version = _cfg.mmt_si_message_version;
                        mh.message_byte_length =
                            static_cast<std::uint32_t>(si_blob.size());
                        mh.payload = std::span<const std::byte>(
                            si_blob.data(), si_blob.size());
                        auto mhe = atsc3::mmt_si_message_header_len32::encode(mh);
                        if (!mhe.ok) {
                            r.error =
                                "encoder_pipeline: mmt_si_message_header_len32 encode failed: " +
                                mhe.error;
                            return r;
                        }
                        buf.insert(buf.end(), mhe.bytes.begin(), mhe.bytes.end());
                    } else {
                        buf.insert(buf.end(), si_blob.begin(), si_blob.end());
                    }
                    mmtp_si_lab_suffix_consumed_payload = true;
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
            } else if (_cfg.prepend_mmtp_gfd_header) {
                auto gh = atsc3::mmtp_payload_gfd_header::encode(_cfg.mmtp_gfd_header);
                if (!gh.ok || gh.bytes.size() != k_mmtp_gfd_header_octets) {
                    r.error =
                        "encoder_pipeline: MMTP GFD payload header encode failed: " +
                        gh.error;
                    return r;
                }
                buf.insert(buf.end(), gh.bytes.begin(), gh.bytes.end());
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

        const bool mmtp_skip_raw_payload =
            want_mmtp && mmtp_si_lab_suffix_consumed_payload;
        if (!mmtp_skip_raw_payload) {
            buf.insert(buf.end(), payload.begin(), payload.end());
        }
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
    alp.payload_config = _cfg.alp_payload_config;
    alp.header_mode      = _cfg.alp_header_mode;
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

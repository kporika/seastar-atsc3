// SPDX-License-Identifier: Apache-2.0
//
// Pure C++ unit test for gw/encoder_pipeline. No Seastar, no networking —
// just exercises the codec composition end to end.
//
// For each input payload:
//
//   payload  ──► encoder_pipeline.encode()  ──► tlv_mux::decode()
//                                                       │
//                                                       ▼
//                                                tlv_mux.payload
//                                                       │
//                                                       ▼
//                                                alp::decode()
//                                                       │
//                                                       ▼
//                                              alp.payload  ==  payload  ✓

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <vector>

#include "alp_decoder.h"
#include "alp_types.h"
#include "encoder_pipeline.h"
#include "lct_rfc5651_word0_decoder.h"
#include "mmtp_header_counter32_decoder.h"
#include "mmtp_header_extension_decoder.h"
#include "mmtp_header_ts_psn_decoder.h"
#include "mmtp_header_word0_decoder.h"
#include "mmtp_payload_isobmff_du_header_non_timed_decoder.h"
#include "mmtp_payload_isobmff_du_header_timed_decoder.h"
#include "mmtp_payload_gfd_header_decoder.h"
#include "mmtp_payload_isobmff_prefix_decoder.h"
#include "mmtp_payload_signalling_prefix_decoder.h"
#include "mmt_si_descriptor_loop_u32_decoder.h"
#include "mmt_si_length32_envelope_decoder.h"
#include "mmt_si_message_header_len32_decoder.h"
#include "mmt_si_mpt_asset_decoder.h"
#include "mmt_si_mpt_asset_descriptors4_decoder.h"
#include "mmt_si_mpt_asset_id8_decoder.h"
#include "mmt_si_mpt_asset_id16_decoder.h"
#include "mmt_si_mpt_asset_location0_decoder.h"
#include "mmt_si_mpt_asset_location_ipv4_decoder.h"
#include "mmt_si_mpt_asset_location_ipv4_nz_decoder.h"
#include "mmt_si_mpt_asset_location_ipv6_nz_decoder.h"
#include "mmt_si_mpt_asset_location_ipv6_decoder.h"
#include "mmt_si_mpt_asset_id8_location_ipv4_decoder.h"
#include "mmt_si_mpt_asset_id8_location_ipv4_nz_decoder.h"
#include "mmt_si_mpt_asset_id16_location_ipv4_decoder.h"
#include "mmt_si_mpt_asset_id16_location_ipv4_nz_decoder.h"
#include "mmt_si_mpt_asset_id16_location_ipv6_decoder.h"
#include "mmt_si_mpt_asset_id16_location_ipv6_nz_decoder.h"
#include "mmt_si_mpt_asset_id16_descriptors4_decoder.h"
#include "mmt_si_mpt_asset_id8_descriptors4_decoder.h"
#include "mmt_si_mpt_asset_id8_location_ipv6_decoder.h"
#include "mmt_si_mpt_asset_id8_location_ipv6_nz_decoder.h"
#include "mmt_si_mpt_table_body_prefix_decoder.h"
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
#include "mmt_si_mpt_table_decoder.h"
#include "mmt_si_pa_table_headers_decoder.h"
#include "mmt_si_pa_table_headers_decoder.h"
#include "tlv_mux_decoder.h"
#include "tlv_mux_types.h"

namespace {

std::uint32_t read_be32_at(std::span<const std::byte> s,
                           std::size_t off) noexcept {
    using U = unsigned;
    return (std::uint32_t(static_cast<U>(std::uint8_t(s[off])) << 24) |
            std::uint32_t(static_cast<U>(std::uint8_t(s[off + 1])) << 16) |
            std::uint32_t(static_cast<U>(std::uint8_t(s[off + 2])) << 8) |
            std::uint32_t(static_cast<U>(std::uint8_t(s[off + 3]))));
}

bool span_equal(std::span<const std::byte> a, std::span<const std::byte> b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

std::string hex(std::span<const std::byte> s) {
    static const char *d = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size() * 2);
    for (auto x : s) {
        const auto v = static_cast<std::uint8_t>(x);
        out.push_back(d[v >> 4]);
        out.push_back(d[v & 0xF]);
    }
    return out;
}

int run_one(const char *label, const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline enc{};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }
    if (tlv.value.packet_type != atsc3::tlv_mux::packet_type::SIGNALING) {
        std::fprintf(stderr,
                     "[%s] tlv_mux packet_type mismatch: got %s want SIGNALING\n",
                     label, atsc3::tlv_mux::packet_type_name(tlv.value.packet_type));
        return 1;
    }
    if (tlv.bytes_consumed != wire.bytes.size()) {
        std::fprintf(stderr,
                     "[%s] tlv_mux bytes_consumed=%zu, expected %zu (no trailing bytes)\n",
                     label, tlv.bytes_consumed, wire.bytes.size());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }
    if (alp.value.packet_type != atsc3::alp::packet_type::PACKET_TYPE_EXTENSION) {
        std::fprintf(stderr,
                     "[%s] alp packet_type mismatch: got %s want PACKET_TYPE_EXTENSION\n",
                     label, atsc3::alp::packet_type_name(alp.value.packet_type));
        return 1;
    }
    if (alp.value.payload_length != payload.size()) {
        std::fprintf(stderr,
                     "[%s] alp payload_length=%u, expected %zu\n",
                     label, alp.value.payload_length, payload.size());
        return 1;
    }
    if (!span_equal(alp.value.payload,
                    std::span<const std::byte>(payload))) {
        std::fprintf(stderr,
                     "[%s] payload mismatch\n  got:  %s\n  want: %s\n",
                     label,
                     hex(alp.value.payload).c_str(),
                     hex(std::span<const std::byte>(payload)).c_str());
        return 1;
    }

    std::printf("[%s] OK (payload=%zu bytes, wire=%zu bytes)\n",
                label, payload.size(), wire.bytes.size());
    return 0;
}

/// Round-trip **ALP** §5.2 base-header **payload_configuration** / **header_mode**
/// through **`encoder_pipeline` → `tlv_mux::decode` → `alp::decode`**.
/// Wire semantics match **`protocol/alp.yaml`** (lab path still uses 16-bit base +
/// opaque body only).
int run_alp_base_header_flags(const char *label, bool want_pc, bool want_hm,
                                const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline enc{atsc3::gw::encoder_pipeline::config{
        .alp_payload_config = want_pc,
        .alp_header_mode    = want_hm,
    }};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }
    if (alp.value.payload_config != want_pc) {
        std::fprintf(stderr,
                     "[%s] alp payload_config: got %d want %d\n", label,
                     static_cast<int>(alp.value.payload_config),
                     static_cast<int>(want_pc));
        return 1;
    }
    if (alp.value.header_mode != want_hm) {
        std::fprintf(stderr,
                     "[%s] alp header_mode: got %d want %d\n", label,
                     static_cast<int>(alp.value.header_mode),
                     static_cast<int>(want_hm));
        return 1;
    }
    if (!span_equal(alp.value.payload,
                    std::span<const std::byte>(payload))) {
        std::fprintf(stderr,
                     "[%s] payload mismatch\n  got:  %s\n  want: %s\n",
                     label,
                     hex(alp.value.payload).c_str(),
                     hex(std::span<const std::byte>(payload)).c_str());
        return 1;
    }

    std::printf("[%s] OK (pc=%d hm=%d payload=%zu wire=%zu)\n", label,
                static_cast<int>(want_pc), static_cast<int>(want_hm),
                payload.size(), wire.bytes.size());
    return 0;
}

int run_lct_prefix(const char *label, std::uint8_t cp,
                   const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline enc{atsc3::gw::with_prepended_lab_lct_word0(cp)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    if (body.size() != payload.size() + 4u) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), payload.size() + 4u);
        return 1;
    }

    auto lct = atsc3::lct_rfc5651_word0::decode(
        body.subspan(0, sizeof(std::uint32_t)));
    if (!lct.ok) {
        std::fprintf(stderr, "[%s] lct_word0 decode failed: %s\n",
                     label, lct.error.c_str());
        return 1;
    }
    if (lct.value.codepoint != cp) {
        std::fprintf(stderr, "[%s] lct codepoint got %u want %u\n", label,
                     static_cast<unsigned>(lct.value.codepoint),
                     static_cast<unsigned>(cp));
        return 1;
    }
    if (!span_equal(body.subspan(4),
                    std::span<const std::byte>(payload))) {
        std::fprintf(stderr, "[%s] payload tail mismatch\n", label);
        return 1;
    }

    std::printf(
        "[%s] OK (user=%zu wire=%zu cp=%u)\n", label, payload.size(),
        wire.bytes.size(), static_cast<unsigned>(cp));
    return 0;
}

int run_mmtp_prefix(const char *label, std::uint8_t payload_type,
                    std::uint16_t packet_id,
                    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline enc{
        atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    if (body.size() != payload.size() + 4u) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), payload.size() + 4u);
        return 1;
    }

    auto mh = atsc3::mmtp_header_word0::decode(body.subspan(0, 4));
    if (!mh.ok) {
        std::fprintf(stderr, "[%s] mmtp word0 decode failed: %s\n",
                     label, mh.error.c_str());
        return 1;
    }
    if (mh.value.payload_type != payload_type ||
        mh.value.packet_id != packet_id) {
        std::fprintf(stderr,
                     "[%s] mmtp header mismatch: type=%u id=%u (want %u %u)\n",
                     label, static_cast<unsigned>(mh.value.payload_type),
                     static_cast<unsigned>(mh.value.packet_id),
                     static_cast<unsigned>(payload_type),
                     static_cast<unsigned>(packet_id));
        return 1;
    }
    if (!span_equal(body.subspan(4),
                    std::span<const std::byte>(payload))) {
        std::fprintf(stderr, "[%s] payload tail mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix(
    const char *label, std::uint8_t payload_type, std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline enc{atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
        sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id))};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    const std::size_t want_len = 4u + 2u + payload.size();
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto mh = atsc3::mmtp_header_word0::decode(body.subspan(0, 4));
    if (!mh.ok || mh.value.payload_type != payload_type ||
        mh.value.packet_id != packet_id) {
        std::fprintf(stderr, "[%s] mmtp word0 mismatch\n", label);
        return 1;
    }
    auto sg = atsc3::mmtp_payload_signalling_prefix::decode(body.subspan(4, 2));
    if (!sg.ok) {
        std::fprintf(stderr, "[%s] signalling prefix decode: %s\n", label,
                     sg.error.c_str());
        return 1;
    }
    if (sg.value.fragmentation_indicator != sig.fragmentation_indicator ||
        sg.value.reserved != sig.reserved ||
        sg.value.length_extension_flag != sig.length_extension_flag ||
        sg.value.aggregation_flag != sig.aggregation_flag ||
        sg.value.fragment_counter != sig.fragment_counter) {
        std::fprintf(stderr, "[%s] signalling prefix field mismatch\n", label);
        return 1;
    }
    if (!span_equal(body.subspan(6),
                    std::span<const std::byte>(payload))) {
        std::fprintf(stderr, "[%s] payload tail mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_length32_envelope(
    const char *label, std::uint8_t payload_type, std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_length32_envelope = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    const std::size_t want_len = 4u + 2u + 4u + payload.size();
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto mh = atsc3::mmtp_header_word0::decode(body.subspan(0, 4));
    if (!mh.ok || mh.value.payload_type != payload_type ||
        mh.value.packet_id != packet_id) {
        std::fprintf(stderr, "[%s] mmtp word0 mismatch\n", label);
        return 1;
    }
    auto sg = atsc3::mmtp_payload_signalling_prefix::decode(body.subspan(4, 2));
    if (!sg.ok) {
        std::fprintf(stderr, "[%s] signalling prefix decode: %s\n", label,
                     sg.error.c_str());
        return 1;
    }
    if (sg.value.fragmentation_indicator != sig.fragmentation_indicator ||
        sg.value.reserved != sig.reserved ||
        sg.value.length_extension_flag != sig.length_extension_flag ||
        sg.value.aggregation_flag != sig.aggregation_flag ||
        sg.value.fragment_counter != sig.fragment_counter) {
        std::fprintf(stderr, "[%s] signalling prefix field mismatch\n", label);
        return 1;
    }
    auto env = atsc3::mmt_si_length32_envelope::decode(body.subspan(6));
    if (!env.ok) {
        std::fprintf(stderr, "[%s] mmt_si_length32_envelope decode: %s\n", label,
                     env.error.c_str());
        return 1;
    }
    if (env.value.body_byte_length !=
        static_cast<std::uint32_t>(payload.size())) {
        std::fprintf(stderr, "[%s] envelope body_byte_length mismatch\n", label);
        return 1;
    }
    if (!span_equal(env.value.payload,
                    std::span<const std::byte>(payload))) {
        std::fprintf(stderr, "[%s] envelope inner payload mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_descriptor_loop_u32(
    const char *label, std::uint8_t payload_type, std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    bool with_length32_envelope,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_descriptor_loop_u32 = true;
    cfg.prepend_mmt_si_length32_envelope = with_length32_envelope;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    const std::size_t loop_wire = sizeof(std::uint32_t) + payload.size();
    const std::size_t want_len =
        4u + 2u + (with_length32_envelope ? (sizeof(std::uint32_t) + loop_wire)
                                          : loop_wire);
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto mh = atsc3::mmtp_header_word0::decode(body.subspan(0, 4));
    if (!mh.ok || mh.value.payload_type != payload_type ||
        mh.value.packet_id != packet_id) {
        std::fprintf(stderr, "[%s] mmtp word0 mismatch\n", label);
        return 1;
    }
    auto sg = atsc3::mmtp_payload_signalling_prefix::decode(body.subspan(4, 2));
    if (!sg.ok) {
        std::fprintf(stderr, "[%s] signalling prefix decode: %s\n", label,
                     sg.error.c_str());
        return 1;
    }
    if (sg.value.fragmentation_indicator != sig.fragmentation_indicator ||
        sg.value.reserved != sig.reserved ||
        sg.value.length_extension_flag != sig.length_extension_flag ||
        sg.value.aggregation_flag != sig.aggregation_flag ||
        sg.value.fragment_counter != sig.fragment_counter) {
        std::fprintf(stderr, "[%s] signalling prefix field mismatch\n", label);
        return 1;
    }
    std::span<const std::byte> tail = body.subspan(6);
    if (with_length32_envelope) {
        auto env = atsc3::mmt_si_length32_envelope::decode(tail);
        if (!env.ok) {
            std::fprintf(stderr, "[%s] mmt_si_length32_envelope decode: %s\n", label,
                         env.error.c_str());
            return 1;
        }
        if (env.value.body_byte_length !=
            static_cast<std::uint32_t>(loop_wire)) {
            std::fprintf(stderr, "[%s] envelope body_byte_length mismatch\n", label);
            return 1;
        }
        tail = std::span<const std::byte>(
            env.value.payload.data(), env.value.payload.size());
    }
    auto lp = atsc3::mmt_si_descriptor_loop_u32::decode(tail);
    if (!lp.ok) {
        std::fprintf(stderr, "[%s] mmt_si_descriptor_loop_u32 decode: %s\n", label,
                     lp.error.c_str());
        return 1;
    }
    if (lp.value.loop_length != static_cast<std::uint32_t>(payload.size())) {
        std::fprintf(stderr, "[%s] descriptor loop_length mismatch\n", label);
        return 1;
    }
    if (!span_equal(
            tail.subspan(sizeof(std::uint32_t),
                         static_cast<std::size_t>(lp.value.loop_length)),
            std::span<const std::byte>(payload))) {
        std::fprintf(stderr, "[%s] descriptor loop body mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_message_header_len32(
    const char *label, std::uint8_t payload_type, std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    bool with_length32_envelope, bool with_descriptor_loop,
    std::uint16_t message_id, std::uint8_t message_version,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_descriptor_loop_u32  = with_descriptor_loop;
    cfg.prepend_mmt_si_length32_envelope    = with_length32_envelope;
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                   = message_id;
    cfg.mmt_si_message_version              = message_version;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    const std::size_t loop_wire =
        with_descriptor_loop ? (sizeof(std::uint32_t) + payload.size()) : payload.size();
    const std::size_t inner_si =
        with_length32_envelope ? (sizeof(std::uint32_t) + loop_wire) : loop_wire;
    const std::size_t msg_wire  = 7u + inner_si;
    const std::size_t want_len = 4u + 2u + msg_wire;
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto mh = atsc3::mmtp_header_word0::decode(body.subspan(0, 4));
    if (!mh.ok || mh.value.payload_type != payload_type ||
        mh.value.packet_id != packet_id) {
        std::fprintf(stderr, "[%s] mmtp word0 mismatch\n", label);
        return 1;
    }
    auto sg = atsc3::mmtp_payload_signalling_prefix::decode(body.subspan(4, 2));
    if (!sg.ok) {
        std::fprintf(stderr, "[%s] signalling prefix decode: %s\n", label,
                     sg.error.c_str());
        return 1;
    }
    if (sg.value.fragmentation_indicator != sig.fragmentation_indicator ||
        sg.value.reserved != sig.reserved ||
        sg.value.length_extension_flag != sig.length_extension_flag ||
        sg.value.aggregation_flag != sig.aggregation_flag ||
        sg.value.fragment_counter != sig.fragment_counter) {
        std::fprintf(stderr, "[%s] signalling prefix field mismatch\n", label);
        return 1;
    }

    auto msg = atsc3::mmt_si_message_header_len32::decode(body.subspan(6));
    if (!msg.ok) {
        std::fprintf(stderr, "[%s] mmt_si_message_header_len32 decode: %s\n", label,
                     msg.error.c_str());
        return 1;
    }
    if (msg.value.message_id != message_id ||
        msg.value.message_version != message_version) {
        std::fprintf(stderr, "[%s] message header id/version mismatch\n", label);
        return 1;
    }
    if (msg.value.message_byte_length != static_cast<std::uint32_t>(inner_si)) {
        std::fprintf(stderr, "[%s] message_byte_length mismatch\n", label);
        return 1;
    }

    std::span<const std::byte> tail = msg.value.payload;
    if (with_length32_envelope) {
        auto env = atsc3::mmt_si_length32_envelope::decode(tail);
        if (!env.ok) {
            std::fprintf(stderr, "[%s] mmt_si_length32_envelope decode: %s\n", label,
                         env.error.c_str());
            return 1;
        }
        if (env.value.body_byte_length !=
            static_cast<std::uint32_t>(loop_wire)) {
            std::fprintf(stderr, "[%s] envelope body_byte_length mismatch\n", label);
            return 1;
        }
        tail = std::span<const std::byte>(
            env.value.payload.data(), env.value.payload.size());
    }
    if (with_descriptor_loop) {
        auto lp = atsc3::mmt_si_descriptor_loop_u32::decode(tail);
        if (!lp.ok) {
            std::fprintf(stderr, "[%s] mmt_si_descriptor_loop_u32 decode: %s\n", label,
                         lp.error.c_str());
            return 1;
        }
        if (lp.value.loop_length !=
            static_cast<std::uint32_t>(payload.size())) {
            std::fprintf(stderr, "[%s] descriptor loop_length mismatch\n", label);
            return 1;
        }
        if (!span_equal(
                tail.subspan(sizeof(std::uint32_t),
                             static_cast<std::size_t>(lp.value.loop_length)),
                std::span<const std::byte>(payload))) {
            std::fprintf(stderr, "[%s] descriptor loop body mismatch\n", label);
            return 1;
        }
    } else if (!span_equal(tail, std::span<const std::byte>(payload))) {
        std::fprintf(stderr, "[%s] message body tail mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_pa_table_headers_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.mmt_si_message_version                = 1;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows           = {row_t{32, 1, 0}};
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    constexpr std::size_t k_pa_one_row = 3u + 4u;
    const std::size_t inner_si         = k_pa_one_row + payload.size();
    const std::size_t msg_wire         = 7u + inner_si;
    const std::size_t want_len         = 4u + 2u + msg_wire;
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto mh = atsc3::mmtp_header_word0::decode(body.subspan(0, 4));
    if (!mh.ok || mh.value.payload_type != payload_type ||
        mh.value.packet_id != packet_id) {
        std::fprintf(stderr, "[%s] mmtp word0 mismatch\n", label);
        return 1;
    }
    auto sg = atsc3::mmtp_payload_signalling_prefix::decode(body.subspan(4, 2));
    if (!sg.ok) {
        std::fprintf(stderr, "[%s] signalling prefix decode: %s\n", label,
                     sg.error.c_str());
        return 1;
    }

    auto msg = atsc3::mmt_si_message_header_len32::decode(body.subspan(6));
    if (!msg.ok) {
        std::fprintf(stderr, "[%s] mmt_si_message_header_len32 decode: %s\n", label,
                     msg.error.c_str());
        return 1;
    }
    if (msg.value.message_byte_length != static_cast<std::uint32_t>(inner_si)) {
        std::fprintf(stderr, "[%s] message_byte_length mismatch\n", label);
        return 1;
    }

    auto pah = atsc3::mmt_si_pa_table_headers::decode(msg.value.payload);
    if (!pah.ok) {
        std::fprintf(stderr, "[%s] mmt_si_pa_table_headers decode: %s\n", label,
                     pah.error.c_str());
        return 1;
    }
    if (pah.value.number_of_tables != 1u || pah.value.elements.size() != 1u) {
        std::fprintf(stderr, "[%s] PA table index row count mismatch\n", label);
        return 1;
    }
    if (pah.value.elements[0].table_id != 32u ||
        pah.value.elements[0].table_version != 1u ||
        pah.value.elements[0].table_length != 0u) {
        std::fprintf(stderr, "[%s] PA table header row field mismatch\n", label);
        return 1;
    }
    std::span<const std::byte> tail = msg.value.payload.subspan(pah.bytes_consumed);
    if (!span_equal(tail, std::span<const std::byte>(payload))) {
        std::fprintf(stderr, "[%s] payload after PA table headers mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_pa_table_body_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    if (payload.size() > 65535u) {
        std::fprintf(stderr, "[%s] payload too large for table_length\n", label);
        return 1;
    }
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.mmt_si_message_version                = 1;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{32, 1, static_cast<std::uint16_t>(payload.size())}};
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    constexpr std::size_t k_pa_one_row = 3u + 4u;
    const std::size_t inner_si         = k_pa_one_row + payload.size();
    const std::size_t msg_wire         = 7u + inner_si;
    const std::size_t want_len         = 4u + 2u + msg_wire;
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto mh = atsc3::mmtp_header_word0::decode(body.subspan(0, 4));
    if (!mh.ok || mh.value.payload_type != payload_type ||
        mh.value.packet_id != packet_id) {
        std::fprintf(stderr, "[%s] mmtp word0 mismatch\n", label);
        return 1;
    }
    auto sg = atsc3::mmtp_payload_signalling_prefix::decode(body.subspan(4, 2));
    if (!sg.ok) {
        std::fprintf(stderr, "[%s] signalling prefix decode: %s\n", label,
                     sg.error.c_str());
        return 1;
    }

    auto msg = atsc3::mmt_si_message_header_len32::decode(body.subspan(6));
    if (!msg.ok) {
        std::fprintf(stderr, "[%s] mmt_si_message_header_len32 decode: %s\n", label,
                     msg.error.c_str());
        return 1;
    }
    if (msg.value.message_byte_length != static_cast<std::uint32_t>(inner_si)) {
        std::fprintf(stderr, "[%s] message_byte_length mismatch\n", label);
        return 1;
    }

    auto pah = atsc3::mmt_si_pa_table_headers::decode(msg.value.payload);
    if (!pah.ok) {
        std::fprintf(stderr, "[%s] mmt_si_pa_table_headers decode: %s\n", label,
                     pah.error.c_str());
        return 1;
    }
    if (pah.value.elements[0].table_length !=
        static_cast<std::uint16_t>(payload.size())) {
        std::fprintf(stderr, "[%s] PA table_length mismatch\n", label);
        return 1;
    }
    if (!span_equal(msg.value.payload.subspan(pah.bytes_consumed),
                    std::span<const std::byte>(payload))) {
        std::fprintf(stderr, "[%s] table body tail mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_pa_multi_table_bodies_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    constexpr std::size_t k_body1 = 4u;
    constexpr std::size_t k_body2 = 4u;
    if (payload.size() != k_body1 + k_body2) {
        std::fprintf(stderr, "[%s] payload size must be %zu\n", label,
                     k_body1 + k_body2);
        return 1;
    }
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.mmt_si_message_version                = 1;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{32, 1, static_cast<std::uint16_t>(k_body1)},
        row_t{128, 0, static_cast<std::uint16_t>(k_body2)}};
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    constexpr std::size_t k_pa_two_rows = 3u + 8u;
    const std::size_t inner_si          = k_pa_two_rows + payload.size();
    const std::size_t msg_wire          = 7u + inner_si;
    const std::size_t want_len          = 4u + 2u + msg_wire;
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto msg = atsc3::mmt_si_message_header_len32::decode(body.subspan(6));
    if (!msg.ok) {
        std::fprintf(stderr, "[%s] mmt_si_message_header_len32 decode: %s\n", label,
                     msg.error.c_str());
        return 1;
    }
    if (msg.value.message_byte_length != static_cast<std::uint32_t>(inner_si)) {
        std::fprintf(stderr, "[%s] message_byte_length mismatch\n", label);
        return 1;
    }

    auto pah = atsc3::mmt_si_pa_table_headers::decode(msg.value.payload);
    if (!pah.ok) {
        std::fprintf(stderr, "[%s] mmt_si_pa_table_headers decode: %s\n", label,
                     pah.error.c_str());
        return 1;
    }
    if (pah.value.number_of_tables != 2u || pah.value.elements.size() != 2u) {
        std::fprintf(stderr, "[%s] PA table row count mismatch\n", label);
        return 1;
    }
    if (pah.value.elements[0].table_id != 32u ||
        pah.value.elements[0].table_length != 4u ||
        pah.value.elements[1].table_id != 128u ||
        pah.value.elements[1].table_length != 4u) {
        std::fprintf(stderr, "[%s] PA header row field mismatch\n", label);
        return 1;
    }
    if (!span_equal(msg.value.payload.subspan(pah.bytes_consumed),
                    std::span<const std::byte>(payload))) {
        std::fprintf(stderr, "[%s] concatenated table bodies mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_pa_mixed_table_body_si_tail_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    constexpr std::size_t k_body = 4u;
    constexpr std::size_t k_tail = 3u;
    if (payload.size() != k_body + k_tail) {
        std::fprintf(stderr, "[%s] payload size must be %zu\n", label,
                     k_body + k_tail);
        return 1;
    }
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.mmt_si_message_version                = 1;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{32, 1, static_cast<std::uint16_t>(k_body)},
        row_t{128, 0, 0}};
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    constexpr std::size_t k_pa_two_rows = 3u + 8u;
    const std::size_t inner_si          = k_pa_two_rows + payload.size();
    const std::size_t want_len          = 4u + 2u + 7u + inner_si;
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto msg = atsc3::mmt_si_message_header_len32::decode(body.subspan(6));
    if (!msg.ok) {
        std::fprintf(stderr, "[%s] mmt_si_message_header_len32 decode: %s\n", label,
                     msg.error.c_str());
        return 1;
    }
    if (msg.value.message_byte_length != static_cast<std::uint32_t>(inner_si)) {
        std::fprintf(stderr, "[%s] message_byte_length mismatch\n", label);
        return 1;
    }

    auto pah = atsc3::mmt_si_pa_table_headers::decode(msg.value.payload);
    if (!pah.ok) {
        std::fprintf(stderr, "[%s] mmt_si_pa_table_headers decode: %s\n", label,
                     pah.error.c_str());
        return 1;
    }
    if (pah.value.elements[0].table_length != 4u ||
        pah.value.elements[1].table_length != 0u) {
        std::fprintf(stderr, "[%s] PA header row field mismatch\n", label);
        return 1;
    }
    if (!span_equal(msg.value.payload.subspan(pah.bytes_consumed),
                    std::span<const std::byte>(payload))) {
        std::fprintf(stderr, "[%s] body+SI tail mismatch\n", label);
        return 1;
    }
    const std::span<const std::byte> ingress(payload);
    if (!span_equal(msg.value.payload.subspan(pah.bytes_consumed, k_body),
                    ingress.subspan(0, k_body))) {
        std::fprintf(stderr, "[%s] MPT table body prefix mismatch\n", label);
        return 1;
    }
    if (!span_equal(
            msg.value.payload.subspan(pah.bytes_consumed + k_body, k_tail),
            ingress.subspan(k_body, k_tail))) {
        std::fprintf(stderr, "[%s] SI tail suffix mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_pa_table_headers_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.mmt_si_message_version                = 1;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body            = alp.value.payload;
    const std::size_t inner_si = payload.size();
    const std::size_t want_len = 4u + 2u + 7u + inner_si;
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto msg = atsc3::mmt_si_message_header_len32::decode(body.subspan(6));
    if (!msg.ok) {
        std::fprintf(stderr, "[%s] mmt_si_message_header_len32 decode: %s\n", label,
                     msg.error.c_str());
        return 1;
    }
    if (msg.value.message_byte_length != static_cast<std::uint32_t>(inner_si)) {
        std::fprintf(stderr, "[%s] message_byte_length mismatch\n", label);
        return 1;
    }

    auto pah = atsc3::mmt_si_pa_table_headers::decode(msg.value.payload);
    if (!pah.ok) {
        std::fprintf(stderr, "[%s] mmt_si_pa_table_headers decode: %s\n", label,
                     pah.error.c_str());
        return 1;
    }
    if (pah.value.number_of_tables != 1u || pah.value.elements.size() != 1u ||
        pah.value.elements[0].table_length != 0u) {
        std::fprintf(stderr, "[%s] PA table index row mismatch\n", label);
        return 1;
    }
    if (!span_equal(msg.value.payload, std::span<const std::byte>(payload))) {
        std::fprintf(stderr, "[%s] message body mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_pa_table_body_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.mmt_si_message_version                = 1;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body            = alp.value.payload;
    const std::size_t inner_si = payload.size();
    const std::size_t want_len = 4u + 2u + 7u + inner_si;
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto msg = atsc3::mmt_si_message_header_len32::decode(body.subspan(6));
    if (!msg.ok) {
        std::fprintf(stderr, "[%s] mmt_si_message_header_len32 decode: %s\n", label,
                     msg.error.c_str());
        return 1;
    }
    if (msg.value.message_byte_length != static_cast<std::uint32_t>(inner_si)) {
        std::fprintf(stderr, "[%s] message_byte_length mismatch\n", label);
        return 1;
    }

    auto pah = atsc3::mmt_si_pa_table_headers::decode(msg.value.payload);
    if (!pah.ok) {
        std::fprintf(stderr, "[%s] mmt_si_pa_table_headers decode: %s\n", label,
                     pah.error.c_str());
        return 1;
    }
    if (pah.value.elements[0].table_length != 4u) {
        std::fprintf(stderr, "[%s] PA table_length mismatch\n", label);
        return 1;
    }
    if (!span_equal(msg.value.payload, std::span<const std::byte>(payload))) {
        std::fprintf(stderr, "[%s] message body mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_pa_multi_table_bodies_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.mmt_si_message_version                = 1;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body            = alp.value.payload;
    const std::size_t inner_si = payload.size();
    const std::size_t want_len = 4u + 2u + 7u + inner_si;
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto msg = atsc3::mmt_si_message_header_len32::decode(body.subspan(6));
    if (!msg.ok) {
        std::fprintf(stderr, "[%s] mmt_si_message_header_len32 decode: %s\n", label,
                     msg.error.c_str());
        return 1;
    }
    if (msg.value.message_byte_length != static_cast<std::uint32_t>(inner_si)) {
        std::fprintf(stderr, "[%s] message_byte_length mismatch\n", label);
        return 1;
    }

    auto pah = atsc3::mmt_si_pa_table_headers::decode(msg.value.payload);
    if (!pah.ok) {
        std::fprintf(stderr, "[%s] mmt_si_pa_table_headers decode: %s\n", label,
                     pah.error.c_str());
        return 1;
    }
    if (pah.value.number_of_tables != 2u) {
        std::fprintf(stderr, "[%s] PA table row count mismatch\n", label);
        return 1;
    }
    if (!span_equal(msg.value.payload, std::span<const std::byte>(payload))) {
        std::fprintf(stderr, "[%s] message body mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_pa_mixed_table_body_si_tail_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.mmt_si_message_version                = 1;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body            = alp.value.payload;
    const std::size_t inner_si = payload.size();
    const std::size_t want_len = 4u + 2u + 7u + inner_si;
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto msg = atsc3::mmt_si_message_header_len32::decode(body.subspan(6));
    if (!msg.ok) {
        std::fprintf(stderr, "[%s] mmt_si_message_header_len32 decode: %s\n", label,
                     msg.error.c_str());
        return 1;
    }
    if (msg.value.message_byte_length != static_cast<std::uint32_t>(inner_si)) {
        std::fprintf(stderr, "[%s] message_byte_length mismatch\n", label);
        return 1;
    }

    auto pah = atsc3::mmt_si_pa_table_headers::decode(msg.value.payload);
    if (!pah.ok) {
        std::fprintf(stderr, "[%s] mmt_si_pa_table_headers decode: %s\n", label,
                     pah.error.c_str());
        return 1;
    }
    if (pah.value.number_of_tables != 2u ||
        pah.value.elements[0].table_length != 4u ||
        pah.value.elements[1].table_length != 0u) {
        std::fprintf(stderr, "[%s] PA header row field mismatch\n", label);
        return 1;
    }
    if (!span_equal(msg.value.payload, std::span<const std::byte>(payload))) {
        std::fprintf(stderr, "[%s] message body mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_table_body_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.mmt_si_message_version                = 1;
    cfg.validate_mmt_si_mpt_table_body        = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body            = alp.value.payload;
    const std::size_t inner_si = payload.size();
    const std::size_t want_len = 4u + 2u + 7u + inner_si;
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto msg = atsc3::mmt_si_message_header_len32::decode(body.subspan(6));
    if (!msg.ok) {
        std::fprintf(stderr, "[%s] mmt_si_message_header_len32 decode: %s\n", label,
                     msg.error.c_str());
        return 1;
    }
    if (msg.value.message_byte_length != static_cast<std::uint32_t>(inner_si)) {
        std::fprintf(stderr, "[%s] message_byte_length mismatch\n", label);
        return 1;
    }

    auto pah = atsc3::mmt_si_pa_table_headers::decode(msg.value.payload);
    if (!pah.ok) {
        std::fprintf(stderr, "[%s] mmt_si_pa_table_headers decode: %s\n", label,
                     pah.error.c_str());
        return 1;
    }
    auto mpt = atsc3::mmt_si_mpt_table::decode(
        msg.value.payload.subspan(pah.bytes_consumed));
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_table_body_prefix_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.mmt_si_message_version                = 1;
    cfg.validate_mmt_si_mpt_table_body        = true;
    cfg.validate_mmt_si_mpt_table_body_prefix = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body            = alp.value.payload;
    const std::size_t inner_si = payload.size();
    const std::size_t want_len = 4u + 2u + 7u + inner_si;
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto msg = atsc3::mmt_si_message_header_len32::decode(body.subspan(6));
    if (!msg.ok) {
        std::fprintf(stderr, "[%s] mmt_si_message_header_len32 decode: %s\n", label,
                     msg.error.c_str());
        return 1;
    }
    if (msg.value.message_byte_length != static_cast<std::uint32_t>(inner_si)) {
        std::fprintf(stderr, "[%s] message_byte_length mismatch\n", label);
        return 1;
    }

    auto pah = atsc3::mmt_si_pa_table_headers::decode(msg.value.payload);
    if (!pah.ok) {
        std::fprintf(stderr, "[%s] mmt_si_pa_table_headers decode: %s\n", label,
                     pah.error.c_str());
        return 1;
    }
    auto mpt = atsc3::mmt_si_mpt_table::decode(
        msg.value.payload.subspan(pah.bytes_consumed));
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_table_body_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.mmt_si_message_version                = 1;
    cfg.validate_mmt_si_plt_table_body        = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body            = alp.value.payload;
    const std::size_t inner_si = payload.size();
    const std::size_t want_len = 4u + 2u + 7u + inner_si;
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto msg = atsc3::mmt_si_message_header_len32::decode(body.subspan(6));
    if (!msg.ok) {
        std::fprintf(stderr, "[%s] mmt_si_message_header_len32 decode: %s\n", label,
                     msg.error.c_str());
        return 1;
    }
    if (msg.value.message_byte_length != static_cast<std::uint32_t>(inner_si)) {
        std::fprintf(stderr, "[%s] message_byte_length mismatch\n", label);
        return 1;
    }

    auto pah = atsc3::mmt_si_pa_table_headers::decode(msg.value.payload);
    if (!pah.ok) {
        std::fprintf(stderr, "[%s] mmt_si_pa_table_headers decode: %s\n", label,
                     pah.error.c_str());
        return 1;
    }
    auto plt = atsc3::mmt_si_plt_table::decode(
        msg.value.payload.subspan(pah.bytes_consumed));
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_table_body_prefix_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.mmt_si_message_version                = 1;
    cfg.validate_mmt_si_plt_table_body        = true;
    cfg.validate_mmt_si_plt_table_body_prefix = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body            = alp.value.payload;
    const std::size_t inner_si = payload.size();
    const std::size_t want_len = 4u + 2u + 7u + inner_si;
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto msg = atsc3::mmt_si_message_header_len32::decode(body.subspan(6));
    if (!msg.ok) {
        std::fprintf(stderr, "[%s] mmt_si_message_header_len32 decode: %s\n", label,
                     msg.error.c_str());
        return 1;
    }
    if (msg.value.message_byte_length != static_cast<std::uint32_t>(inner_si)) {
        std::fprintf(stderr, "[%s] message_byte_length mismatch\n", label);
        return 1;
    }

    auto pah = atsc3::mmt_si_pa_table_headers::decode(msg.value.payload);
    if (!pah.ok) {
        std::fprintf(stderr, "[%s] mmt_si_pa_table_headers decode: %s\n", label,
                     pah.error.c_str());
        return 1;
    }
    auto plt = atsc3::mmt_si_plt_table::decode(
        msg.value.payload.subspan(pah.bytes_consumed));
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_pa_inline_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                   = 0;
    cfg.mmt_si_message_version              = 1;
    cfg.validate_mmt_si_mpt_table_body      = true;
    cfg.validate_mmt_si_mpt_asset           = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body            = alp.value.payload;
    const std::size_t inner_si = payload.size();
    const std::size_t want_len = 4u + 2u + 7u + inner_si;
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto msg = atsc3::mmt_si_message_header_len32::decode(body.subspan(6));
    if (!msg.ok) {
        std::fprintf(stderr, "[%s] mmt_si_message_header_len32 decode: %s\n", label,
                     msg.error.c_str());
        return 1;
    }
    if (msg.value.message_byte_length != static_cast<std::uint32_t>(inner_si)) {
        std::fprintf(stderr, "[%s] message_byte_length mismatch\n", label);
        return 1;
    }

    auto pah = atsc3::mmt_si_pa_table_headers::decode(msg.value.payload);
    if (!pah.ok) {
        std::fprintf(stderr, "[%s] mmt_si_pa_table_headers decode: %s\n", label,
                     pah.error.c_str());
        return 1;
    }
    auto mpt = atsc3::mmt_si_mpt_table::decode(
        msg.value.payload.subspan(pah.bytes_consumed));
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 19u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 0u ||
        asset.value.location_count != 0u ||
        asset.value.asset_descriptors_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_id8_location_ipv4_pa_inline_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32            = true;
    cfg.mmt_si_message_id                              = 0;
    cfg.mmt_si_message_version                         = 1;
    cfg.validate_mmt_si_mpt_table_body                 = true;
    cfg.validate_mmt_si_mpt_asset_id8_location_ipv4    = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    const auto ingress = std::span<const std::byte>(payload);
    auto       pah     = atsc3::mmt_si_pa_table_headers::decode(ingress);
    if (!pah.ok || pah.bytes_consumed != 7u) {
        std::fprintf(stderr, "[%s] mmt_si_pa_table_headers fixture mismatch\n", label);
        return 1;
    }
    auto mpt = atsc3::mmt_si_mpt_table::decode(ingress.subspan(pah.bytes_consumed));
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 31u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_id8_location_ipv4::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 1u ||
        asset.value.asset_id != 1u || asset.value.location_count != 1u ||
        asset.value.location_type != 1u || asset.value.ipv4_src_addr != 0u ||
        asset.value.ipv4_dst_addr != 0u || asset.value.dst_port != 0u ||
        asset.value.asset_descriptors_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_id8_location_ipv4 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_id16_location_ipv6_nz_pa_inline_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32                 = true;
    cfg.mmt_si_message_id                                     = 0;
    cfg.mmt_si_message_version                                = 1;
    cfg.validate_mmt_si_mpt_table_body                        = true;
    cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz       = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    const auto ingress = std::span<const std::byte>(payload);
    auto       pah     = atsc3::mmt_si_pa_table_headers::decode(ingress);
    if (!pah.ok || pah.bytes_consumed != 7u) {
        std::fprintf(stderr, "[%s] mmt_si_pa_table_headers fixture mismatch\n", label);
        return 1;
    }
    auto mpt = atsc3::mmt_si_mpt_table::decode(ingress.subspan(pah.bytes_consumed));
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 56u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_id16_location_ipv6_nz::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 2u ||
        asset.value.asset_id_byte0 != 1u || asset.value.asset_id_byte1 != 2u ||
        asset.value.location_count != 1u || asset.value.location_type != 2u ||
        asset.value.ipv6_src_addr_0 != 0u || asset.value.ipv6_src_addr_1 != 0u ||
        asset.value.ipv6_src_addr_2 != 65535u ||
        asset.value.ipv6_src_addr_3 != 167772161u ||
        asset.value.ipv6_dst_addr_0 != 0u || asset.value.ipv6_dst_addr_1 != 0u ||
        asset.value.ipv6_dst_addr_2 != 65535u ||
        asset.value.ipv6_dst_addr_3 != 3758096385u ||
        asset.value.dst_port != 5000u || asset.value.asset_descriptors_length != 0u) {
        std::fprintf(stderr,
                     "[%s] mmt_si_mpt_asset_id16_location_ipv6_nz mismatch\n",
                     label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_delivery_pa_inline_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                   = 0;
    cfg.mmt_si_message_version              = 1;
    cfg.validate_mmt_si_plt_table_body        = true;
    cfg.validate_mmt_si_plt_delivery_info     = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body            = alp.value.payload;
    const std::size_t inner_si = payload.size();
    const std::size_t want_len = 4u + 2u + 7u + inner_si;
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto msg = atsc3::mmt_si_message_header_len32::decode(body.subspan(6));
    if (!msg.ok) {
        std::fprintf(stderr, "[%s] mmt_si_message_header_len32 decode: %s\n", label,
                     msg.error.c_str());
        return 1;
    }
    if (msg.value.message_byte_length != static_cast<std::uint32_t>(inner_si)) {
        std::fprintf(stderr, "[%s] message_byte_length mismatch\n", label);
        return 1;
    }

    auto pah = atsc3::mmt_si_pa_table_headers::decode(msg.value.payload);
    if (!pah.ok) {
        std::fprintf(stderr, "[%s] mmt_si_pa_table_headers decode: %s\n", label,
                     pah.error.c_str());
        return 1;
    }
    auto plt = atsc3::mmt_si_plt_table::decode(
        msg.value.payload.subspan(pah.bytes_consumed));
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 9u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 0u ||
        pref.value.num_of_ip_delivery != 1u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto delivery = atsc3::mmt_si_plt_delivery_info::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!delivery.ok || delivery.value.location_type != 0u ||
        delivery.value.descripor_loop_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_delivery_info mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_delivery_url3_pa_inline_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32      = true;
    cfg.mmt_si_message_id                        = 0;
    cfg.mmt_si_message_version                   = 1;
    cfg.validate_mmt_si_plt_table_body           = true;
    cfg.validate_mmt_si_plt_delivery_info_url_3  = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    const auto ingress = std::span<const std::byte>(payload);
    auto       pah     = atsc3::mmt_si_pa_table_headers::decode(ingress);
    if (!pah.ok || pah.bytes_consumed != 7u) {
        std::fprintf(stderr, "[%s] mmt_si_pa_table_headers fixture mismatch\n", label);
        return 1;
    }
    auto plt = atsc3::mmt_si_plt_table::decode(
        ingress.subspan(pah.bytes_consumed));
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 13u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 0u ||
        pref.value.num_of_ip_delivery != 1u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto delivery = atsc3::mmt_si_plt_delivery_info_url_3::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!delivery.ok || delivery.value.location_type != 5u ||
        delivery.value.url_length != 3u ||
        delivery.value.descripor_loop_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_delivery_info_url_3 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_table_body_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{32, 1, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_mpt_table_body = true;
    cfg.validate_mmt_si_mpt_table_body_prefix = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                   = 16;
    cfg.mmt_si_message_version              = 0;
    cfg.validate_mmt_si_mpt_table_body      = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpi_descriptor_loop_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32    = true;
    cfg.mmt_si_message_id                      = 1;
    cfg.mmt_si_message_version                 = 0;
    cfg.prepend_mmt_si_descriptor_loop_u32     = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                   = 16;
    cfg.mmt_si_message_version              = 0;
    cfg.validate_mmt_si_mpt_table_body      = true;
    cfg.validate_mmt_si_mpt_asset           = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 19u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 0u ||
        asset.value.location_count != 0u ||
        asset.value.asset_descriptors_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_id8_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                   = 16;
    cfg.mmt_si_message_version              = 0;
    cfg.validate_mmt_si_mpt_table_body      = true;
    cfg.validate_mmt_si_mpt_asset_id8       = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 20u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_id8::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 1u ||
        asset.value.asset_id != 1u || asset.value.location_count != 0u ||
        asset.value.asset_descriptors_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_id8 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_delivery_info_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32   = true;
    cfg.mmt_si_message_id                     = 128;
    cfg.mmt_si_message_version                = 0;
    cfg.validate_mmt_si_plt_table_body        = true;
    cfg.validate_mmt_si_plt_delivery_info     = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 9u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 0u ||
        pref.value.num_of_ip_delivery != 1u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto delivery = atsc3::mmt_si_plt_delivery_info::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!delivery.ok || delivery.value.location_type != 0u ||
        delivery.value.descripor_loop_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_delivery_info mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_descriptors4_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32    = true;
    cfg.mmt_si_message_id                      = 16;
    cfg.mmt_si_message_version                 = 0;
    cfg.validate_mmt_si_mpt_table_body         = true;
    cfg.validate_mmt_si_mpt_asset_descriptors4 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 23u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_descriptors4::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 0u ||
        asset.value.location_count != 0u ||
        asset.value.asset_descriptors_length != 4u ||
        asset.value.descriptor_byte0 != 0xDEu ||
        asset.value.descriptor_byte1 != 0xADu ||
        asset.value.descriptor_byte2 != 0xBEu ||
        asset.value.descriptor_byte3 != 0xEFu) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_descriptors4 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_location_ipv4_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32        = true;
    cfg.mmt_si_message_id                          = 16;
    cfg.mmt_si_message_version                     = 0;
    cfg.validate_mmt_si_mpt_table_body             = true;
    cfg.validate_mmt_si_mpt_asset_location_ipv4    = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 30u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_location_ipv4::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 0u ||
        asset.value.location_count != 1u || asset.value.location_type != 1u ||
        asset.value.ipv4_src_addr != 0u || asset.value.ipv4_dst_addr != 0u ||
        asset.value.dst_port != 0u ||
        asset.value.asset_descriptors_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_location_ipv4 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_package_entry_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32   = true;
    cfg.mmt_si_message_id                     = 128;
    cfg.mmt_si_message_version                = 0;
    cfg.validate_mmt_si_plt_table_body        = true;
    cfg.validate_mmt_si_plt_package_entry     = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 6u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 1u ||
        pref.value.num_of_ip_delivery != 0u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto entry = atsc3::mmt_si_plt_package_entry::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!entry.ok || entry.value.MMT_package_id_length != 0u ||
        entry.value.location_type != 0u || entry.value.packet_id != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_package_entry mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_package_entry_id8_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32      = true;
    cfg.mmt_si_message_id                        = 128;
    cfg.mmt_si_message_version                   = 0;
    cfg.validate_mmt_si_plt_table_body           = true;
    cfg.validate_mmt_si_plt_package_entry_id8  = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 7u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 1u ||
        pref.value.num_of_ip_delivery != 0u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto entry = atsc3::mmt_si_plt_package_entry_id8::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!entry.ok || entry.value.MMT_package_id_length != 1u ||
        entry.value.MMT_package_id != 1u || entry.value.location_type != 0u ||
        entry.value.packet_id != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_package_entry_id8 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_delivery_info_ipv6_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32        = true;
    cfg.mmt_si_message_id                          = 128;
    cfg.mmt_si_message_version                     = 0;
    cfg.validate_mmt_si_plt_table_body             = true;
    cfg.validate_mmt_si_plt_delivery_info_ipv6     = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 43u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 0u ||
        pref.value.num_of_ip_delivery != 1u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto delivery = atsc3::mmt_si_plt_delivery_info_ipv6::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!delivery.ok || delivery.value.location_type != 2u ||
        delivery.value.descripor_loop_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_delivery_info_ipv6 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_delivery_info_url_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32         = true;
    cfg.mmt_si_message_id                           = 128;
    cfg.mmt_si_message_version                      = 0;
    cfg.validate_mmt_si_plt_table_body              = true;
    cfg.validate_mmt_si_plt_delivery_info_url       = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 10u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 0u ||
        pref.value.num_of_ip_delivery != 1u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto delivery = atsc3::mmt_si_plt_delivery_info_url::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!delivery.ok || delivery.value.location_type != 5u ||
        delivery.value.url_length != 0u ||
        delivery.value.descripor_loop_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_delivery_info_url mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_package_entry_ipv4_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32      = true;
    cfg.mmt_si_message_id                        = 128;
    cfg.mmt_si_message_version                   = 0;
    cfg.validate_mmt_si_plt_table_body           = true;
    cfg.validate_mmt_si_plt_package_entry_ipv4   = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 14u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 1u ||
        pref.value.num_of_ip_delivery != 0u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto entry = atsc3::mmt_si_plt_package_entry_ipv4::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!entry.ok || entry.value.MMT_package_id_length != 0u ||
        entry.value.location_type != 1u || entry.value.ipv4_src_addr != 0u ||
        entry.value.ipv4_dst_addr != 0u || entry.value.dst_port != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_package_entry_ipv4 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_package_entry_ipv6_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32         = true;
    cfg.mmt_si_message_id                           = 128;
    cfg.mmt_si_message_version                      = 0;
    cfg.validate_mmt_si_plt_table_body              = true;
    cfg.validate_mmt_si_plt_package_entry_ipv6      = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 38u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 1u ||
        pref.value.num_of_ip_delivery != 0u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto entry = atsc3::mmt_si_plt_package_entry_ipv6::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!entry.ok || entry.value.MMT_package_id_length != 0u ||
        entry.value.location_type != 2u || entry.value.ipv6_src_addr_0 != 0u ||
        entry.value.ipv6_src_addr_1 != 0u || entry.value.ipv6_src_addr_2 != 0u ||
        entry.value.ipv6_src_addr_3 != 0u || entry.value.ipv6_dst_addr_0 != 0u ||
        entry.value.ipv6_dst_addr_1 != 0u || entry.value.ipv6_dst_addr_2 != 0u ||
        entry.value.ipv6_dst_addr_3 != 0u || entry.value.dst_port != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_package_entry_ipv6 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_delivery_info_url_3_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32          = true;
    cfg.mmt_si_message_id                            = 128;
    cfg.mmt_si_message_version                       = 0;
    cfg.validate_mmt_si_plt_table_body               = true;
    cfg.validate_mmt_si_plt_delivery_info_url_3      = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 13u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 0u ||
        pref.value.num_of_ip_delivery != 1u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto delivery = atsc3::mmt_si_plt_delivery_info_url_3::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!delivery.ok || delivery.value.location_type != 5u ||
        delivery.value.url_length != 3u || delivery.value.url_byte0 != 0x6Cu ||
        delivery.value.url_byte1 != 0x61u || delivery.value.url_byte2 != 0x62u ||
        delivery.value.descripor_loop_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_delivery_info_url_3 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_delivery_info_url_4_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32           = true;
    cfg.mmt_si_message_id                             = 128;
    cfg.mmt_si_message_version                        = 0;
    cfg.validate_mmt_si_plt_table_body                = true;
    cfg.validate_mmt_si_plt_delivery_info_url_4         = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 14u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 0u ||
        pref.value.num_of_ip_delivery != 1u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto delivery = atsc3::mmt_si_plt_delivery_info_url_4::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!delivery.ok || delivery.value.location_type != 5u ||
        delivery.value.url_length != 4u || delivery.value.url_byte0 != 0x68u ||
        delivery.value.url_byte1 != 0x74u || delivery.value.url_byte2 != 0x74u ||
        delivery.value.url_byte3 != 0x70u ||
        delivery.value.descripor_loop_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_delivery_info_url_4 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_delivery_info_ipv4_nz_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32            = true;
    cfg.mmt_si_message_id                              = 128;
    cfg.mmt_si_message_version                         = 0;
    cfg.validate_mmt_si_plt_table_body                 = true;
    cfg.validate_mmt_si_plt_delivery_info_ipv4_nz      = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 19u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 0u ||
        pref.value.num_of_ip_delivery != 1u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto delivery = atsc3::mmt_si_plt_delivery_info_ipv4_nz::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!delivery.ok || delivery.value.location_type != 1u ||
        delivery.value.ipv4_src_addr != 0x0A000001u ||
        delivery.value.ipv4_dst_addr != 0xE0000001u ||
        delivery.value.dst_port != 5000u ||
        delivery.value.descripor_loop_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_delivery_info_ipv4_nz mismatch\n",
                     label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_package_entry_ipv4_nz_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32             = true;
    cfg.mmt_si_message_id                               = 128;
    cfg.mmt_si_message_version                          = 0;
    cfg.validate_mmt_si_plt_table_body                  = true;
    cfg.validate_mmt_si_plt_package_entry_ipv4_nz       = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 14u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 1u ||
        pref.value.num_of_ip_delivery != 0u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto entry = atsc3::mmt_si_plt_package_entry_ipv4_nz::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!entry.ok || entry.value.MMT_package_id_length != 0u ||
        entry.value.location_type != 1u ||
        entry.value.ipv4_src_addr != 0x0A000001u ||
        entry.value.ipv4_dst_addr != 0xE0000001u ||
        entry.value.dst_port != 5000u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_package_entry_ipv4_nz mismatch\n",
                     label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_package_entry_ipv6_nz_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32              = true;
    cfg.mmt_si_message_id                                = 128;
    cfg.mmt_si_message_version                           = 0;
    cfg.validate_mmt_si_plt_table_body                   = true;
    cfg.validate_mmt_si_plt_package_entry_ipv6_nz        = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 38u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 1u ||
        pref.value.num_of_ip_delivery != 0u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto entry = atsc3::mmt_si_plt_package_entry_ipv6_nz::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!entry.ok || entry.value.MMT_package_id_length != 0u ||
        entry.value.location_type != 2u ||
        entry.value.ipv6_src_addr_0 != 0u || entry.value.ipv6_src_addr_1 != 0u ||
        entry.value.ipv6_src_addr_2 != 0x0000FFFFu ||
        entry.value.ipv6_src_addr_3 != 0x0A000001u ||
        entry.value.ipv6_dst_addr_0 != 0u || entry.value.ipv6_dst_addr_1 != 0u ||
        entry.value.ipv6_dst_addr_2 != 0x0000FFFFu ||
        entry.value.ipv6_dst_addr_3 != 0xE0000001u ||
        entry.value.dst_port != 5000u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_package_entry_ipv6_nz mismatch\n",
                     label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_location_ipv4_nz_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32              = true;
    cfg.mmt_si_message_id                                = 16;
    cfg.mmt_si_message_version                           = 0;
    cfg.validate_mmt_si_mpt_table_body                   = true;
    cfg.validate_mmt_si_mpt_asset_location_ipv4_nz       = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 30u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_location_ipv4_nz::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 0u ||
        asset.value.location_count != 1u || asset.value.location_type != 1u ||
        asset.value.ipv4_src_addr != 0x0A000001u ||
        asset.value.ipv4_dst_addr != 0xE0000001u ||
        asset.value.dst_port != 5000u ||
        asset.value.asset_descriptors_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_location_ipv4_nz mismatch\n",
                     label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_location0_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                   = 16;
    cfg.mmt_si_message_version              = 0;
    cfg.validate_mmt_si_mpt_table_body       = true;
    cfg.validate_mmt_si_mpt_asset_location0 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 22u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_location0::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 0u ||
        asset.value.location_count != 1u || asset.value.location_type != 0u ||
        asset.value.packet_id != 0u ||
        asset.value.asset_descriptors_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_location0 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}


int run_mmtp_signalling_prefix_with_mpt_asset_id8_location_ipv4_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                   = 16;
    cfg.mmt_si_message_version              = 0;
    cfg.validate_mmt_si_mpt_table_body                 = true;
    cfg.validate_mmt_si_mpt_asset_id8_location_ipv4 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 31u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_id8_location_ipv4::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 1u ||
        asset.value.asset_id != 1u || asset.value.location_count != 1u ||
        asset.value.location_type != 1u || asset.value.ipv4_src_addr != 0u ||
        asset.value.ipv4_dst_addr != 0u || asset.value.dst_port != 0u ||
        asset.value.asset_descriptors_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_id8_location_ipv4 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}


int run_mmtp_signalling_prefix_with_plt_package_entry_id8_location_ipv4_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                   = 128;
    cfg.mmt_si_message_version              = 0;
    cfg.validate_mmt_si_plt_table_body = true;
    cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 15u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 1u ||
        pref.value.num_of_ip_delivery != 0u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto entry = atsc3::mmt_si_plt_package_entry_id8_location_ipv4::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!entry.ok || entry.value.MMT_package_id_length != 1u ||
        entry.value.MMT_package_id != 1u || entry.value.location_type != 1u ||
        entry.value.ipv4_src_addr != 0u || entry.value.ipv4_dst_addr != 0u ||
        entry.value.dst_port != 0u) {
        std::fprintf(stderr,
                     "[%s] mmt_si_plt_package_entry_id8_location_ipv4 mismatch\n",
                     label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}


int run_mmtp_signalling_prefix_with_mpt_asset_id8_location_ipv6_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                   = 16;
    cfg.mmt_si_message_version              = 0;
    cfg.validate_mmt_si_mpt_table_body                 = true;
    cfg.validate_mmt_si_mpt_asset_id8_location_ipv6 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 55u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_id8_location_ipv6::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 1u ||
        asset.value.asset_id != 1u || asset.value.location_count != 1u ||
        asset.value.location_type != 2u || asset.value.ipv6_src_addr_0 != 0u ||
        asset.value.ipv6_src_addr_1 != 0u || asset.value.ipv6_src_addr_2 != 0u ||
        asset.value.ipv6_src_addr_3 != 0u || asset.value.ipv6_dst_addr_0 != 0u ||
        asset.value.ipv6_dst_addr_1 != 0u || asset.value.ipv6_dst_addr_2 != 0u ||
        asset.value.ipv6_dst_addr_3 != 0u || asset.value.dst_port != 0u ||
        asset.value.asset_descriptors_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_id8_location_ipv6 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}


int run_mmtp_signalling_prefix_with_plt_package_entry_id8_location_ipv6_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                   = 128;
    cfg.mmt_si_message_version              = 0;
    cfg.validate_mmt_si_plt_table_body = true;
    cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 39u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 1u ||
        pref.value.num_of_ip_delivery != 0u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto entry = atsc3::mmt_si_plt_package_entry_id8_location_ipv6::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!entry.ok || entry.value.MMT_package_id_length != 1u ||
        entry.value.MMT_package_id != 1u || entry.value.location_type != 2u ||
        entry.value.ipv6_src_addr_0 != 0u || entry.value.ipv6_src_addr_1 != 0u ||
        entry.value.ipv6_src_addr_2 != 0u || entry.value.ipv6_src_addr_3 != 0u ||
        entry.value.ipv6_dst_addr_0 != 0u || entry.value.ipv6_dst_addr_1 != 0u ||
        entry.value.ipv6_dst_addr_2 != 0u || entry.value.ipv6_dst_addr_3 != 0u ||
        entry.value.dst_port != 0u) {
        std::fprintf(stderr,
                     "[%s] mmt_si_plt_package_entry_id8_location_ipv6 mismatch\n",
                     label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}


int run_mmtp_signalling_prefix_with_mpt_asset_location_ipv6_nz_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                   = 16;
    cfg.mmt_si_message_version              = 0;
    cfg.validate_mmt_si_mpt_table_body                = true;
    cfg.validate_mmt_si_mpt_asset_location_ipv6_nz = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 54u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_location_ipv6_nz::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 0u ||
        asset.value.location_count != 1u || asset.value.location_type != 2u ||
        asset.value.ipv6_src_addr_0 != 0u || asset.value.ipv6_src_addr_1 != 0u ||
        asset.value.ipv6_src_addr_2 != 0x0000FFFFu ||
        asset.value.ipv6_src_addr_3 != 0x0A000001u ||
        asset.value.ipv6_dst_addr_0 != 0u || asset.value.ipv6_dst_addr_1 != 0u ||
        asset.value.ipv6_dst_addr_2 != 0x0000FFFFu ||
        asset.value.ipv6_dst_addr_3 != 0xE0000001u ||
        asset.value.dst_port != 5000u ||
        asset.value.asset_descriptors_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_location_ipv6_nz mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}


int run_mmtp_signalling_prefix_with_plt_package_entry_id8_location_ipv4_nz_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                   = 128;
    cfg.mmt_si_message_version              = 0;
    cfg.validate_mmt_si_plt_table_body = true;
    cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4_nz = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 15u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 1u ||
        pref.value.num_of_ip_delivery != 0u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto entry = atsc3::mmt_si_plt_package_entry_id8_location_ipv4_nz::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!entry.ok || entry.value.MMT_package_id_length != 1u ||
        entry.value.MMT_package_id != 1u || entry.value.location_type != 1u ||
        entry.value.ipv4_src_addr != 0x0A000001u ||
        entry.value.ipv4_dst_addr != 0xE0000001u ||
        entry.value.dst_port != 5000u) {
        std::fprintf(stderr,
                     "[%s] mmt_si_plt_package_entry_id8_location_ipv4_nz mismatch\n",
                     label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}


int run_mmtp_signalling_prefix_with_plt_package_entry_id8_location_ipv6_nz_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                   = 128;
    cfg.mmt_si_message_version              = 0;
    cfg.validate_mmt_si_plt_table_body = true;
    cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6_nz = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 39u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 1u ||
        pref.value.num_of_ip_delivery != 0u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto entry = atsc3::mmt_si_plt_package_entry_id8_location_ipv6_nz::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!entry.ok || entry.value.MMT_package_id_length != 1u ||
        entry.value.MMT_package_id != 1u || entry.value.location_type != 2u ||
        entry.value.ipv6_src_addr_0 != 0u || entry.value.ipv6_src_addr_1 != 0u ||
        entry.value.ipv6_src_addr_2 != 0x0000FFFFu ||
        entry.value.ipv6_src_addr_3 != 0x0A000001u ||
        entry.value.ipv6_dst_addr_0 != 0u || entry.value.ipv6_dst_addr_1 != 0u ||
        entry.value.ipv6_dst_addr_2 != 0x0000FFFFu ||
        entry.value.ipv6_dst_addr_3 != 0xE0000001u ||
        entry.value.dst_port != 5000u) {
        std::fprintf(stderr,
                     "[%s] mmt_si_plt_package_entry_id8_location_ipv6_nz mismatch\n",
                     label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}


int run_mmtp_signalling_prefix_with_mpt_asset_id8_location_ipv4_nz_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                   = 16;
    cfg.mmt_si_message_version              = 0;
    cfg.validate_mmt_si_mpt_table_body                    = true;
    cfg.validate_mmt_si_mpt_asset_id8_location_ipv4_nz = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 31u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_id8_location_ipv4_nz::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 1u ||
        asset.value.asset_id != 1u || asset.value.location_count != 1u ||
        asset.value.location_type != 1u ||
        asset.value.ipv4_src_addr != 0x0A000001u ||
        asset.value.ipv4_dst_addr != 0xE0000001u ||
        asset.value.dst_port != 5000u ||
        asset.value.asset_descriptors_length != 0u) {
        std::fprintf(stderr,
                     "[%s] mmt_si_mpt_asset_id8_location_ipv4_nz mismatch\n",
                     label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}


int run_mmtp_signalling_prefix_with_mpt_asset_id8_location_ipv6_nz_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                   = 16;
    cfg.mmt_si_message_version              = 0;
    cfg.validate_mmt_si_mpt_table_body                    = true;
    cfg.validate_mmt_si_mpt_asset_id8_location_ipv6_nz = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 55u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_id8_location_ipv6_nz::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 1u ||
        asset.value.asset_id != 1u || asset.value.location_count != 1u ||
        asset.value.location_type != 2u || asset.value.ipv6_src_addr_0 != 0u ||
        asset.value.ipv6_src_addr_1 != 0u || asset.value.ipv6_src_addr_2 != 65535u ||
        asset.value.ipv6_src_addr_3 != 167772161u ||
        asset.value.ipv6_dst_addr_0 != 0u || asset.value.ipv6_dst_addr_1 != 0u ||
        asset.value.ipv6_dst_addr_2 != 65535u ||
        asset.value.ipv6_dst_addr_3 != 3758096385u || asset.value.dst_port != 5000u ||
        asset.value.asset_descriptors_length != 0u) {
        std::fprintf(stderr,
                     "[%s] mmt_si_mpt_asset_id8_location_ipv6_nz mismatch\n",
                     label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}


int run_mmtp_signalling_prefix_with_mpt_asset_id16_location_ipv4_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                   = 16;
    cfg.mmt_si_message_version              = 0;
    cfg.validate_mmt_si_mpt_table_body = true;
    cfg.validate_mmt_si_mpt_asset_id16_location_ipv4 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 32u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u || pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_id16_location_ipv4::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || (asset.value.asset_id_length != 2u ||
        asset.value.asset_id_byte0 != 1u || asset.value.asset_id_byte1 != 2u ||
        asset.value.location_count != 1u || asset.value.location_type != 1u ||
        asset.value.ipv4_src_addr != 0u || asset.value.ipv4_dst_addr != 0u ||
        asset.value.dst_port != 0u || asset.value.asset_descriptors_length != 0u)) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_id16_location_ipv4 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}


int run_mmtp_signalling_prefix_with_mpt_asset_id16_location_ipv4_nz_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                   = 16;
    cfg.mmt_si_message_version              = 0;
    cfg.validate_mmt_si_mpt_table_body = true;
    cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 32u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u || pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_id16_location_ipv4_nz::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || (asset.value.asset_id_length != 2u ||
        asset.value.asset_id_byte0 != 1u || asset.value.asset_id_byte1 != 2u ||
        asset.value.location_count != 1u || asset.value.location_type != 1u ||
        asset.value.ipv4_src_addr != 0x0A000001u || asset.value.ipv4_dst_addr != 0xE0000001u ||
        asset.value.dst_port != 5000u || asset.value.asset_descriptors_length != 0u)) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_id16_location_ipv4_nz mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}


int run_mmtp_signalling_prefix_with_mpt_asset_id16_location_ipv6_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                   = 16;
    cfg.mmt_si_message_version              = 0;
    cfg.validate_mmt_si_mpt_table_body = true;
    cfg.validate_mmt_si_mpt_asset_id16_location_ipv6 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 55u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u || pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset_span = mpt.value.payload.subspan(pref.bytes_consumed);
    std::vector<std::byte> asset_buf(asset_span.begin(), asset_span.end());
    if (asset_buf.size() == 50u) {
        asset_buf.push_back(std::byte{0});
    }
    auto asset = atsc3::mmt_si_mpt_asset_id16_location_ipv6::decode(asset_buf);
    if (!asset.ok || (asset.value.asset_id_length != 2u ||
        asset.value.asset_id_byte0 != 1u || asset.value.asset_id_byte1 != 2u ||
        asset.value.location_count != 1u || asset.value.location_type != 2u ||
        asset.value.ipv6_src_addr_0 != 0u || asset.value.ipv6_src_addr_1 != 0u ||
        asset.value.ipv6_src_addr_2 != 0u || asset.value.ipv6_src_addr_3 != 0u ||
        asset.value.ipv6_dst_addr_0 != 0u || asset.value.ipv6_dst_addr_1 != 0u ||
        asset.value.ipv6_dst_addr_2 != 0u || asset.value.ipv6_dst_addr_3 != 0u ||
        asset.value.dst_port != 0u || asset.value.asset_descriptors_length != 0u)) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_id16_location_ipv6 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}


int run_mmtp_signalling_prefix_with_mpt_asset_id16_location_ipv6_nz_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                   = 16;
    cfg.mmt_si_message_version              = 0;
    cfg.validate_mmt_si_mpt_table_body = true;
    cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 56u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u || pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_id16_location_ipv6_nz::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || (asset.value.asset_id_length != 2u ||
        asset.value.asset_id_byte0 != 1u || asset.value.asset_id_byte1 != 2u ||
        asset.value.location_count != 1u || asset.value.location_type != 2u ||
        asset.value.ipv6_src_addr_0 != 0u || asset.value.ipv6_src_addr_1 != 0u ||
        asset.value.ipv6_src_addr_2 != 65535u || asset.value.ipv6_src_addr_3 != 167772161u ||
        asset.value.ipv6_dst_addr_0 != 0u || asset.value.ipv6_dst_addr_1 != 0u ||
        asset.value.ipv6_dst_addr_2 != 65535u || asset.value.ipv6_dst_addr_3 != 3758096385u ||
        asset.value.dst_port != 5000u || asset.value.asset_descriptors_length != 0u)) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_id16_location_ipv6_nz mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}


int run_mmtp_signalling_prefix_with_mpt_asset_id16_descriptors4_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                   = 16;
    cfg.mmt_si_message_version              = 0;
    cfg.validate_mmt_si_mpt_table_body = true;
    cfg.validate_mmt_si_mpt_asset_id16_descriptors4 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 25u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u || pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_id16_descriptors4::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || (asset.value.asset_id_length != 2u ||
        asset.value.asset_id_byte0 != 1u || asset.value.asset_id_byte1 != 2u ||
        asset.value.location_count != 0u || asset.value.asset_descriptors_length != 4u ||
        asset.value.descriptor_byte0 != 0xDEu || asset.value.descriptor_byte1 != 0xADu ||
        asset.value.descriptor_byte2 != 0xBEu || asset.value.descriptor_byte3 != 0xEFu)) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_id16_descriptors4 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_location_ipv6_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32        = true;
    cfg.mmt_si_message_id                            = 16;
    cfg.mmt_si_message_version                       = 0;
    cfg.validate_mmt_si_mpt_table_body               = true;
    cfg.validate_mmt_si_mpt_asset_location_ipv6      = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 54u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_location_ipv6::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 0u ||
        asset.value.location_count != 1u || asset.value.location_type != 2u ||
        asset.value.ipv6_src_addr_0 != 0u || asset.value.ipv6_src_addr_1 != 0u ||
        asset.value.ipv6_src_addr_2 != 0u || asset.value.ipv6_src_addr_3 != 0u ||
        asset.value.ipv6_dst_addr_0 != 0u || asset.value.ipv6_dst_addr_1 != 0u ||
        asset.value.ipv6_dst_addr_2 != 0u || asset.value.ipv6_dst_addr_3 != 0u ||
        asset.value.dst_port != 0u ||
        asset.value.asset_descriptors_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_location_ipv6 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_id16_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                   = 16;
    cfg.mmt_si_message_version              = 0;
    cfg.validate_mmt_si_mpt_table_body      = true;
    cfg.validate_mmt_si_mpt_asset_id16      = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 21u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_id16::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 2u ||
        asset.value.asset_id_byte0 != 0x01u ||
        asset.value.asset_id_byte1 != 0x02u ||
        asset.value.location_count != 0u ||
        asset.value.asset_descriptors_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_id16 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_id8_descriptors4_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32            = true;
    cfg.mmt_si_message_id                              = 16;
    cfg.mmt_si_message_version                         = 0;
    cfg.validate_mmt_si_mpt_table_body                 = true;
    cfg.validate_mmt_si_mpt_asset_id8_descriptors4     = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 24u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_id8_descriptors4::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 1u ||
        asset.value.asset_id != 1u || asset.value.location_count != 0u ||
        asset.value.asset_descriptors_length != 4u ||
        asset.value.descriptor_byte0 != 0xDEu ||
        asset.value.descriptor_byte1 != 0xADu ||
        asset.value.descriptor_byte2 != 0xBEu ||
        asset.value.descriptor_byte3 != 0xEFu) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_id8_descriptors4 mismatch\n",
                     label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_delivery_info_ipv4_in_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32        = true;
    cfg.mmt_si_message_id                          = 128;
    cfg.mmt_si_message_version                     = 0;
    cfg.validate_mmt_si_plt_table_body             = true;
    cfg.validate_mmt_si_plt_delivery_info_ipv4     = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 19u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 0u ||
        pref.value.num_of_ip_delivery != 1u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto delivery = atsc3::mmt_si_plt_delivery_info_ipv4::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!delivery.ok || delivery.value.location_type != 1u ||
        delivery.value.descripor_loop_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_delivery_info_ipv4 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_consumption_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                   = 128;
    cfg.mmt_si_message_version              = 0;
    cfg.validate_mmt_si_plt_table_body      = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_descriptors4_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{32, 1, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_mpt_table_body         = true;
    cfg.validate_mmt_si_mpt_asset_descriptors4 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 23u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_descriptors4::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 0u ||
        asset.value.location_count != 0u ||
        asset.value.asset_descriptors_length != 4u ||
        asset.value.descriptor_byte0 != 0xDEu ||
        asset.value.descriptor_byte1 != 0xADu ||
        asset.value.descriptor_byte2 != 0xBEu ||
        asset.value.descriptor_byte3 != 0xEFu) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_descriptors4 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_id8_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{32, 1, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_mpt_table_body  = true;
    cfg.validate_mmt_si_mpt_asset_id8 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 20u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_id8::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 1u ||
        asset.value.asset_id != 1u || asset.value.location_count != 0u ||
        asset.value.asset_descriptors_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_id8 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_id16_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{32, 1, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_mpt_table_body   = true;
    cfg.validate_mmt_si_mpt_asset_id16 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 21u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_id16::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 2u ||
        asset.value.asset_id_byte0 != 0x01u ||
        asset.value.asset_id_byte1 != 0x02u ||
        asset.value.location_count != 0u ||
        asset.value.asset_descriptors_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_id16 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_location0_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{32, 1, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_mpt_table_body       = true;
    cfg.validate_mmt_si_mpt_asset_location0 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 22u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_location0::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 0u ||
        asset.value.location_count != 1u || asset.value.location_type != 0u ||
        asset.value.packet_id != 0u ||
        asset.value.asset_descriptors_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_location0 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_location_ipv4_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{32, 1, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_mpt_table_body            = true;
    cfg.validate_mmt_si_mpt_asset_location_ipv4 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 30u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_location_ipv4::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 0u ||
        asset.value.location_count != 1u || asset.value.location_type != 1u ||
        asset.value.ipv4_src_addr != 0u || asset.value.ipv4_dst_addr != 0u ||
        asset.value.dst_port != 0u ||
        asset.value.asset_descriptors_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_location_ipv4 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_location_ipv4_nz_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{32, 1, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_mpt_table_body               = true;
    cfg.validate_mmt_si_mpt_asset_location_ipv4_nz = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 30u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_location_ipv4_nz::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 0u ||
        asset.value.location_count != 1u || asset.value.location_type != 1u ||
        asset.value.ipv4_src_addr != 0x0A000001u ||
        asset.value.ipv4_dst_addr != 0xE0000001u ||
        asset.value.dst_port != 5000u ||
        asset.value.asset_descriptors_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_location_ipv4_nz mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_location_ipv6_nz_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{32, 1, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_mpt_table_body                = true;
    cfg.validate_mmt_si_mpt_asset_location_ipv6_nz = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 54u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_location_ipv6_nz::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 0u ||
        asset.value.location_count != 1u || asset.value.location_type != 2u ||
        asset.value.ipv6_src_addr_0 != 0u || asset.value.ipv6_src_addr_1 != 0u ||
        asset.value.ipv6_src_addr_2 != 0x0000FFFFu ||
        asset.value.ipv6_src_addr_3 != 0x0A000001u ||
        asset.value.ipv6_dst_addr_0 != 0u || asset.value.ipv6_dst_addr_1 != 0u ||
        asset.value.ipv6_dst_addr_2 != 0x0000FFFFu ||
        asset.value.ipv6_dst_addr_3 != 0xE0000001u ||
        asset.value.dst_port != 5000u ||
        asset.value.asset_descriptors_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_location_ipv6_nz mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_location_ipv6_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{32, 1, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_mpt_table_body            = true;
    cfg.validate_mmt_si_mpt_asset_location_ipv6 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 54u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_location_ipv6::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 0u ||
        asset.value.location_count != 1u || asset.value.location_type != 2u ||
        asset.value.ipv6_src_addr_0 != 0u || asset.value.ipv6_src_addr_1 != 0u ||
        asset.value.ipv6_src_addr_2 != 0u || asset.value.ipv6_src_addr_3 != 0u ||
        asset.value.ipv6_dst_addr_0 != 0u || asset.value.ipv6_dst_addr_1 != 0u ||
        asset.value.ipv6_dst_addr_2 != 0u || asset.value.ipv6_dst_addr_3 != 0u ||
        asset.value.dst_port != 0u ||
        asset.value.asset_descriptors_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_location_ipv6 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_id8_location_ipv4_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{32, 1, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_mpt_table_body                 = true;
    cfg.validate_mmt_si_mpt_asset_id8_location_ipv4 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 31u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_id8_location_ipv4::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 1u ||
        asset.value.asset_id != 1u || asset.value.location_count != 1u ||
        asset.value.location_type != 1u || asset.value.ipv4_src_addr != 0u ||
        asset.value.ipv4_dst_addr != 0u || asset.value.dst_port != 0u ||
        asset.value.asset_descriptors_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_id8_location_ipv4 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_id8_location_ipv4_nz_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{32, 1, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_mpt_table_body                    = true;
    cfg.validate_mmt_si_mpt_asset_id8_location_ipv4_nz = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 31u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_id8_location_ipv4_nz::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 1u ||
        asset.value.asset_id != 1u || asset.value.location_count != 1u ||
        asset.value.location_type != 1u ||
        asset.value.ipv4_src_addr != 0x0A000001u ||
        asset.value.ipv4_dst_addr != 0xE0000001u ||
        asset.value.dst_port != 5000u ||
        asset.value.asset_descriptors_length != 0u) {
        std::fprintf(stderr,
                     "[%s] mmt_si_mpt_asset_id8_location_ipv4_nz mismatch\n",
                     label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_id8_location_ipv6_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{32, 1, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_mpt_table_body                 = true;
    cfg.validate_mmt_si_mpt_asset_id8_location_ipv6 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 55u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_id8_location_ipv6::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 1u ||
        asset.value.asset_id != 1u || asset.value.location_count != 1u ||
        asset.value.location_type != 2u || asset.value.ipv6_src_addr_0 != 0u ||
        asset.value.ipv6_src_addr_1 != 0u || asset.value.ipv6_src_addr_2 != 0u ||
        asset.value.ipv6_src_addr_3 != 0u || asset.value.ipv6_dst_addr_0 != 0u ||
        asset.value.ipv6_dst_addr_1 != 0u || asset.value.ipv6_dst_addr_2 != 0u ||
        asset.value.ipv6_dst_addr_3 != 0u || asset.value.dst_port != 0u ||
        asset.value.asset_descriptors_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_id8_location_ipv6 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_id8_location_ipv6_nz_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{32, 1, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_mpt_table_body                    = true;
    cfg.validate_mmt_si_mpt_asset_id8_location_ipv6_nz = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 55u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_id8_location_ipv6_nz::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 1u ||
        asset.value.asset_id != 1u || asset.value.location_count != 1u ||
        asset.value.location_type != 2u || asset.value.ipv6_src_addr_0 != 0u ||
        asset.value.ipv6_src_addr_1 != 0u || asset.value.ipv6_src_addr_2 != 65535u ||
        asset.value.ipv6_src_addr_3 != 167772161u ||
        asset.value.ipv6_dst_addr_0 != 0u || asset.value.ipv6_dst_addr_1 != 0u ||
        asset.value.ipv6_dst_addr_2 != 65535u ||
        asset.value.ipv6_dst_addr_3 != 3758096385u || asset.value.dst_port != 5000u ||
        asset.value.asset_descriptors_length != 0u) {
        std::fprintf(stderr,
                     "[%s] mmt_si_mpt_asset_id8_location_ipv6_nz mismatch\n",
                     label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}


int run_mmtp_signalling_prefix_with_mpt_asset_id16_location_ipv4_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{32, 1, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_mpt_table_body = true;
    cfg.validate_mmt_si_mpt_asset_id16_location_ipv4 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 32u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u || pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_id16_location_ipv4::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || (asset.value.asset_id_length != 2u ||
        asset.value.asset_id_byte0 != 1u || asset.value.asset_id_byte1 != 2u ||
        asset.value.location_count != 1u || asset.value.location_type != 1u ||
        asset.value.ipv4_src_addr != 0u || asset.value.ipv4_dst_addr != 0u ||
        asset.value.dst_port != 0u || asset.value.asset_descriptors_length != 0u)) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_id16_location_ipv4 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_id16_location_ipv4_nz_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{32, 1, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_mpt_table_body = true;
    cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 32u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u || pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_id16_location_ipv4_nz::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || (asset.value.asset_id_length != 2u ||
        asset.value.asset_id_byte0 != 1u || asset.value.asset_id_byte1 != 2u ||
        asset.value.location_count != 1u || asset.value.location_type != 1u ||
        asset.value.ipv4_src_addr != 0x0A000001u || asset.value.ipv4_dst_addr != 0xE0000001u ||
        asset.value.dst_port != 5000u || asset.value.asset_descriptors_length != 0u)) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_id16_location_ipv4_nz mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_id16_location_ipv6_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{32, 1, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_mpt_table_body = true;
    cfg.validate_mmt_si_mpt_asset_id16_location_ipv6 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 55u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u || pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset_span = mpt.value.payload.subspan(pref.bytes_consumed);
    std::vector<std::byte> asset_buf(asset_span.begin(), asset_span.end());
    if (asset_buf.size() == 50u) {
        asset_buf.push_back(std::byte{0});
    }
    auto asset = atsc3::mmt_si_mpt_asset_id16_location_ipv6::decode(asset_buf);
    if (!asset.ok || (asset.value.asset_id_length != 2u ||
        asset.value.asset_id_byte0 != 1u || asset.value.asset_id_byte1 != 2u ||
        asset.value.location_count != 1u || asset.value.location_type != 2u ||
        asset.value.ipv6_src_addr_0 != 0u || asset.value.ipv6_src_addr_1 != 0u ||
        asset.value.ipv6_src_addr_2 != 0u || asset.value.ipv6_src_addr_3 != 0u ||
        asset.value.ipv6_dst_addr_0 != 0u || asset.value.ipv6_dst_addr_1 != 0u ||
        asset.value.ipv6_dst_addr_2 != 0u || asset.value.ipv6_dst_addr_3 != 0u ||
        asset.value.dst_port != 0u || asset.value.asset_descriptors_length != 0u)) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_id16_location_ipv6 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_id16_location_ipv6_nz_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{32, 1, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_mpt_table_body = true;
    cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 56u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u || pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_id16_location_ipv6_nz::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || (asset.value.asset_id_length != 2u ||
        asset.value.asset_id_byte0 != 1u || asset.value.asset_id_byte1 != 2u ||
        asset.value.location_count != 1u || asset.value.location_type != 2u ||
        asset.value.ipv6_src_addr_0 != 0u || asset.value.ipv6_src_addr_1 != 0u ||
        asset.value.ipv6_src_addr_2 != 65535u || asset.value.ipv6_src_addr_3 != 167772161u ||
        asset.value.ipv6_dst_addr_0 != 0u || asset.value.ipv6_dst_addr_1 != 0u ||
        asset.value.ipv6_dst_addr_2 != 65535u || asset.value.ipv6_dst_addr_3 != 3758096385u ||
        asset.value.dst_port != 5000u || asset.value.asset_descriptors_length != 0u)) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_id16_location_ipv6_nz mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_id16_descriptors4_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{32, 1, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_mpt_table_body = true;
    cfg.validate_mmt_si_mpt_asset_id16_descriptors4 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 25u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u || pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_id16_descriptors4::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || (asset.value.asset_id_length != 2u ||
        asset.value.asset_id_byte0 != 1u || asset.value.asset_id_byte1 != 2u ||
        asset.value.location_count != 0u || asset.value.asset_descriptors_length != 4u ||
        asset.value.descriptor_byte0 != 0xDEu || asset.value.descriptor_byte1 != 0xADu ||
        asset.value.descriptor_byte2 != 0xBEu || asset.value.descriptor_byte3 != 0xEFu)) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_id16_descriptors4 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_mpt_asset_id8_descriptors4_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{32, 1, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_mpt_table_body = true;
    cfg.validate_mmt_si_mpt_asset_id8_descriptors4 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 24u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u || pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset_id8_descriptors4::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || (asset.value.asset_id_length != 1u || asset.value.asset_id != 1u ||
        asset.value.location_count != 0u || asset.value.asset_descriptors_length != 4u ||
        asset.value.descriptor_byte0 != 0xDEu || asset.value.descriptor_byte1 != 0xADu ||
        asset.value.descriptor_byte2 != 0xBEu || asset.value.descriptor_byte3 != 0xEFu)) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset_id8_descriptors4 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}
int run_mmtp_signalling_prefix_with_mpt_asset_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{32, 1, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_mpt_table_body = true;
    cfg.validate_mmt_si_mpt_asset      = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto mpt = atsc3::mmt_si_mpt_table::decode(payload);
    if (!mpt.ok || mpt.value.table_id != 32u || mpt.value.table_length != 19u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_mpt_table_body_prefix::decode(mpt.value.payload);
    if (!pref.ok || pref.value.number_of_assets != 1u ||
        pref.bytes_consumed != 5u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto asset = atsc3::mmt_si_mpt_asset::decode(
        mpt.value.payload.subspan(pref.bytes_consumed));
    if (!asset.ok || asset.value.asset_id_length != 0u ||
        asset.value.location_count != 0u ||
        asset.value.asset_descriptors_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_mpt_asset mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_delivery_info_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{128, 0, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_plt_table_body  = true;
    cfg.validate_mmt_si_plt_delivery_info = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 9u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 0u ||
        pref.value.num_of_ip_delivery != 1u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto delivery = atsc3::mmt_si_plt_delivery_info::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!delivery.ok || delivery.value.location_type != 0u ||
        delivery.value.descripor_loop_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_delivery_info mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_delivery_info_ipv4_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{128, 0, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_plt_table_body         = true;
    cfg.validate_mmt_si_plt_delivery_info_ipv4 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 19u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 0u ||
        pref.value.num_of_ip_delivery != 1u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto delivery = atsc3::mmt_si_plt_delivery_info_ipv4::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!delivery.ok || delivery.value.location_type != 1u ||
        delivery.value.descripor_loop_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_delivery_info_ipv4 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_delivery_info_ipv4_nz_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{128, 0, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_plt_table_body           = true;
    cfg.validate_mmt_si_plt_delivery_info_ipv4_nz = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 19u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 0u ||
        pref.value.num_of_ip_delivery != 1u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto delivery = atsc3::mmt_si_plt_delivery_info_ipv4_nz::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!delivery.ok || delivery.value.location_type != 1u ||
        delivery.value.ipv4_src_addr != 0x0A000001u ||
        delivery.value.ipv4_dst_addr != 0xE0000001u ||
        delivery.value.dst_port != 5000u ||
        delivery.value.descripor_loop_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_delivery_info_ipv4_nz mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_delivery_info_ipv6_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{128, 0, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_plt_table_body         = true;
    cfg.validate_mmt_si_plt_delivery_info_ipv6 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 43u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 0u ||
        pref.value.num_of_ip_delivery != 1u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto delivery = atsc3::mmt_si_plt_delivery_info_ipv6::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!delivery.ok || delivery.value.location_type != 2u ||
        delivery.value.descripor_loop_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_delivery_info_ipv6 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_delivery_info_url_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{128, 0, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_plt_table_body       = true;
    cfg.validate_mmt_si_plt_delivery_info_url = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 10u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 0u ||
        pref.value.num_of_ip_delivery != 1u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto delivery = atsc3::mmt_si_plt_delivery_info_url::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!delivery.ok || delivery.value.location_type != 5u ||
        delivery.value.url_length != 0u ||
        delivery.value.descripor_loop_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_delivery_info_url mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_delivery_info_url_3_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{128, 0, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_plt_table_body        = true;
    cfg.validate_mmt_si_plt_delivery_info_url_3 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 13u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 0u ||
        pref.value.num_of_ip_delivery != 1u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto delivery = atsc3::mmt_si_plt_delivery_info_url_3::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!delivery.ok || delivery.value.location_type != 5u ||
        delivery.value.url_length != 3u || delivery.value.url_byte0 != 0x6Cu ||
        delivery.value.url_byte1 != 0x61u || delivery.value.url_byte2 != 0x62u ||
        delivery.value.descripor_loop_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_delivery_info_url_3 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_delivery_info_url_4_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{128, 0, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_plt_table_body         = true;
    cfg.validate_mmt_si_plt_delivery_info_url_4 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 14u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 0u ||
        pref.value.num_of_ip_delivery != 1u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto delivery = atsc3::mmt_si_plt_delivery_info_url_4::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!delivery.ok || delivery.value.location_type != 5u ||
        delivery.value.url_length != 4u || delivery.value.url_byte0 != 0x68u ||
        delivery.value.url_byte1 != 0x74u || delivery.value.url_byte2 != 0x74u ||
        delivery.value.url_byte3 != 0x70u ||
        delivery.value.descripor_loop_length != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_delivery_info_url_4 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_package_entry_id8_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{128, 0, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_plt_table_body         = true;
    cfg.validate_mmt_si_plt_package_entry_id8 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 7u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 1u ||
        pref.value.num_of_ip_delivery != 0u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto entry = atsc3::mmt_si_plt_package_entry_id8::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!entry.ok || entry.value.MMT_package_id_length != 1u ||
        entry.value.MMT_package_id != 1u || entry.value.location_type != 0u ||
        entry.value.packet_id != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_package_entry_id8 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_package_entry_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{128, 0, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_plt_table_body    = true;
    cfg.validate_mmt_si_plt_package_entry = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 6u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 1u ||
        pref.value.num_of_ip_delivery != 0u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto entry = atsc3::mmt_si_plt_package_entry::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!entry.ok || entry.value.MMT_package_id_length != 0u ||
        entry.value.location_type != 0u || entry.value.packet_id != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_package_entry mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_package_entry_ipv4_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{128, 0, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_plt_table_body         = true;
    cfg.validate_mmt_si_plt_package_entry_ipv4 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 14u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 1u ||
        pref.value.num_of_ip_delivery != 0u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto entry = atsc3::mmt_si_plt_package_entry_ipv4::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!entry.ok || entry.value.MMT_package_id_length != 0u ||
        entry.value.location_type != 1u || entry.value.ipv4_src_addr != 0u ||
        entry.value.ipv4_dst_addr != 0u || entry.value.dst_port != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_package_entry_ipv4 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_package_entry_ipv4_nz_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{128, 0, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_plt_table_body            = true;
    cfg.validate_mmt_si_plt_package_entry_ipv4_nz = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 14u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 1u ||
        pref.value.num_of_ip_delivery != 0u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto entry = atsc3::mmt_si_plt_package_entry_ipv4_nz::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!entry.ok || entry.value.MMT_package_id_length != 0u ||
        entry.value.location_type != 1u ||
        entry.value.ipv4_src_addr != 0x0A000001u ||
        entry.value.ipv4_dst_addr != 0xE0000001u ||
        entry.value.dst_port != 5000u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_package_entry_ipv4_nz mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_package_entry_id8_location_ipv4_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{128, 0, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_plt_table_body = true;
    cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 15u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 1u ||
        pref.value.num_of_ip_delivery != 0u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto entry = atsc3::mmt_si_plt_package_entry_id8_location_ipv4::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!entry.ok || entry.value.MMT_package_id_length != 1u ||
        entry.value.MMT_package_id != 1u || entry.value.location_type != 1u ||
        entry.value.ipv4_src_addr != 0u || entry.value.ipv4_dst_addr != 0u ||
        entry.value.dst_port != 0u) {
        std::fprintf(stderr,
                     "[%s] mmt_si_plt_package_entry_id8_location_ipv4 mismatch\n",
                     label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_package_entry_id8_location_ipv4_nz_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{128, 0, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_plt_table_body = true;
    cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4_nz = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 15u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 1u ||
        pref.value.num_of_ip_delivery != 0u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto entry = atsc3::mmt_si_plt_package_entry_id8_location_ipv4_nz::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!entry.ok || entry.value.MMT_package_id_length != 1u ||
        entry.value.MMT_package_id != 1u || entry.value.location_type != 1u ||
        entry.value.ipv4_src_addr != 0x0A000001u ||
        entry.value.ipv4_dst_addr != 0xE0000001u ||
        entry.value.dst_port != 5000u) {
        std::fprintf(stderr,
                     "[%s] mmt_si_plt_package_entry_id8_location_ipv4_nz mismatch\n",
                     label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_package_entry_id8_location_ipv6_nz_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{128, 0, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_plt_table_body = true;
    cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6_nz = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 39u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 1u ||
        pref.value.num_of_ip_delivery != 0u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto entry = atsc3::mmt_si_plt_package_entry_id8_location_ipv6_nz::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!entry.ok || entry.value.MMT_package_id_length != 1u ||
        entry.value.MMT_package_id != 1u || entry.value.location_type != 2u ||
        entry.value.ipv6_src_addr_0 != 0u || entry.value.ipv6_src_addr_1 != 0u ||
        entry.value.ipv6_src_addr_2 != 0x0000FFFFu ||
        entry.value.ipv6_src_addr_3 != 0x0A000001u ||
        entry.value.ipv6_dst_addr_0 != 0u || entry.value.ipv6_dst_addr_1 != 0u ||
        entry.value.ipv6_dst_addr_2 != 0x0000FFFFu ||
        entry.value.ipv6_dst_addr_3 != 0xE0000001u ||
        entry.value.dst_port != 5000u) {
        std::fprintf(stderr,
                     "[%s] mmt_si_plt_package_entry_id8_location_ipv6_nz mismatch\n",
                     label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_package_entry_ipv6_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{128, 0, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_plt_table_body         = true;
    cfg.validate_mmt_si_plt_package_entry_ipv6 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 38u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 1u ||
        pref.value.num_of_ip_delivery != 0u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto entry = atsc3::mmt_si_plt_package_entry_ipv6::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!entry.ok || entry.value.MMT_package_id_length != 0u ||
        entry.value.location_type != 2u || entry.value.ipv6_src_addr_0 != 0u ||
        entry.value.ipv6_src_addr_1 != 0u || entry.value.ipv6_src_addr_2 != 0u ||
        entry.value.ipv6_src_addr_3 != 0u || entry.value.ipv6_dst_addr_0 != 0u ||
        entry.value.ipv6_dst_addr_1 != 0u || entry.value.ipv6_dst_addr_2 != 0u ||
        entry.value.ipv6_dst_addr_3 != 0u || entry.value.dst_port != 0u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_package_entry_ipv6 mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_package_entry_ipv6_nz_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{128, 0, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_plt_table_body             = true;
    cfg.validate_mmt_si_plt_package_entry_ipv6_nz = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 38u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 1u ||
        pref.value.num_of_ip_delivery != 0u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto entry = atsc3::mmt_si_plt_package_entry_ipv6_nz::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!entry.ok || entry.value.MMT_package_id_length != 0u ||
        entry.value.location_type != 2u ||
        entry.value.ipv6_src_addr_0 != 0u || entry.value.ipv6_src_addr_1 != 0u ||
        entry.value.ipv6_src_addr_2 != 0x0000FFFFu ||
        entry.value.ipv6_src_addr_3 != 0x0A000001u ||
        entry.value.ipv6_dst_addr_0 != 0u || entry.value.ipv6_dst_addr_1 != 0u ||
        entry.value.ipv6_dst_addr_2 != 0x0000FFFFu ||
        entry.value.ipv6_dst_addr_3 != 0xE0000001u ||
        entry.value.dst_port != 5000u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_package_entry_ipv6_nz mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_plt_package_entry_id8_location_ipv6_in_message(
    const char *label,
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::byte> &payload) {
    using row_t = atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row;
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.prepend_mmt_si_message_header_len32 = true;
    cfg.mmt_si_message_id                     = 0;
    cfg.prepend_mmt_si_pa_table_headers       = true;
    cfg.mmt_si_pa_table_header_rows = {
        row_t{128, 0, static_cast<std::uint16_t>(payload.size())}};
    cfg.validate_mmt_si_plt_table_body = true;
    cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6 = true;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto plt = atsc3::mmt_si_plt_table::decode(payload);
    if (!plt.ok || plt.value.table_id != 128u || plt.value.table_length != 39u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table fixture mismatch\n", label);
        return 1;
    }
    auto pref = atsc3::mmt_si_plt_table_body_prefix::decode(plt.value.payload);
    if (!pref.ok || pref.value.num_of_packages != 1u ||
        pref.value.num_of_ip_delivery != 0u || pref.bytes_consumed != 2u) {
        std::fprintf(stderr, "[%s] mmt_si_plt_table_body_prefix mismatch\n", label);
        return 1;
    }
    auto entry = atsc3::mmt_si_plt_package_entry_id8_location_ipv6::decode(
        plt.value.payload.subspan(pref.bytes_consumed));
    if (!entry.ok || entry.value.MMT_package_id_length != 1u ||
        entry.value.MMT_package_id != 1u || entry.value.location_type != 2u ||
        entry.value.ipv6_src_addr_0 != 0u || entry.value.ipv6_src_addr_1 != 0u ||
        entry.value.ipv6_src_addr_2 != 0u || entry.value.ipv6_src_addr_3 != 0u ||
        entry.value.ipv6_dst_addr_0 != 0u || entry.value.ipv6_dst_addr_1 != 0u ||
        entry.value.ipv6_dst_addr_2 != 0u || entry.value.ipv6_dst_addr_3 != 0u ||
        entry.value.dst_port != 0u) {
        std::fprintf(stderr,
                     "[%s] mmt_si_plt_package_entry_id8_location_ipv6 mismatch\n",
                     label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_signalling_prefix_with_aggregate(
    const char *label, std::uint8_t payload_type, std::uint16_t packet_id,
    const atsc3::mmtp_payload_signalling_prefix::decoded_t &sig,
    const std::vector<std::vector<std::byte>> &aggregate_bodies,
    const std::vector<std::byte> &payload) {
    std::size_t agg_wire = 0;
    for (const auto &b : aggregate_bodies) {
        agg_wire += (sig.length_extension_flag ? 4u : 2u) + b.size();
    }
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
            sig, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id));
    cfg.mmtp_signalling_aggregate_bodies = aggregate_bodies;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    const std::size_t want_len = 4u + 2u + agg_wire + payload.size();
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto mh = atsc3::mmtp_header_word0::decode(body.subspan(0, 4));
    if (!mh.ok || mh.value.payload_type != payload_type ||
        mh.value.packet_id != packet_id) {
        std::fprintf(stderr, "[%s] mmtp word0 mismatch\n", label);
        return 1;
    }
    auto sg = atsc3::mmtp_payload_signalling_prefix::decode(body.subspan(4, 2));
    if (!sg.ok) {
        std::fprintf(stderr, "[%s] signalling prefix decode: %s\n", label,
                     sg.error.c_str());
        return 1;
    }
    if (sg.value.fragmentation_indicator != sig.fragmentation_indicator ||
        sg.value.reserved != sig.reserved ||
        sg.value.length_extension_flag != sig.length_extension_flag ||
        sg.value.aggregation_flag != sig.aggregation_flag ||
        sg.value.fragment_counter != sig.fragment_counter) {
        std::fprintf(stderr, "[%s] signalling prefix field mismatch\n", label);
        return 1;
    }
    std::size_t off = 6u;
    for (const auto &want_body : aggregate_bodies) {
        std::size_t decl_len = 0;
        if (sig.length_extension_flag) {
            if (body.size() < off + 4u) {
                std::fprintf(stderr, "[%s] missing 32b aggregate length\n", label);
                return 1;
            }
            decl_len = static_cast<std::size_t>(
                (static_cast<std::uint32_t>(static_cast<std::uint8_t>(body[off])) << 24) |
                (static_cast<std::uint32_t>(static_cast<std::uint8_t>(body[off + 1])) << 16) |
                (static_cast<std::uint32_t>(static_cast<std::uint8_t>(body[off + 2])) << 8) |
                static_cast<std::uint32_t>(static_cast<std::uint8_t>(body[off + 3])));
            off += 4u;
        } else {
            if (body.size() < off + 2u) {
                std::fprintf(stderr, "[%s] missing 16b aggregate length\n", label);
                return 1;
            }
            decl_len = static_cast<std::size_t>(
                (static_cast<std::uint16_t>(static_cast<std::uint8_t>(body[off])) << 8) |
                static_cast<std::uint16_t>(static_cast<std::uint8_t>(body[off + 1])));
            off += 2u;
        }
        if (decl_len != want_body.size()) {
            std::fprintf(stderr, "[%s] aggregate declared length mismatch\n", label);
            return 1;
        }
        if (body.size() < off + decl_len) {
            std::fprintf(stderr, "[%s] aggregate body truncated\n", label);
            return 1;
        }
        if (!span_equal(body.subspan(off, decl_len),
                        std::span<const std::byte>(want_body.data(), want_body.size()))) {
            std::fprintf(stderr, "[%s] aggregate body mismatch\n", label);
            return 1;
        }
        off += decl_len;
    }
    if (!span_equal(body.subspan(off),
                    std::span<const std::byte>(payload.data(), payload.size()))) {
        std::fprintf(stderr, "[%s] payload tail mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_isobmff_prefix(
    const char *label, std::uint16_t packet_id,
    const atsc3::mmtp_payload_isobmff_prefix::decoded_t &iso_fields,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_isobmff_prefix(
            iso_fields,
            atsc3::gw::with_prepended_lab_mmtp_word0(0, packet_id));
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    const std::size_t want_len = 4u + 8u + payload.size();
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto mh = atsc3::mmtp_header_word0::decode(body.subspan(0, 4));
    if (!mh.ok || mh.value.payload_type != 0 || mh.value.packet_id != packet_id) {
        std::fprintf(stderr, "[%s] mmtp word0 mismatch\n", label);
        return 1;
    }
    auto isod = atsc3::mmtp_payload_isobmff_prefix::decode(body.subspan(4, 8));
    if (!isod.ok) {
        std::fprintf(stderr, "[%s] ISOBMFF prefix decode: %s\n", label,
                     isod.error.c_str());
        return 1;
    }
    const std::uint16_t want_exc =
        static_cast<std::uint16_t>(6u + payload.size());
    if (isod.value.payload_length_excluding_length_field != want_exc) {
        std::fprintf(stderr, "[%s] ISOBMFF length_excluding mismatch\n", label);
        return 1;
    }
    if (isod.value.fragment_type != iso_fields.fragment_type ||
        isod.value.timed_flag != iso_fields.timed_flag ||
        isod.value.fragmentation_indicator != iso_fields.fragmentation_indicator ||
        isod.value.aggregation_flag != iso_fields.aggregation_flag ||
        isod.value.fragment_counter != iso_fields.fragment_counter ||
        isod.value.sequence_number != iso_fields.sequence_number) {
        std::fprintf(stderr, "[%s] ISOBMFF prefix field mismatch\n", label);
        return 1;
    }
    if (!span_equal(body.subspan(12),
                    std::span<const std::byte>(payload.data(), payload.size()))) {
        std::fprintf(stderr, "[%s] payload tail mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_gfd_prefix(
    const char *label, std::uint16_t packet_id,
    const atsc3::mmtp_payload_gfd_header::decoded_t &gfd_fields,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_gfd_header(
            gfd_fields,
            atsc3::gw::with_prepended_lab_mmtp_word0(1, packet_id));
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    const std::size_t want_len = 4u + 12u + payload.size();
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto mh = atsc3::mmtp_header_word0::decode(body.subspan(0, 4));
    if (!mh.ok || mh.value.payload_type != 1 ||
        mh.value.packet_id != packet_id) {
        std::fprintf(stderr, "[%s] mmtp word0 mismatch\n", label);
        return 1;
    }
    auto gd = atsc3::mmtp_payload_gfd_header::decode(body.subspan(4, 12));
    if (!gd.ok) {
        std::fprintf(stderr, "[%s] GFD header decode: %s\n", label,
                     gd.error.c_str());
        return 1;
    }
    const auto& v = gd.value;
    if (v.session_last_packet_flag != gfd_fields.session_last_packet_flag ||
        v.object_last_packet_flag != gfd_fields.object_last_packet_flag ||
        v.object_last_byte_flag != gfd_fields.object_last_byte_flag ||
        v.code_point != gfd_fields.code_point ||
        v.reserved != gfd_fields.reserved ||
        v.transport_object_identifier !=
            gfd_fields.transport_object_identifier ||
        v.start_offset != gfd_fields.start_offset) {
        std::fprintf(stderr, "[%s] GFD header field mismatch\n", label);
        return 1;
    }
    if (!span_equal(body.subspan(16),
                    std::span<const std::byte>(payload.data(), payload.size()))) {
        std::fprintf(stderr, "[%s] payload tail mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_isobmff_non_agg_du_header_non_timed(
    const char *label, std::uint16_t packet_id,
    const atsc3::mmtp_payload_isobmff_prefix::decoded_t &iso_fields,
    std::uint32_t want_item_id, const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_isobmff_prefix(
            iso_fields,
            atsc3::gw::with_prepended_lab_mmtp_word0(0, packet_id));
    cfg.prepend_mmtp_isobmff_du_header = true;
    cfg.mmtp_isobmff_du_header_non_timed.item_id = want_item_id;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    constexpr std::size_t k_duh = 4u;
    const std::size_t want_len = 4u + 8u + k_duh + payload.size();
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto mh = atsc3::mmtp_header_word0::decode(body.subspan(0, 4));
    if (!mh.ok || mh.value.payload_type != 0 || mh.value.packet_id != packet_id) {
        std::fprintf(stderr, "[%s] mmtp word0 mismatch\n", label);
        return 1;
    }
    auto isod = atsc3::mmtp_payload_isobmff_prefix::decode(body.subspan(4, 8));
    if (!isod.ok) {
        std::fprintf(stderr, "[%s] ISOBMFF prefix decode: %s\n", label,
                     isod.error.c_str());
        return 1;
    }
    const std::uint16_t want_exc = static_cast<std::uint16_t>(
        6u + k_duh + payload.size());
    if (isod.value.payload_length_excluding_length_field != want_exc) {
        std::fprintf(stderr, "[%s] ISOBMFF length_excluding mismatch\n", label);
        return 1;
    }
    auto duh = atsc3::mmtp_payload_isobmff_du_header_non_timed::decode(
        body.subspan(12, k_duh));
    if (!duh.ok || duh.value.item_id != want_item_id) {
        std::fprintf(stderr, "[%s] non-timed DU header mismatch\n", label);
        return 1;
    }
    if (!span_equal(body.subspan(12 + k_duh),
                    std::span<const std::byte>(payload.data(), payload.size()))) {
        std::fprintf(stderr, "[%s] payload tail mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_isobmff_non_agg_du_header_timed(
    const char *label, std::uint16_t packet_id,
    const atsc3::mmtp_payload_isobmff_prefix::decoded_t &iso_fields,
    const atsc3::mmtp_payload_isobmff_du_header_timed::decoded_t &want_duh,
    const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_isobmff_prefix(
            iso_fields,
            atsc3::gw::with_prepended_lab_mmtp_word0(0, packet_id));
    cfg.prepend_mmtp_isobmff_du_header = true;
    cfg.mmtp_isobmff_du_header_timed = want_duh;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    constexpr std::size_t k_duh = 14u;
    const std::size_t want_len = 4u + 8u + k_duh + payload.size();
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto isod = atsc3::mmtp_payload_isobmff_prefix::decode(body.subspan(4, 8));
    if (!isod.ok) {
        std::fprintf(stderr, "[%s] ISOBMFF prefix decode: %s\n", label,
                     isod.error.c_str());
        return 1;
    }
    const std::uint16_t want_exc = static_cast<std::uint16_t>(
        6u + k_duh + payload.size());
    if (isod.value.payload_length_excluding_length_field != want_exc) {
        std::fprintf(stderr, "[%s] ISOBMFF length_excluding mismatch\n", label);
        return 1;
    }
    auto duh = atsc3::mmtp_payload_isobmff_du_header_timed::decode(
        body.subspan(12, k_duh));
    if (!duh.ok || duh.value.movie_fragment_sequence_number !=
                      want_duh.movie_fragment_sequence_number ||
        duh.value.sample_number != want_duh.sample_number ||
        duh.value.offset != want_duh.offset ||
        duh.value.subsample_priority != want_duh.subsample_priority ||
        duh.value.dependency_counter != want_duh.dependency_counter) {
        std::fprintf(stderr, "[%s] timed DU header mismatch\n", label);
        return 1;
    }
    if (!span_equal(body.subspan(12 + k_duh),
                    std::span<const std::byte>(payload.data(), payload.size()))) {
        std::fprintf(stderr, "[%s] payload tail mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_isobmff_aggregate_du_header_non_timed(
    const char *label, std::uint16_t packet_id,
    const atsc3::mmtp_payload_isobmff_prefix::decoded_t &iso_fields,
    std::uint32_t want_item_id,
    const std::vector<std::vector<std::byte>> &agg_bodies,
    const std::vector<std::byte> &tail_payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_isobmff_prefix(
            iso_fields,
            atsc3::gw::with_prepended_lab_mmtp_word0(0, packet_id));
    cfg.prepend_mmtp_isobmff_du_header = true;
    cfg.mmtp_isobmff_du_header_non_timed.item_id = want_item_id;
    cfg.mmtp_isobmff_aggregate_bodies = agg_bodies;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(tail_payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    constexpr std::size_t k_duh = 4u;
    std::size_t agg_wire = 0;
    for (const auto &ch : agg_bodies) {
        agg_wire += 2u + k_duh + ch.size();
    }
    const std::size_t want_len = 4u + 8u + agg_wire + tail_payload.size();
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto isod = atsc3::mmtp_payload_isobmff_prefix::decode(body.subspan(4, 8));
    if (!isod.ok) {
        std::fprintf(stderr, "[%s] ISOBMFF prefix decode: %s\n", label,
                     isod.error.c_str());
        return 1;
    }
    const std::uint16_t want_exc = static_cast<std::uint16_t>(
        6u + agg_wire + tail_payload.size());
    if (isod.value.payload_length_excluding_length_field != want_exc) {
        std::fprintf(stderr, "[%s] ISOBMFF length_excluding mismatch\n", label);
        return 1;
    }
    std::size_t off = 12u;
    for (const auto &want_du : agg_bodies) {
        if (body.size() < off + 2u) {
            std::fprintf(stderr, "[%s] missing DU_length\n", label);
            return 1;
        }
        const std::uint16_t dlen =
            static_cast<std::uint16_t>(
                (static_cast<std::uint16_t>(static_cast<std::uint8_t>(body[off]))
                 << 8) |
                static_cast<std::uint16_t>(
                    static_cast<std::uint8_t>(body[off + 1])));
        off += 2u;
        const std::uint16_t want_len_du =
            static_cast<std::uint16_t>(k_duh + want_du.size());
        if (dlen != want_len_du) {
            std::fprintf(stderr, "[%s] DU_length mismatch got %u want %u\n",
                         label, static_cast<unsigned>(dlen),
                         static_cast<unsigned>(want_len_du));
            return 1;
        }
        auto duh = atsc3::mmtp_payload_isobmff_du_header_non_timed::decode(
            body.subspan(off, k_duh));
        if (!duh.ok || duh.value.item_id != want_item_id) {
            std::fprintf(stderr, "[%s] non-timed DU header mismatch\n", label);
            return 1;
        }
        off += k_duh;
        if (body.size() < off + want_du.size()) {
            std::fprintf(stderr, "[%s] DU body truncated\n", label);
            return 1;
        }
        if (!span_equal(body.subspan(off, want_du.size()),
                        std::span<const std::byte>(want_du.data(),
                                                   want_du.size()))) {
            std::fprintf(stderr, "[%s] DU body mismatch\n", label);
            return 1;
        }
        off += want_du.size();
    }
    if (!span_equal(body.subspan(off),
                    std::span<const std::byte>(tail_payload.data(),
                                               tail_payload.size()))) {
        std::fprintf(stderr, "[%s] tail payload mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (tail=%zu wire=%zu)\n", label, tail_payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_isobmff_aggregate_du_header_timed(
    const char *label, std::uint16_t packet_id,
    const atsc3::mmtp_payload_isobmff_prefix::decoded_t &iso_fields,
    const atsc3::mmtp_payload_isobmff_du_header_timed::decoded_t &want_duh,
    const std::vector<std::vector<std::byte>> &agg_bodies,
    const std::vector<std::byte> &tail_payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_isobmff_prefix(
            iso_fields,
            atsc3::gw::with_prepended_lab_mmtp_word0(0, packet_id));
    cfg.prepend_mmtp_isobmff_du_header = true;
    cfg.mmtp_isobmff_du_header_timed   = want_duh;
    cfg.mmtp_isobmff_aggregate_bodies  = agg_bodies;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(tail_payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    constexpr std::size_t k_duh = 14u;
    std::size_t agg_wire = 0;
    for (const auto &ch : agg_bodies) {
        agg_wire += 2u + k_duh + ch.size();
    }
    const std::size_t want_len = 4u + 8u + agg_wire + tail_payload.size();
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto isod = atsc3::mmtp_payload_isobmff_prefix::decode(body.subspan(4, 8));
    if (!isod.ok) {
        std::fprintf(stderr, "[%s] ISOBMFF prefix decode: %s\n", label,
                     isod.error.c_str());
        return 1;
    }
    const std::uint16_t want_exc = static_cast<std::uint16_t>(
        6u + agg_wire + tail_payload.size());
    if (isod.value.payload_length_excluding_length_field != want_exc) {
        std::fprintf(stderr, "[%s] ISOBMFF length_excluding mismatch\n", label);
        return 1;
    }
    std::size_t off = 12u;
    for (const auto &want_du : agg_bodies) {
        if (body.size() < off + 2u) {
            std::fprintf(stderr, "[%s] missing DU_length\n", label);
            return 1;
        }
        const std::uint16_t dlen =
            static_cast<std::uint16_t>(
                (static_cast<std::uint16_t>(static_cast<std::uint8_t>(body[off]))
                 << 8) |
                static_cast<std::uint16_t>(
                    static_cast<std::uint8_t>(body[off + 1])));
        off += 2u;
        const std::uint16_t want_len_du =
            static_cast<std::uint16_t>(k_duh + want_du.size());
        if (dlen != want_len_du) {
            std::fprintf(stderr, "[%s] DU_length mismatch got %u want %u\n",
                         label, static_cast<unsigned>(dlen),
                         static_cast<unsigned>(want_len_du));
            return 1;
        }
        auto duh = atsc3::mmtp_payload_isobmff_du_header_timed::decode(
            body.subspan(off, k_duh));
        if (!duh.ok || duh.value.movie_fragment_sequence_number !=
                          want_duh.movie_fragment_sequence_number ||
            duh.value.sample_number != want_duh.sample_number ||
            duh.value.offset != want_duh.offset ||
            duh.value.subsample_priority != want_duh.subsample_priority ||
            duh.value.dependency_counter != want_duh.dependency_counter) {
            std::fprintf(stderr, "[%s] timed DU header mismatch\n", label);
            return 1;
        }
        off += k_duh;
        if (body.size() < off + want_du.size()) {
            std::fprintf(stderr, "[%s] DU body truncated\n", label);
            return 1;
        }
        if (!span_equal(body.subspan(off, want_du.size()),
                        std::span<const std::byte>(want_du.data(),
                                                   want_du.size()))) {
            std::fprintf(stderr, "[%s] DU body mismatch\n", label);
            return 1;
        }
        off += want_du.size();
    }
    if (!span_equal(body.subspan(off),
                    std::span<const std::byte>(tail_payload.data(),
                                               tail_payload.size()))) {
        std::fprintf(stderr, "[%s] tail payload mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (tail=%zu wire=%zu)\n", label, tail_payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_isobmff_aggregate(
    const char *label, std::uint16_t packet_id,
    const atsc3::mmtp_payload_isobmff_prefix::decoded_t &iso_fields,
    const std::vector<std::vector<std::byte>> &agg_bodies,
    const std::vector<std::byte> &tail_payload) {
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_isobmff_prefix(
            iso_fields,
            atsc3::gw::with_prepended_lab_mmtp_word0(0, packet_id));
    cfg.mmtp_isobmff_aggregate_bodies = agg_bodies;
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(tail_payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    std::size_t agg_wire = 0;
    for (const auto &ch : agg_bodies) {
        agg_wire += 2u + ch.size();
    }
    const std::size_t want_len = 4u + 8u + agg_wire + tail_payload.size();
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto mh = atsc3::mmtp_header_word0::decode(body.subspan(0, 4));
    if (!mh.ok || mh.value.payload_type != 0 || mh.value.packet_id != packet_id) {
        std::fprintf(stderr, "[%s] mmtp word0 mismatch\n", label);
        return 1;
    }
    auto isod = atsc3::mmtp_payload_isobmff_prefix::decode(body.subspan(4, 8));
    if (!isod.ok) {
        std::fprintf(stderr, "[%s] ISOBMFF prefix decode: %s\n", label,
                     isod.error.c_str());
        return 1;
    }
    const std::uint16_t want_exc = static_cast<std::uint16_t>(6u + agg_wire +
                                                             tail_payload.size());
    if (isod.value.payload_length_excluding_length_field != want_exc) {
        std::fprintf(stderr, "[%s] ISOBMFF length_excluding mismatch\n", label);
        return 1;
    }
    if (isod.value.fragment_type != iso_fields.fragment_type ||
        isod.value.timed_flag != iso_fields.timed_flag ||
        isod.value.fragmentation_indicator != iso_fields.fragmentation_indicator ||
        isod.value.aggregation_flag != iso_fields.aggregation_flag ||
        isod.value.fragment_counter != iso_fields.fragment_counter ||
        isod.value.sequence_number != iso_fields.sequence_number) {
        std::fprintf(stderr, "[%s] ISOBMFF prefix field mismatch\n", label);
        return 1;
    }
    std::size_t off = 12u;
    for (const auto &want_du : agg_bodies) {
        if (body.size() < off + 2u) {
            std::fprintf(stderr, "[%s] missing DU_length\n", label);
            return 1;
        }
        const std::uint16_t dlen =
            static_cast<std::uint16_t>(
                (static_cast<std::uint16_t>(static_cast<std::uint8_t>(body[off]))
                 << 8) |
                static_cast<std::uint16_t>(
                    static_cast<std::uint8_t>(body[off + 1])));
        off += 2u;
        if (dlen != want_du.size()) {
            std::fprintf(stderr, "[%s] DU_length mismatch\n", label);
            return 1;
        }
        if (body.size() < off + want_du.size()) {
            std::fprintf(stderr, "[%s] DU body truncated\n", label);
            return 1;
        }
        if (!span_equal(body.subspan(off, want_du.size()),
                        std::span<const std::byte>(want_du.data(),
                                                   want_du.size()))) {
            std::fprintf(stderr, "[%s] DU body mismatch\n", label);
            return 1;
        }
        off += want_du.size();
    }
    if (!span_equal(body.subspan(off),
                    std::span<const std::byte>(tail_payload.data(),
                                               tail_payload.size()))) {
        std::fprintf(stderr, "[%s] tail payload mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (tail=%zu wire=%zu)\n", label, tail_payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_extension_prefix(const char *label, std::uint8_t payload_type,
                              std::uint16_t packet_id, std::uint16_t ext_type,
                              std::vector<std::byte> ext_val,
                              const std::vector<std::byte> &payload) {
    const std::size_t ext_octets = ext_val.size();
    atsc3::gw::encoder_pipeline enc{atsc3::gw::with_prepended_lab_mmtp_extension(
        ext_type, std::move(ext_val),
        atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id))};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    const std::size_t want_len = 4u + 4u + ext_octets + payload.size();
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto mh = atsc3::mmtp_header_word0::decode(body.subspan(0, 4));
    if (!mh.ok || mh.value.payload_type != payload_type ||
        mh.value.packet_id != packet_id || !mh.value.extension_flag) {
        std::fprintf(stderr, "[%s] mmtp word0 mismatch (X flag)\n", label);
        return 1;
    }
    auto ex = atsc3::mmtp_header_extension::decode(body.subspan(4));
    if (!ex.ok || ex.value.extension_type != ext_type ||
        ex.value.extension_length_bytes != ext_octets ||
        ex.value.payload.size() != ext_octets) {
        std::fprintf(stderr, "[%s] mmtp extension decode mismatch\n", label);
        return 1;
    }
    if (!span_equal(body.subspan(4u + ex.bytes_consumed),
                    std::span<const std::byte>(payload))) {
        std::fprintf(stderr, "[%s] payload tail mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu ext=%zu)\n", label,
                payload.size(), wire.bytes.size(), ext_octets);
    return 0;
}

int run_mmtp_extension_chain2(
    const char *label, std::uint8_t payload_type, std::uint16_t packet_id,
    std::uint16_t ext_type_a, std::vector<std::byte> ext_val_a,
    std::uint16_t ext_type_b, std::vector<std::byte> ext_val_b,
    const std::vector<std::byte> &payload) {
    const std::size_t ext_a = ext_val_a.size();
    const std::size_t ext_b = ext_val_b.size();
    atsc3::gw::encoder_pipeline::config cfg =
        atsc3::gw::with_prepended_lab_mmtp_word0(payload_type, packet_id);
    cfg = atsc3::gw::with_prepended_lab_mmtp_extension(
        ext_type_a, std::move(ext_val_a), std::move(cfg));
    cfg = atsc3::gw::with_prepended_lab_mmtp_extension(
        ext_type_b, std::move(ext_val_b), std::move(cfg));
    atsc3::gw::encoder_pipeline enc{std::move(cfg)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    const std::size_t tlv_a = 4u + ext_a;
    const std::size_t tlv_b = 4u + ext_b;
    const std::size_t want_len = 4u + tlv_a + tlv_b + payload.size();
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto mh = atsc3::mmtp_header_word0::decode(body.subspan(0, 4));
    if (!mh.ok || mh.value.payload_type != payload_type ||
        mh.value.packet_id != packet_id || !mh.value.extension_flag) {
        std::fprintf(stderr, "[%s] mmtp word0 mismatch (X flag)\n", label);
        return 1;
    }
    std::size_t off = 4u;
    auto ex1 = atsc3::mmtp_header_extension::decode(body.subspan(off));
    if (!ex1.ok || ex1.value.extension_type != ext_type_a ||
        ex1.value.extension_length_bytes != ext_a ||
        ex1.value.payload.size() != ext_a) {
        std::fprintf(stderr, "[%s] mmtp extension A decode mismatch\n", label);
        return 1;
    }
    off += ex1.bytes_consumed;
    auto ex2 = atsc3::mmtp_header_extension::decode(body.subspan(off));
    if (!ex2.ok || ex2.value.extension_type != ext_type_b ||
        ex2.value.extension_length_bytes != ext_b ||
        ex2.value.payload.size() != ext_b) {
        std::fprintf(stderr, "[%s] mmtp extension B decode mismatch\n", label);
        return 1;
    }
    off += ex2.bytes_consumed;
    if (!span_equal(body.subspan(off),
                    std::span<const std::byte>(payload))) {
        std::fprintf(stderr, "[%s] payload tail mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_tspsn_extension_prefix(
    const char *label, std::uint8_t payload_type, std::uint16_t packet_id,
    std::uint32_t ts, std::uint32_t psn, std::uint16_t ext_type,
    std::vector<std::byte> ext_val, const std::vector<std::byte> &payload) {
    const std::size_t ext_octets = ext_val.size();
    atsc3::gw::encoder_pipeline enc{atsc3::gw::with_prepended_lab_mmtp_extension(
        ext_type, std::move(ext_val),
        atsc3::gw::with_prepended_lab_mmtp_ts_psn(
            ts, psn, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type,
                                                              packet_id)))};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    const std::size_t want_len = 4u + 8u + 4u + ext_octets + payload.size();
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto mh = atsc3::mmtp_header_word0::decode(body.subspan(0, 4));
    if (!mh.ok || mh.value.payload_type != payload_type ||
        mh.value.packet_id != packet_id || !mh.value.extension_flag) {
        std::fprintf(stderr, "[%s] mmtp word0 mismatch\n", label);
        return 1;
    }
    auto tp = atsc3::mmtp_header_ts_psn::decode(body.subspan(4, 8));
    if (!tp.ok || tp.value.timestamp != ts ||
        tp.value.packet_sequence_number != psn) {
        std::fprintf(stderr, "[%s] mmtp ts_psn mismatch\n", label);
        return 1;
    }
    auto ex = atsc3::mmtp_header_extension::decode(body.subspan(12));
    if (!ex.ok || ex.value.extension_type != ext_type ||
        ex.value.extension_length_bytes != ext_octets) {
        std::fprintf(stderr, "[%s] mmtp extension mismatch\n", label);
        return 1;
    }
    if (!span_equal(body.subspan(12u + ex.bytes_consumed),
                    std::span<const std::byte>(payload))) {
        std::fprintf(stderr, "[%s] payload tail mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_tspsn_counter_prefix(const char *label, std::uint8_t payload_type,
                                  std::uint16_t packet_id, std::uint32_t ts,
                                  std::uint32_t psn, std::uint32_t pkt_ctr,
                                  const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline enc{
        atsc3::gw::with_prepended_lab_mmtp_packet_counter(
            pkt_ctr,
            atsc3::gw::with_prepended_lab_mmtp_ts_psn(
                ts, psn, atsc3::gw::with_prepended_lab_mmtp_word0(
                             payload_type, packet_id)))};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    if (body.size() != payload.size() + 16u) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), payload.size() + 16u);
        return 1;
    }

    auto mh = atsc3::mmtp_header_word0::decode(body.subspan(0, 4));
    if (!mh.ok || mh.value.payload_type != payload_type ||
        mh.value.packet_id != packet_id || !mh.value.packet_counter_flag) {
        std::fprintf(stderr, "[%s] mmtp word0 mismatch (C flag)\n", label);
        return 1;
    }
    auto tp = atsc3::mmtp_header_ts_psn::decode(body.subspan(4, 8));
    if (!tp.ok || tp.value.timestamp != ts ||
        tp.value.packet_sequence_number != psn) {
        std::fprintf(stderr, "[%s] mmtp ts_psn mismatch\n", label);
        return 1;
    }
    auto ctr = atsc3::mmtp_header_counter32::decode(body.subspan(12, 4));
    if (!ctr.ok || ctr.value.packet_counter != pkt_ctr) {
        std::fprintf(stderr, "[%s] mmtp packet_counter mismatch\n", label);
        return 1;
    }
    if (!span_equal(body.subspan(16),
                    std::span<const std::byte>(payload))) {
        std::fprintf(stderr, "[%s] payload tail mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_tspsn_counter_ext_prefix(
    const char *label, std::uint8_t payload_type, std::uint16_t packet_id,
    std::uint32_t ts, std::uint32_t psn, std::uint32_t pkt_ctr,
    std::uint16_t ext_type, std::vector<std::byte> ext_val,
    const std::vector<std::byte> &payload) {
    const std::size_t ext_octets = ext_val.size();
    atsc3::gw::encoder_pipeline enc{atsc3::gw::with_prepended_lab_mmtp_extension(
        ext_type, std::move(ext_val),
        atsc3::gw::with_prepended_lab_mmtp_packet_counter(
            pkt_ctr,
            atsc3::gw::with_prepended_lab_mmtp_ts_psn(
                ts, psn, atsc3::gw::with_prepended_lab_mmtp_word0(
                             payload_type, packet_id))))};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    const std::size_t want_len = 4u + 8u + 4u + 4u + ext_octets + payload.size();
    if (body.size() != want_len) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), want_len);
        return 1;
    }

    auto mh = atsc3::mmtp_header_word0::decode(body.subspan(0, 4));
    if (!mh.ok || mh.value.payload_type != payload_type ||
        mh.value.packet_id != packet_id || !mh.value.extension_flag ||
        !mh.value.packet_counter_flag) {
        std::fprintf(stderr, "[%s] mmtp word0 mismatch (C/X)\n", label);
        return 1;
    }
    auto tp = atsc3::mmtp_header_ts_psn::decode(body.subspan(4, 8));
    if (!tp.ok || tp.value.timestamp != ts ||
        tp.value.packet_sequence_number != psn) {
        std::fprintf(stderr, "[%s] mmtp ts_psn mismatch\n", label);
        return 1;
    }
    auto ctr = atsc3::mmtp_header_counter32::decode(body.subspan(12, 4));
    if (!ctr.ok || ctr.value.packet_counter != pkt_ctr) {
        std::fprintf(stderr, "[%s] mmtp packet_counter mismatch\n", label);
        return 1;
    }
    auto ex = atsc3::mmtp_header_extension::decode(body.subspan(16));
    if (!ex.ok || ex.value.extension_type != ext_type ||
        ex.value.extension_length_bytes != ext_octets) {
        std::fprintf(stderr, "[%s] mmtp extension mismatch\n", label);
        return 1;
    }
    if (!span_equal(body.subspan(16u + ex.bytes_consumed),
                    std::span<const std::byte>(payload))) {
        std::fprintf(stderr, "[%s] payload tail mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_tspsn_prefix(const char *label, std::uint8_t payload_type,
                          std::uint16_t packet_id, std::uint32_t ts,
                          std::uint32_t psn,
                          const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline enc{atsc3::gw::with_prepended_lab_mmtp_ts_psn(
        ts, psn, atsc3::gw::with_prepended_lab_mmtp_word0(payload_type,
                                                          packet_id))};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    if (body.size() != payload.size() + 12u) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), payload.size() + 12u);
        return 1;
    }

    auto mh = atsc3::mmtp_header_word0::decode(body.subspan(0, 4));
    if (!mh.ok || mh.value.payload_type != payload_type ||
        mh.value.packet_id != packet_id) {
        std::fprintf(stderr, "[%s] mmtp word0 mismatch\n", label);
        return 1;
    }
    auto tp = atsc3::mmtp_header_ts_psn::decode(body.subspan(4, 8));
    if (!tp.ok || tp.value.timestamp != ts ||
        tp.value.packet_sequence_number != psn) {
        std::fprintf(stderr, "[%s] mmtp ts_psn mismatch\n", label);
        return 1;
    }
    if (!span_equal(body.subspan(12),
                    std::span<const std::byte>(payload))) {
        std::fprintf(stderr, "[%s] payload tail mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_tspsn_then_lct(const char *label, std::uint8_t mmtp_pt,
                            std::uint16_t mmtp_pid, std::uint32_t ts,
                            std::uint32_t psn, std::uint8_t lct_cp,
                            const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline enc{atsc3::gw::with_prepended_lab_mmtp_ts_psn(
        ts, psn,
        atsc3::gw::with_prepended_lab_mmtp_word0(
            mmtp_pt, mmtp_pid,
            atsc3::gw::with_prepended_lab_lct_word0(lct_cp)))};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    if (body.size() != payload.size() + 16u) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), payload.size() + 16u);
        return 1;
    }

    auto mh = atsc3::mmtp_header_word0::decode(body.subspan(0, 4));
    if (!mh.ok || mh.value.payload_type != mmtp_pt ||
        mh.value.packet_id != mmtp_pid) {
        std::fprintf(stderr, "[%s] mmtp prefix mismatch\n", label);
        return 1;
    }
    auto tp = atsc3::mmtp_header_ts_psn::decode(body.subspan(4, 8));
    if (!tp.ok || tp.value.timestamp != ts ||
        tp.value.packet_sequence_number != psn) {
        std::fprintf(stderr, "[%s] mmtp ts_psn mismatch\n", label);
        return 1;
    }
    auto lct = atsc3::lct_rfc5651_word0::decode(body.subspan(12, 4));
    if (!lct.ok || lct.value.codepoint != lct_cp) {
        std::fprintf(stderr, "[%s] lct after mmtp ts_psn mismatch\n", label);
        return 1;
    }
    if (!span_equal(body.subspan(16),
                    std::span<const std::byte>(payload))) {
        std::fprintf(stderr, "[%s] payload tail mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_mmtp_then_lct(const char *label, std::uint8_t mmtp_pt,
                      std::uint16_t mmtp_pid, std::uint8_t lct_cp,
                      const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline enc{atsc3::gw::with_prepended_lab_mmtp_word0(
        mmtp_pt, mmtp_pid, atsc3::gw::with_prepended_lab_lct_word0(lct_cp))};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    if (body.size() != payload.size() + 8u) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), payload.size() + 8u);
        return 1;
    }

    auto mh = atsc3::mmtp_header_word0::decode(body.subspan(0, 4));
    if (!mh.ok || mh.value.payload_type != mmtp_pt ||
        mh.value.packet_id != mmtp_pid) {
        std::fprintf(stderr, "[%s] mmtp prefix mismatch\n", label);
        return 1;
    }
    auto lct = atsc3::lct_rfc5651_word0::decode(body.subspan(4, 4));
    if (!lct.ok || lct.value.codepoint != lct_cp) {
        std::fprintf(stderr, "[%s] lct after mmtp mismatch\n", label);
        return 1;
    }
    if (!span_equal(body.subspan(8),
                    std::span<const std::byte>(payload))) {
        std::fprintf(stderr, "[%s] payload tail mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu)\n", label, payload.size(),
                wire.bytes.size());
    return 0;
}

int run_lct_prefix_tsi(const char *label, std::uint8_t cp, std::uint32_t tsi,
                       const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline enc{
        atsc3::gw::with_prepended_lab_lct_word0_tsi(cp, tsi)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    if (body.size() != payload.size() + 8u) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), payload.size() + 8u);
        return 1;
    }

    auto lct = atsc3::lct_rfc5651_word0::decode(body.subspan(
        0, sizeof(std::uint32_t)));
    if (!lct.ok) {
        std::fprintf(stderr, "[%s] lct_word0 decode failed: %s\n",
                     label, lct.error.c_str());
        return 1;
    }
    if (lct.value.codepoint != cp) {
        std::fprintf(stderr, "[%s] lct codepoint got %u want %u\n", label,
                     static_cast<unsigned>(lct.value.codepoint),
                     static_cast<unsigned>(cp));
        return 1;
    }
    if (!lct.value.tsi_flag || lct.value.header_length_words != 2) {
        std::fprintf(stderr,
                     "[%s] lct word0: want tsi_flag=1 header_length_words=2\n",
                     label);
        return 1;
    }
    const std::uint32_t tsi_obs = read_be32_at(body, 4);
    if (tsi_obs != tsi) {
        std::fprintf(stderr, "[%s] TSI BE32 got %u want %u\n", label,
                     static_cast<unsigned>(tsi_obs),
                     static_cast<unsigned>(tsi));
        return 1;
    }
    if (!span_equal(body.subspan(8),
                    std::span<const std::byte>(payload))) {
        std::fprintf(stderr, "[%s] payload tail mismatch\n", label);
        return 1;
    }

    std::printf(
        "[%s] OK (user=%zu wire=%zu cp=%u tsi=%u)\n", label,
        payload.size(), wire.bytes.size(), static_cast<unsigned>(cp),
        static_cast<unsigned>(tsi));
    return 0;
}

int run_lct_prefix_toi(const char *label, std::uint8_t cp, std::uint32_t toi,
                       const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline enc{
        atsc3::gw::with_prepended_lab_lct_word0_toi(cp, toi)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    if (body.size() != payload.size() + 8u) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), payload.size() + 8u);
        return 1;
    }

    auto lct = atsc3::lct_rfc5651_word0::decode(body.subspan(
        0, sizeof(std::uint32_t)));
    if (!lct.ok) {
        std::fprintf(stderr, "[%s] lct_word0 decode failed: %s\n",
                     label, lct.error.c_str());
        return 1;
    }
    if (lct.value.codepoint != cp) {
        std::fprintf(stderr, "[%s] lct codepoint got %u want %u\n", label,
                     static_cast<unsigned>(lct.value.codepoint),
                     static_cast<unsigned>(cp));
        return 1;
    }
    if (lct.value.tsi_flag || lct.value.toi_flag != 1 ||
        lct.value.header_length_words != 2) {
        std::fprintf(stderr,
                     "[%s] lct word0: want !tsi toi(O)==1 hdr_len==2\n", label);
        return 1;
    }
    const std::uint32_t toi_obs = read_be32_at(body, 4);
    if (toi_obs != toi) {
        std::fprintf(stderr, "[%s] TOI BE32 got %u want %u\n", label,
                     static_cast<unsigned>(toi_obs),
                     static_cast<unsigned>(toi));
        return 1;
    }
    if (!span_equal(body.subspan(8),
                    std::span<const std::byte>(payload))) {
        std::fprintf(stderr, "[%s] payload tail mismatch\n", label);
        return 1;
    }

    std::printf(
        "[%s] OK (user=%zu wire=%zu cp=%u toi=%u)\n", label,
        payload.size(), wire.bytes.size(), static_cast<unsigned>(cp),
        static_cast<unsigned>(toi));
    return 0;
}

int run_lct_prefix_tsi_toi(const char *label, std::uint8_t cp,
                           std::uint32_t tsi, std::uint32_t toi,
                           const std::vector<std::byte> &payload) {
    atsc3::gw::encoder_pipeline enc{
        atsc3::gw::with_prepended_lab_lct_word0_tsi_toi(cp, tsi, toi)};

    auto wire = enc.encode(std::span<const std::byte>(payload));
    if (!wire.ok) {
        std::fprintf(stderr, "[%s] encode failed: %s\n",
                     label, wire.error.c_str());
        return 1;
    }

    auto tlv = atsc3::tlv_mux::decode(std::span<const std::byte>(
        wire.bytes.data(), wire.bytes.size()));
    if (!tlv.ok) {
        std::fprintf(stderr, "[%s] tlv_mux decode failed: %s\n",
                     label, tlv.error.c_str());
        return 1;
    }

    auto alp = atsc3::alp::decode(tlv.value.payload);
    if (!alp.ok) {
        std::fprintf(stderr, "[%s] alp decode failed: %s\n",
                     label, alp.error.c_str());
        return 1;
    }

    const auto body = alp.value.payload;
    if (body.size() != payload.size() + 12u) {
        std::fprintf(stderr,
                     "[%s] alp inner size mismatch: got %zu want %zu\n",
                     label, body.size(), payload.size() + 12u);
        return 1;
    }

    auto lct = atsc3::lct_rfc5651_word0::decode(body.subspan(
        0, sizeof(std::uint32_t)));
    if (!lct.ok) {
        std::fprintf(stderr, "[%s] lct_word0 decode failed: %s\n",
                     label, lct.error.c_str());
        return 1;
    }
    if (lct.value.codepoint != cp) {
        std::fprintf(stderr, "[%s] lct codepoint got %u want %u\n", label,
                     static_cast<unsigned>(lct.value.codepoint),
                     static_cast<unsigned>(cp));
        return 1;
    }
    if (!lct.value.tsi_flag || lct.value.toi_flag != 1 ||
        lct.value.header_length_words != 3) {
        std::fprintf(stderr,
                     "[%s] lct word0: want S=1 toi(O)==1 hdr_len==3\n", label);
        return 1;
    }
    const std::uint32_t tsi_obs = read_be32_at(body, 4);
    const std::uint32_t toi_obs = read_be32_at(body, 8);
    if (tsi_obs != tsi) {
        std::fprintf(stderr, "[%s] TSI BE32 got %u want %u\n", label,
                     static_cast<unsigned>(tsi_obs),
                     static_cast<unsigned>(tsi));
        return 1;
    }
    if (toi_obs != toi) {
        std::fprintf(stderr, "[%s] TOI BE32 got %u want %u\n", label,
                     static_cast<unsigned>(toi_obs),
                     static_cast<unsigned>(toi));
        return 1;
    }
    if (!span_equal(body.subspan(12),
                    std::span<const std::byte>(payload))) {
        std::fprintf(stderr, "[%s] payload tail mismatch\n", label);
        return 1;
    }

    std::printf("[%s] OK (user=%zu wire=%zu cp=%u tsi=%u toi=%u)\n", label,
                payload.size(), wire.bytes.size(), static_cast<unsigned>(cp),
                static_cast<unsigned>(tsi), static_cast<unsigned>(toi));
    return 0;
}

}  // namespace

int main() {
    int failures = 0;

    // 1) trivial 4-byte payload (RTCM-ish stub)
    {
        std::vector<std::byte> p{
            std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};
        failures += run_one("DEADBEEF", p);
    }

    // 2) empty payload — a degenerate but valid framing
    {
        std::vector<std::byte> p{};
        failures += run_one("empty", p);
    }

    // 3) 1-byte payload — exercises the smallest non-empty path
    {
        std::vector<std::byte> p{std::byte{0x42}};
        failures += run_one("single-byte", p);
    }

    // 4) 256-byte filled pattern — crosses byte boundaries / both ALP length
    //    bytes are non-zero
    {
        std::vector<std::byte> p(256);
        for (std::size_t i = 0; i < p.size(); ++i) {
            p[i] = static_cast<std::byte>(i & 0xFF);
        }
        failures += run_one("256-byte-pattern", p);
    }

    // 5) 2047-byte payload — the maximum the ALP 11-bit length field allows
    {
        std::vector<std::byte> p(2047, std::byte{0xA5});
        failures += run_one("alp-max-2047", p);
    }

    // 5b) ALP §5.2 **payload_configuration** / **header_mode** on the wire
    //     (`protocol/alp.yaml`; lab still omits long-header octets beyond 16b)
    {
        std::vector<std::byte> p{std::byte{0x11}, std::byte{0x22}};
        failures += run_alp_base_header_flags("alp-pc0-hm0", false, false, p);
        failures += run_alp_base_header_flags("alp-pc1-hm1", true, true, p);
        failures += run_alp_base_header_flags("alp-pc1-hm0", true, false, p);
        failures += run_alp_base_header_flags("alp-pc0-hm1", false, true, p);
    }

    // 6) oversize (2048) must fail at the encoder, not crash
    {
        std::vector<std::byte> p(2048, std::byte{0x5A});
        atsc3::gw::encoder_pipeline enc{};
        auto r = enc.encode(std::span<const std::byte>(p));
        if (r.ok) {
            std::fprintf(stderr,
                "[oversize-2048] expected encode failure, got ok\n");
            ++failures;
        } else {
            std::printf("[oversize-2048] OK (rejected: %s)\n",
                        r.error.c_str());
        }
    }

    // 6b) MMTP packet header word‑0 lab prefix (M8; ISO/IEC 23008-1 Figure 1)
    {
        std::vector<std::byte> p{std::byte{0x01}, std::byte{0x02}};
        failures += run_mmtp_prefix("mmtp-word0-signalling", 2, 0x10u, p);
        failures += run_mmtp_prefix("mmtp-word0-isobmff", 0, 1u,
                                    std::vector<std::byte>{});
        {
            atsc3::mmtp_payload_gfd_header::decoded_t gfd{};
            gfd.session_last_packet_flag  = true;
            gfd.object_last_packet_flag   = false;
            gfd.object_last_byte_flag     = true;
            gfd.code_point                = 9;
            gfd.reserved                  = 5;
            gfd.transport_object_identifier = 0xDEADBEEFu;
            gfd.start_offset              = 0x112233445566u;
            std::vector<std::byte> user{std::byte{0x77}, std::byte{0x88}};
            failures += run_mmtp_gfd_prefix("mmtp-gfd-prefix-lab", 99u, gfd, user);
        }
        {
            atsc3::mmtp_payload_signalling_prefix::decoded_t sig{};
            sig.fragmentation_indicator         = 0;
            sig.reserved                        = 0;
            sig.length_extension_flag           = false;
            sig.aggregation_flag                = false;
            sig.fragment_counter                = 0;
            failures += run_mmtp_signalling_prefix(
                "mmtp-signalling-prefix-default", 2, 0x10u, sig, p);
        }
        {
            atsc3::mmtp_payload_signalling_prefix::decoded_t sig{};
            sig.fragmentation_indicator         = 1;
            sig.reserved                        = 0;
            sig.length_extension_flag           = true;
            sig.aggregation_flag                = false;
            sig.fragment_counter                = 7;
            failures += run_mmtp_signalling_prefix(
                "mmtp-signalling-prefix-4207", 2, 0x10u, sig,
                std::vector<std::byte>{std::byte{0xAA}});
        }
        {
            atsc3::mmtp_payload_signalling_prefix::decoded_t sig_e{};
            sig_e.fragmentation_indicator         = 0;
            sig_e.reserved                        = 0;
            sig_e.length_extension_flag           = false;
            sig_e.aggregation_flag                = false;
            sig_e.fragment_counter                = 0;
            std::vector<std::byte> inner{std::byte{0x10}, std::byte{0x20}, std::byte{0x30}};
            failures += run_mmtp_signalling_prefix_with_length32_envelope(
                "mmtp-signalling-length32-envelope", 2, 0x10u, sig_e, inner);
        }
        {
            atsc3::mmtp_payload_signalling_prefix::decoded_t sig_e{};
            sig_e.fragmentation_indicator         = 0;
            sig_e.reserved                        = 0;
            sig_e.length_extension_flag           = false;
            sig_e.aggregation_flag                = false;
            sig_e.fragment_counter                = 0;
            std::vector<std::byte> inner{std::byte{0x10}, std::byte{0x20}, std::byte{0x30}};
            std::vector<std::byte> desc_wire{
                std::byte{0x10}, std::byte{0x04}, std::byte{0xDE},
                std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};
            failures += run_mmtp_signalling_prefix_with_descriptor_loop_u32(
                "mmtp-signalling-si-desc-loop-u32", 2, 0x10u, sig_e, false,
                desc_wire);
            failures += run_mmtp_signalling_prefix_with_descriptor_loop_u32(
                "mmtp-signalling-si-desc-loop-u32+len32", 2, 0x10u, sig_e, true,
                desc_wire);
            failures += run_mmtp_signalling_prefix_with_message_header_len32(
                "mmtp-signalling-si-msg+len32", 2, 0x10u, sig_e, true, false, 1u,
                3u, inner);
            failures += run_mmtp_signalling_prefix_with_message_header_len32(
                "mmtp-signalling-si-msg+len32+desc", 2, 0x10u, sig_e, true, true,
                0u, 9u, desc_wire);
            failures += run_mmtp_signalling_prefix_with_message_header_len32(
                "mmtp-signalling-si-mpi-msg", 2, 1u, sig_e, false, false, 1u, 0u,
                std::vector<std::byte>{std::byte{0xDE}, std::byte{0xAD}});
            failures += run_mmtp_signalling_prefix_with_message_header_len32(
                "mmtp-signalling-si-mpi-msg-4b", 2, 1u, sig_e, false, false, 1u,
                0u,
                std::vector<std::byte>{std::byte{0xDE}, std::byte{0xAD},
                                       std::byte{0xBE}, std::byte{0xEF}});
            {
                atsc3::gw::encoder_pipeline::config cfg =
                    atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
                        sig_e,
                        atsc3::gw::with_prepended_lab_mmtp_word0(2, 0x10u));
                cfg.prepend_mmt_si_message_header_len32 = true;
                cfg.mmt_si_message_id                   = 1;
                cfg.prepend_mmt_si_pa_table_headers     = true;
                cfg.mmt_si_pa_table_header_rows = {
                    atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row{
                        32, 1, 0}};
                atsc3::gw::encoder_pipeline enc{std::move(cfg)};
                auto bad = enc.encode(std::span<const std::byte>(
                    std::vector<std::byte>{std::byte{0x01}}));
                if (bad.ok) {
                    std::fprintf(stderr,
                                 "[pa-table-headers-mpi-message-id] expected "
                                 "encode failure\n");
                    ++failures;
                }
            }
            failures += run_mmtp_signalling_prefix_with_pa_table_headers_in_message(
                "mmtp-signalling-si-pa-table+msg", 2, 0x10u, sig_e,
                std::vector<std::byte>{std::byte{0x10}, std::byte{0x20},
                                       std::byte{0x30}, std::byte{0x40}});
            failures += run_mmtp_signalling_prefix_with_pa_table_body_in_message(
                "mmtp-signalling-si-pa-table-body+msg", 2, 0x10u, sig_e,
                std::vector<std::byte>{std::byte{0xDE}, std::byte{0xAD},
                                       std::byte{0xBE}, std::byte{0xEF}});
            {
                atsc3::gw::encoder_pipeline::config cfg =
                    atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
                        sig_e,
                        atsc3::gw::with_prepended_lab_mmtp_word0(2, 0x10u));
                cfg.prepend_mmt_si_message_header_len32 = true;
                cfg.mmt_si_message_id                   = 0;
                cfg.prepend_mmt_si_pa_table_headers     = true;
                cfg.mmt_si_pa_table_header_rows = {
                    atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row{
                        32, 1, 4}};
                atsc3::gw::encoder_pipeline enc{std::move(cfg)};
                auto bad = enc.encode(std::span<const std::byte>(
                    std::vector<std::byte>{std::byte{0x01}, std::byte{0x02}}));
                if (bad.ok) {
                    std::fprintf(stderr,
                                 "[pa-table-body-len-mismatch] expected encode "
                                 "failure\n");
                    ++failures;
                }
            }
            failures += run_mmtp_signalling_prefix_with_pa_multi_table_bodies_in_message(
                "mmtp-signalling-si-pa-multi-table-body+msg", 2, 0x10u, sig_e,
                std::vector<std::byte>{std::byte{0xDE}, std::byte{0xAD},
                                       std::byte{0xBE}, std::byte{0xEF},
                                       std::byte{0xCA}, std::byte{0xFE},
                                       std::byte{0xBA}, std::byte{0xBE}});
            {
                atsc3::gw::encoder_pipeline::config cfg =
                    atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
                        sig_e,
                        atsc3::gw::with_prepended_lab_mmtp_word0(2, 0x10u));
                cfg.prepend_mmt_si_message_header_len32 = true;
                cfg.mmt_si_message_id                   = 0;
                cfg.prepend_mmt_si_pa_table_headers     = true;
                cfg.mmt_si_pa_table_header_rows = {
                    atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row{
                        32, 1, 4},
                    atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row{
                        128, 0, 4}};
                atsc3::gw::encoder_pipeline enc{std::move(cfg)};
                auto bad = enc.encode(std::span<const std::byte>(
                    std::vector<std::byte>{std::byte{0x01}, std::byte{0x02},
                                           std::byte{0x03}, std::byte{0x04},
                                           std::byte{0x05}, std::byte{0x06},
                                           std::byte{0x07}}));
                if (bad.ok) {
                    std::fprintf(stderr,
                                 "[pa-multi-table-body-len-mismatch] expected "
                                 "encode failure\n");
                    ++failures;
                }
            }
            failures += run_mmtp_signalling_prefix_with_pa_mixed_table_body_si_tail_in_message(
                "mmtp-signalling-si-pa-mixed-body+tail+msg", 2, 0x10u, sig_e,
                std::vector<std::byte>{std::byte{0xDE}, std::byte{0xAD},
                                       std::byte{0xBE}, std::byte{0xEF},
                                       std::byte{0x10}, std::byte{0x20},
                                       std::byte{0x30}});
            failures +=
                run_mmtp_signalling_prefix_with_pa_table_headers_in_consumption_message(
                    "mmtp-signalling-si-pa-table-consumption-msg", 2, 0x10u, sig_e,
                    std::vector<std::byte>{
                        std::byte{0x01}, std::byte{0x00}, std::byte{0x04},
                        std::byte{0x20}, std::byte{0x01}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x10}, std::byte{0x20},
                        std::byte{0x30}, std::byte{0x40}});
            failures +=
                run_mmtp_signalling_prefix_with_pa_table_body_in_consumption_message(
                    "mmtp-signalling-si-pa-table-body-consumption-msg", 2, 0x10u,
                    sig_e,
                    std::vector<std::byte>{
                        std::byte{0x01}, std::byte{0x00}, std::byte{0x04},
                        std::byte{0x20}, std::byte{0x01}, std::byte{0x00},
                        std::byte{0x04}, std::byte{0xDE}, std::byte{0xAD},
                        std::byte{0xBE}, std::byte{0xEF}});
            failures +=
                run_mmtp_signalling_prefix_with_pa_multi_table_bodies_in_consumption_message(
                    "mmtp-signalling-si-pa-multi-table-consumption-msg", 2, 0x10u,
                    sig_e,
                    std::vector<std::byte>{
                        std::byte{0x02}, std::byte{0x00}, std::byte{0x08},
                        std::byte{0x20}, std::byte{0x01}, std::byte{0x00},
                        std::byte{0x04}, std::byte{0x80}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x04}, std::byte{0xDE},
                        std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF},
                        std::byte{0xCA}, std::byte{0xFE}, std::byte{0xBA},
                        std::byte{0xBE}});
            failures +=
                run_mmtp_signalling_prefix_with_pa_mixed_table_body_si_tail_in_consumption_message(
                    "mmtp-signalling-si-pa-mixed-consumption-msg", 2, 0x10u, sig_e,
                    std::vector<std::byte>{
                        std::byte{0x02}, std::byte{0x00}, std::byte{0x08},
                        std::byte{0x20}, std::byte{0x01}, std::byte{0x00},
                        std::byte{0x04}, std::byte{0x80}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0xDE},
                        std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF},
                        std::byte{0x10}, std::byte{0x20}, std::byte{0x30}});
            failures +=
                run_mmtp_signalling_prefix_with_mpt_table_body_in_consumption_message(
                    "mmtp-signalling-si-mpt-table-body-consumption-msg", 2, 0x10u,
                    sig_e,
                    std::vector<std::byte>{
                        std::byte{0x01}, std::byte{0x00}, std::byte{0x04},
                        std::byte{0x20}, std::byte{0x01}, std::byte{0x00},
                        std::byte{0x09}, std::byte{0x20}, std::byte{0x01},
                        std::byte{0x00}, std::byte{0x05}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}});
            failures +=
                run_mmtp_signalling_prefix_with_mpt_table_body_prefix_in_consumption_message(
                    "mmtp-signalling-si-mpt-table-body-prefix-consumption-msg", 2,
                    0x10u, sig_e,
                    std::vector<std::byte>{
                        std::byte{0x01}, std::byte{0x00}, std::byte{0x04},
                        std::byte{0x20}, std::byte{0x01}, std::byte{0x00},
                        std::byte{0x09}, std::byte{0x20}, std::byte{0x01},
                        std::byte{0x00}, std::byte{0x05}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}});
            failures +=
                run_mmtp_signalling_prefix_with_plt_table_body_in_consumption_message(
                    "mmtp-signalling-si-plt-table-body-consumption-msg", 2, 0x10u,
                    sig_e,
                    std::vector<std::byte>{
                        std::byte{0x01}, std::byte{0x00}, std::byte{0x04},
                        std::byte{0x80}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x06}, std::byte{0x80}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x02}, std::byte{0x00},
                        std::byte{0x00}});
            failures +=
                run_mmtp_signalling_prefix_with_plt_table_body_prefix_in_consumption_message(
                    "mmtp-signalling-si-plt-table-body-prefix-consumption-msg", 2,
                    0x10u, sig_e,
                    std::vector<std::byte>{
                        std::byte{0x01}, std::byte{0x00}, std::byte{0x04},
                        std::byte{0x80}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x06}, std::byte{0x80}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x02}, std::byte{0x00},
                        std::byte{0x00}});
            failures +=
                run_mmtp_signalling_prefix_with_mpt_asset_pa_inline_in_consumption_message(
                    "mmtp-signalling-si-mpt-asset-pa-inline-consumption-msg", 2,
                    0x10u, sig_e,
                    std::vector<std::byte>{
                        std::byte{0x01}, std::byte{0x00}, std::byte{0x04},
                        std::byte{0x20}, std::byte{0x01}, std::byte{0x00},
                        std::byte{0x17}, std::byte{0x20}, std::byte{0x01},
                        std::byte{0x00}, std::byte{0x13}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}});
            failures +=
                run_mmtp_signalling_prefix_with_mpt_asset_id8_location_ipv4_pa_inline_in_consumption_message(
                    "mmtp-signalling-si-mpt-asset-id8-ipv4-pa-inline-consumption-msg", 2,
                    0x10u, sig_e,
                    std::vector<std::byte>{
                        std::byte{0x01}, std::byte{0x00}, std::byte{0x04},
                        std::byte{0x20}, std::byte{0x01}, std::byte{0x00},
                        std::byte{0x23}, std::byte{0x20}, std::byte{0x01},
                        std::byte{0x00}, std::byte{0x1f}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x01}, std::byte{0x01}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x01}, std::byte{0x01},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}});
            failures +=
                run_mmtp_signalling_prefix_with_mpt_asset_id16_location_ipv6_nz_pa_inline_in_consumption_message(
                    "mmtp-signalling-si-mpt-asset-id16-ipv6-nz-pa-inline-consumption-msg",
                    2, 0x10u, sig_e,
                    std::vector<std::byte>{
                        std::byte{0x01}, std::byte{0x00}, std::byte{0x04},
                        std::byte{0x20}, std::byte{0x01}, std::byte{0x00},
                        std::byte{0x3c}, std::byte{0x20}, std::byte{0x01},
                        std::byte{0x00}, std::byte{0x38}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x02}, std::byte{0x01}, std::byte{0x02},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                        std::byte{0x02}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0xff},
                        std::byte{0xff}, std::byte{0x0a}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x01}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0xff}, std::byte{0xff}, std::byte{0xe0},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                        std::byte{0x13}, std::byte{0x88}, std::byte{0x00},
                        std::byte{0x00}});
            failures +=
                run_mmtp_signalling_prefix_with_plt_delivery_pa_inline_in_consumption_message(
                    "mmtp-signalling-si-plt-delivery-pa-inline-consumption-msg", 2,
                    0x10u, sig_e,
                    std::vector<std::byte>{
                        std::byte{0x01}, std::byte{0x00}, std::byte{0x04},
                        std::byte{0x80}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x0d}, std::byte{0x80}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x09}, std::byte{0x00},
                        std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}});
            failures +=
                run_mmtp_signalling_prefix_with_plt_delivery_url3_pa_inline_in_consumption_message(
                    "mmtp-signalling-si-plt-delivery-url3-pa-inline-consumption-msg", 2,
                    0x10u, sig_e,
                    std::vector<std::byte>{
                        std::byte{0x01}, std::byte{0x00}, std::byte{0x04},
                        std::byte{0x80}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x11}, std::byte{0x80}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x0d}, std::byte{0x00},
                        std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x05},
                        std::byte{0x03}, std::byte{0x6c}, std::byte{0x61},
                        std::byte{0x62}, std::byte{0x00}, std::byte{0x00}});
            failures += run_mmtp_signalling_prefix_with_mpt_table_body_in_message(
                "mmtp-signalling-si-mpt-table+msg", 2, 0x10u, sig_e,
                std::vector<std::byte>{std::byte{0x20}, std::byte{0x01},
                                       std::byte{0x00}, std::byte{0x05},
                                       std::byte{0x00}, std::byte{0x00},
                                       std::byte{0x00}, std::byte{0x00},
                                       std::byte{0x00}});
            failures += run_mmtp_signalling_prefix_with_mpt_consumption_message(
                "mmtp-signalling-si-mpt-consumption-msg", 2, 2u, sig_e,
                std::vector<std::byte>{std::byte{0x20}, std::byte{0x01},
                                       std::byte{0x00}, std::byte{0x05},
                                       std::byte{0x00}, std::byte{0x00},
                                       std::byte{0x00}, std::byte{0x00},
                                       std::byte{0x00}});
            {
                atsc3::gw::encoder_pipeline::config cfg =
                    atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
                        sig_e,
                        atsc3::gw::with_prepended_lab_mmtp_word0(2, 2u));
                cfg.prepend_mmt_si_message_header_len32 = true;
                cfg.mmt_si_message_id                   = 16;
                cfg.prepend_mmt_si_pa_table_headers     = true;
                cfg.mmt_si_pa_table_header_rows = {
                    atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row{
                        32, 1, 9}};
                atsc3::gw::encoder_pipeline enc{std::move(cfg)};
                auto bad = enc.encode(std::span<const std::byte>(
                    std::vector<std::byte>{std::byte{0x20}, std::byte{0x01},
                                           std::byte{0x00}, std::byte{0x05},
                                           std::byte{0x00}, std::byte{0x00},
                                           std::byte{0x00}, std::byte{0x00},
                                           std::byte{0x00}}));
                if (bad.ok) {
                    std::fprintf(stderr,
                                 "[pa-table-headers-mpt-message-id] expected "
                                 "encode failure\n");
                    ++failures;
                }
            }
            failures += run_mmtp_signalling_prefix_with_mpi_descriptor_loop_in_message(
                "mmtp-signalling-si-mpi-desc-loop+msg", 2, 1u, sig_e,
                std::vector<std::byte>{std::byte{0x10}, std::byte{0x04},
                                       std::byte{0xDE}, std::byte{0xAD},
                                       std::byte{0xBE}, std::byte{0xEF}});
            failures += run_mmtp_signalling_prefix_with_mpt_asset_in_consumption_message(
                "mmtp-signalling-si-mpt-asset-consumption-msg", 2, 2u, sig_e,
                std::vector<std::byte>{
                    std::byte{0x20}, std::byte{0x01}, std::byte{0x00},
                    std::byte{0x13}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}});
            failures +=
                run_mmtp_signalling_prefix_with_mpt_asset_id8_in_consumption_message(
                    "mmtp-signalling-si-mpt-asset-id8-consumption-msg", 2, 2u,
                    sig_e,
                    std::vector<std::byte>{
                        std::byte{0x20}, std::byte{0x01}, std::byte{0x00},
                        std::byte{0x14}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                        std::byte{0x01}, std::byte{0x01}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}});
            failures +=
                run_mmtp_signalling_prefix_with_plt_delivery_info_in_consumption_message(
                    "mmtp-signalling-si-plt-delivery-consumption-msg", 2,
                    0x10u, sig_e,
                    std::vector<std::byte>{std::byte{0x80}, std::byte{0x00},
                                           std::byte{0x00}, std::byte{0x09},
                                           std::byte{0x00}, std::byte{0x01},
                                           std::byte{0x00}, std::byte{0x00},
                                           std::byte{0x00}, std::byte{0x00},
                                           std::byte{0x00}, std::byte{0x00},
                                           std::byte{0x00}});
            failures +=
                run_mmtp_signalling_prefix_with_mpt_asset_descriptors4_in_consumption_message(
                    "mmtp-signalling-si-mpt-descriptors4-consumption-msg", 2, 2u,
                    sig_e,
                    std::vector<std::byte>{
                        std::byte{0x20}, std::byte{0x01}, std::byte{0x00},
                        std::byte{0x17}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x04},
                        std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE},
                        std::byte{0xEF}});
            failures +=
                run_mmtp_signalling_prefix_with_mpt_asset_location_ipv4_in_consumption_message(
                    "mmtp-signalling-si-mpt-location-ipv4-consumption-msg", 2,
                    2u, sig_e,
                    std::vector<std::byte>{
                        std::byte{0x20}, std::byte{0x01}, std::byte{0x00},
                        std::byte{0x1E}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                        std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}});
            failures +=
                run_mmtp_signalling_prefix_with_plt_package_entry_in_consumption_message(
                    "mmtp-signalling-si-plt-package-consumption-msg", 2,
                    0x10u, sig_e,
                    std::vector<std::byte>{std::byte{0x80}, std::byte{0x00},
                                           std::byte{0x00}, std::byte{0x06},
                                           std::byte{0x01}, std::byte{0x00},
                                           std::byte{0x00}, std::byte{0x00},
                                           std::byte{0x00}, std::byte{0x00}});
            failures +=
                run_mmtp_signalling_prefix_with_plt_package_entry_id8_in_consumption_message(
                    "mmtp-signalling-si-plt-package-id8-consumption-msg", 2,
                    0x10u, sig_e,
                    std::vector<std::byte>{std::byte{0x80}, std::byte{0x00},
                                           std::byte{0x00}, std::byte{0x07},
                                           std::byte{0x01}, std::byte{0x00},
                                           std::byte{0x01}, std::byte{0x01},
                                           std::byte{0x00}, std::byte{0x00},
                                           std::byte{0x00}});
            {
                static const std::uint8_t zn[] = {
                    0x80u, 0x00u, 0x00u, 0x2bu, 0x00u, 0x01u, 0x00u, 0x00u, 0x00u, 0x00u,
                    0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
                    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
                    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
                    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
                };
                std::vector<std::byte> zn_ingress;
                zn_ingress.reserve(sizeof(zn));
                for (const auto b : zn) {
                    zn_ingress.push_back(static_cast<std::byte>(b));
                }
                failures +=
                    run_mmtp_signalling_prefix_with_plt_delivery_info_ipv6_in_consumption_message(
                        "mmtp-signalling-si-plt-delivery-ipv6-consumption-msg", 2, 0x10u,
                        sig_e, zn_ingress);
            }
            {
                std::vector<std::byte> zy_ingress;
                zy_ingress.reserve(58u);
                for (const unsigned b :
                     {0x20u, 0x01u, 0x00u, 0x36u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u}) {
                    zy_ingress.push_back(static_cast<std::byte>(b));
                }
                zy_ingress.insert(zy_ingress.end(), 49u, std::byte{0x00});
                zy_ingress[20] = std::byte{0x01};
                zy_ingress[21] = std::byte{0x02};
                failures +=
                    run_mmtp_signalling_prefix_with_mpt_asset_location_ipv6_in_consumption_message(
                        "mmtp-signalling-si-mpt-asset-location-ipv6-consumption-msg", 2, 2u,
                        sig_e, zy_ingress);
            }
            failures +=
                run_mmtp_signalling_prefix_with_plt_package_entry_ipv4_in_consumption_message(
                    "mmtp-signalling-si-plt-package-ipv4-consumption-msg", 2, 0x10u, sig_e,
                    std::vector<std::byte>{
                        std::byte{0x80}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x0E}, std::byte{0x01}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x01}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}});
            failures +=
                run_mmtp_signalling_prefix_with_mpt_asset_id16_in_consumption_message(
                    "mmtp-signalling-si-mpt-asset-id16-consumption-msg", 2, 2u, sig_e,
                    std::vector<std::byte>{
                        std::byte{0x20}, std::byte{0x01}, std::byte{0x00},
                        std::byte{0x15}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x02},
                        std::byte{0x01}, std::byte{0x02}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}});
            failures +=
                run_mmtp_signalling_prefix_with_plt_delivery_info_url_in_consumption_message(
                    "mmtp-signalling-si-plt-delivery-url-consumption-msg", 2,
                    0x10u, sig_e,
                    std::vector<std::byte>{
                        std::byte{0x80}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x0A}, std::byte{0x00}, std::byte{0x01},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x05}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}});
            {
                std::vector<std::byte> zz_ingress;
                zz_ingress.reserve(42u);
                for (const unsigned b :
                     {0x80u, 0x00u, 0x00u, 0x26u, 0x01u, 0x00u, 0x00u, 0x02u}) {
                    zz_ingress.push_back(static_cast<std::byte>(b));
                }
                zz_ingress.insert(zz_ingress.end(), 34u, std::byte{0x00});
                failures +=
                    run_mmtp_signalling_prefix_with_plt_package_entry_ipv6_in_consumption_message(
                        "mmtp-signalling-si-plt-package-ipv6-consumption-msg", 2,
                        0x10u, sig_e, zz_ingress);
            }
            failures +=
                run_mmtp_signalling_prefix_with_plt_delivery_info_url_4_in_consumption_message(
                    "mmtp-signalling-si-plt-delivery-url4-consumption-msg", 2, 0x10u,
                    sig_e,
                    std::vector<std::byte>{
                        std::byte{0x80}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x0E}, std::byte{0x00}, std::byte{0x01},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x05}, std::byte{0x04},
                        std::byte{0x68}, std::byte{0x74}, std::byte{0x74},
                        std::byte{0x70}, std::byte{0x00}, std::byte{0x00}});
            failures +=
                run_mmtp_signalling_prefix_with_plt_delivery_info_url_3_in_consumption_message(
                    "mmtp-signalling-si-plt-delivery-url3-consumption-msg", 2, 0x10u,
                    sig_e,
                    std::vector<std::byte>{
                        std::byte{0x80}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x0D}, std::byte{0x00}, std::byte{0x01},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x05}, std::byte{0x03},
                        std::byte{0x6C}, std::byte{0x61}, std::byte{0x62},
                        std::byte{0x00}, std::byte{0x00}});
            failures +=
                run_mmtp_signalling_prefix_with_plt_delivery_info_ipv4_nz_in_consumption_message(
                    "mmtp-signalling-si-plt-delivery-ipv4-nz-consumption-msg", 2,
                    0x10u, sig_e,
                    std::vector<std::byte>{
                        std::byte{0x80}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x13}, std::byte{0x00}, std::byte{0x01},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x01}, std::byte{0x0A},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                        std::byte{0xE0}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x01}, std::byte{0x13}, std::byte{0x88},
                        std::byte{0x00}, std::byte{0x00}});
            failures +=
                run_mmtp_signalling_prefix_with_mpt_asset_location_ipv4_nz_in_consumption_message(
                    "mmtp-signalling-si-mpt-asset-location-ipv4-nz-consumption-msg", 2,
                    2u, sig_e,
                    std::vector<std::byte>{
                        std::byte{0x20}, std::byte{0x01}, std::byte{0x00},
                        std::byte{0x1E}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                        std::byte{0x01}, std::byte{0x0A}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x01}, std::byte{0xE0},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                        std::byte{0x13}, std::byte{0x88}, std::byte{0x00},
                        std::byte{0x00}});
            failures +=
                run_mmtp_signalling_prefix_with_plt_package_entry_ipv4_nz_in_consumption_message(
                    "mmtp-signalling-si-plt-package-ipv4-nz-consumption-msg", 2,
                    0x10u, sig_e,
                    std::vector<std::byte>{
                        std::byte{0x80}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x0E}, std::byte{0x01}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x01}, std::byte{0x0A},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                        std::byte{0xE0}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x01}, std::byte{0x13}, std::byte{0x88}});
            {
                std::vector<std::byte> aaj_ingress;
                aaj_ingress.reserve(42u);
                for (const unsigned b :
                     {0x80u, 0x00u, 0x00u, 0x26u, 0x01u, 0x00u, 0x00u, 0x02u}) {
                    aaj_ingress.push_back(static_cast<std::byte>(b));
                }
                const std::uint8_t tail[] = {
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0xff, 0xff, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xe0, 0x00,
                    0x00, 0x01, 0x13, 0x88};
                for (const auto b : tail) {
                    aaj_ingress.push_back(static_cast<std::byte>(b));
                }
                failures +=
                    run_mmtp_signalling_prefix_with_plt_package_entry_ipv6_nz_in_consumption_message(
                        "mmtp-signalling-si-plt-package-ipv6-nz-consumption-msg", 2,
                        0x10u, sig_e, aaj_ingress);
            }
failures +=
                run_mmtp_signalling_prefix_with_mpt_asset_location0_in_consumption_message(
                    "mmtp-signalling-si-mpt-asset-location0-consumption-msg", 2,
                    2u, sig_e,
                    std::vector<std::byte>{std::byte{0x20}, std::byte{0x01}, std::byte{0x00}, std::byte{0x16}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}});
            failures +=
                run_mmtp_signalling_prefix_with_mpt_asset_id8_location_ipv4_in_consumption_message(
                    "mmtp-signalling-si-mpt-asset-id8-location-ipv4-consumption-msg", 2,
                    2u, sig_e,
                    std::vector<std::byte>{std::byte{0x20}, std::byte{0x01}, std::byte{0x00}, std::byte{0x1f}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}});
            failures +=
                run_mmtp_signalling_prefix_with_plt_package_entry_id8_location_ipv4_in_consumption_message(
                    "mmtp-signalling-si-plt-package-entry-id8-location-ipv4-consumption-msg", 2,
                    0x10u, sig_e,
                    std::vector<std::byte>{std::byte{0x80}, std::byte{0x00}, std::byte{0x00}, std::byte{0x0f}, std::byte{0x01}, std::byte{0x00}, std::byte{0x01}, std::byte{0x01}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}});
            failures +=
                run_mmtp_signalling_prefix_with_plt_package_entry_id8_location_ipv4_nz_in_consumption_message(
                    "mmtp-signalling-si-plt-package-entry-id8-location-ipv4-nz-consumption-msg", 2,
                    0x10u, sig_e,
                    std::vector<std::byte>{std::byte{0x80}, std::byte{0x00}, std::byte{0x00}, std::byte{0x0f}, std::byte{0x01}, std::byte{0x00}, std::byte{0x01}, std::byte{0x01}, std::byte{0x01}, std::byte{0x0a}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0xe0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0x13}, std::byte{0x88}});
            failures +=
                run_mmtp_signalling_prefix_with_mpt_asset_id8_location_ipv4_nz_in_consumption_message(
                    "mmtp-signalling-si-mpt-asset-id8-location-ipv4-nz-consumption-msg", 2,
                    2u, sig_e,
                    std::vector<std::byte>{std::byte{0x20}, std::byte{0x01}, std::byte{0x00}, std::byte{0x1f}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0x01}, std::byte{0x0a}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0xe0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0x13}, std::byte{0x88}, std::byte{0x00}, std::byte{0x00}});
            failures +=
                run_mmtp_signalling_prefix_with_mpt_asset_id16_location_ipv4_in_consumption_message(
                    "mmtp-signalling-si-mpt-asset-id16-location-ipv4-consumption-msg", 2,
                    2u, sig_e,
                    std::vector<std::byte>{std::byte{0x20}, std::byte{0x01}, std::byte{0x00}, std::byte{0x20}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02}, std::byte{0x01}, std::byte{0x02}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}});
            failures +=
                run_mmtp_signalling_prefix_with_mpt_asset_id16_location_ipv4_nz_in_consumption_message(
                    "mmtp-signalling-si-mpt-asset-id16-location-ipv4-nz-consumption-msg", 2,
                    2u, sig_e,
                    std::vector<std::byte>{std::byte{0x20}, std::byte{0x01}, std::byte{0x00}, std::byte{0x20}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02}, std::byte{0x01}, std::byte{0x02}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0x01}, std::byte{0x0a}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0xe0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0x13}, std::byte{0x88}, std::byte{0x00}, std::byte{0x00}});
            failures +=
                run_mmtp_signalling_prefix_with_mpt_asset_id16_descriptors4_in_consumption_message(
                    "mmtp-signalling-si-mpt-asset-id16-descriptors4-consumption-msg", 2,
                    2u, sig_e,
                    std::vector<std::byte>{std::byte{0x20}, std::byte{0x01}, std::byte{0x00}, std::byte{0x19}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02}, std::byte{0x01}, std::byte{0x02}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x04}, std::byte{0xde}, std::byte{0xad}, std::byte{0xbe}, std::byte{0xef}});
            {
                static const char *hx =
                    "2001003700000000010000000000010100000000000102000000000000000000000000000000000000000000000000000000000000000000000000";
                std::vector<std::byte> abu_id8_ipv6_ingress;
                abu_id8_ipv6_ingress.reserve(59u);
                for (std::size_t i = 0; hx[i] != '\0'; i += 2) {
                    const auto nyb = [](char c) -> unsigned {
                        if (c >= '0' && c <= '9') {
                            return static_cast<unsigned>(c - '0');
                        }
                        return static_cast<unsigned>(c - 'a' + 10);
                    };
                    abu_id8_ipv6_ingress.push_back(static_cast<std::byte>(
                        (nyb(hx[i]) << 4) | nyb(hx[i + 1])));
                }
            failures +=
                run_mmtp_signalling_prefix_with_mpt_asset_id8_location_ipv6_in_consumption_message(
                    "mmtp-signalling-si-mpt-asset-id8-location-ipv6-consumption-msg", 2, 2u, sig_e,
                    abu_id8_ipv6_ingress);
            }

            {
                static const char *hx =
                    "80000027010001010200000000000000000000000000000000000000000000000000000000000000000000";
                std::vector<std::byte> abu_plt_id8_ipv6_ingress;
                abu_plt_id8_ipv6_ingress.reserve(43u);
                for (std::size_t i = 0; hx[i] != '\0'; i += 2) {
                    const auto nyb = [](char c) -> unsigned {
                        if (c >= '0' && c <= '9') {
                            return static_cast<unsigned>(c - '0');
                        }
                        return static_cast<unsigned>(c - 'a' + 10);
                    };
                    abu_plt_id8_ipv6_ingress.push_back(static_cast<std::byte>(
                        (nyb(hx[i]) << 4) | nyb(hx[i + 1])));
                }
            failures +=
                run_mmtp_signalling_prefix_with_plt_package_entry_id8_location_ipv6_in_consumption_message(
                    "mmtp-signalling-si-plt-package-entry-id8-location-ipv6-consumption-msg", 2, 0x10u, sig_e,
                    abu_plt_id8_ipv6_ingress);
            }

            {
                static const char *hx =
                    "2001003600000000010000000000000000000000010200000000000000000000ffff0a00000100000000000000000000ffffe000000113880000";
                std::vector<std::byte> abu_mpt_loc_ipv6_nz_ingress;
                abu_mpt_loc_ipv6_nz_ingress.reserve(58u);
                for (std::size_t i = 0; hx[i] != '\0'; i += 2) {
                    const auto nyb = [](char c) -> unsigned {
                        if (c >= '0' && c <= '9') {
                            return static_cast<unsigned>(c - '0');
                        }
                        return static_cast<unsigned>(c - 'a' + 10);
                    };
                    abu_mpt_loc_ipv6_nz_ingress.push_back(static_cast<std::byte>(
                        (nyb(hx[i]) << 4) | nyb(hx[i + 1])));
                }
            failures +=
                run_mmtp_signalling_prefix_with_mpt_asset_location_ipv6_nz_in_consumption_message(
                    "mmtp-signalling-si-mpt-asset-location-ipv6-nz-consumption-msg", 2, 2u, sig_e,
                    abu_mpt_loc_ipv6_nz_ingress);
            }

            {
                static const char *hx =
                    "80000027010001010200000000000000000000ffff0a00000100000000000000000000ffffe00000011388";
                std::vector<std::byte> abu_plt_id8_ipv6_nz_ingress;
                abu_plt_id8_ipv6_nz_ingress.reserve(43u);
                for (std::size_t i = 0; hx[i] != '\0'; i += 2) {
                    const auto nyb = [](char c) -> unsigned {
                        if (c >= '0' && c <= '9') {
                            return static_cast<unsigned>(c - '0');
                        }
                        return static_cast<unsigned>(c - 'a' + 10);
                    };
                    abu_plt_id8_ipv6_nz_ingress.push_back(static_cast<std::byte>(
                        (nyb(hx[i]) << 4) | nyb(hx[i + 1])));
                }
            failures +=
                run_mmtp_signalling_prefix_with_plt_package_entry_id8_location_ipv6_nz_in_consumption_message(
                    "mmtp-signalling-si-plt-package-entry-id8-location-ipv6-nz-consumption-msg", 2, 0x10u, sig_e,
                    abu_plt_id8_ipv6_nz_ingress);
            }

            {
                static const char *hx =
                    "200100370000000001000000000001010000000000010200000000000000000000ffff0a00000100000000000000000000ffffe000000113880000";
                std::vector<std::byte> abu_id8_ipv6_nz_ingress;
                abu_id8_ipv6_nz_ingress.reserve(59u);
                for (std::size_t i = 0; hx[i] != '\0'; i += 2) {
                    const auto nyb = [](char c) -> unsigned {
                        if (c >= '0' && c <= '9') {
                            return static_cast<unsigned>(c - '0');
                        }
                        return static_cast<unsigned>(c - 'a' + 10);
                    };
                    abu_id8_ipv6_nz_ingress.push_back(static_cast<std::byte>(
                        (nyb(hx[i]) << 4) | nyb(hx[i + 1])));
                }
            failures +=
                run_mmtp_signalling_prefix_with_mpt_asset_id8_location_ipv6_nz_in_consumption_message(
                    "mmtp-signalling-si-mpt-asset-id8-location-ipv6-nz-consumption-msg", 2, 2u, sig_e,
                    abu_id8_ipv6_nz_ingress);
            }

            {
                static const char *hx =
                    "2001003700000000010000000000020102000000000001020000000000000000000000000000000000000000000000000000000000000000000000";
                std::vector<std::byte> abu_id16_ipv6_ingress;
                abu_id16_ipv6_ingress.reserve(59u);
                for (std::size_t i = 0; hx[i] != '\0'; i += 2) {
                    const auto nyb = [](char c) -> unsigned {
                        if (c >= '0' && c <= '9') {
                            return static_cast<unsigned>(c - '0');
                        }
                        return static_cast<unsigned>(c - 'a' + 10);
                    };
                    abu_id16_ipv6_ingress.push_back(static_cast<std::byte>(
                        (nyb(hx[i]) << 4) | nyb(hx[i + 1])));
                }
            failures +=
                run_mmtp_signalling_prefix_with_mpt_asset_id16_location_ipv6_in_consumption_message(
                    "mmtp-signalling-si-mpt-asset-id16-location-ipv6-consumption-msg", 2, 2u, sig_e,
                    abu_id16_ipv6_ingress);
            }

            {
                static const char *hx =
                    "20010038000000000100000000000201020000000000010200000000000000000000ffff0a00000100000000000000000000ffffe000000113880000";
                std::vector<std::byte> abu_id16_ipv6_nz_ingress;
                abu_id16_ipv6_nz_ingress.reserve(60u);
                for (std::size_t i = 0; hx[i] != '\0'; i += 2) {
                    const auto nyb = [](char c) -> unsigned {
                        if (c >= '0' && c <= '9') {
                            return static_cast<unsigned>(c - '0');
                        }
                        return static_cast<unsigned>(c - 'a' + 10);
                    };
                    abu_id16_ipv6_nz_ingress.push_back(static_cast<std::byte>(
                        (nyb(hx[i]) << 4) | nyb(hx[i + 1])));
                }
            failures +=
                run_mmtp_signalling_prefix_with_mpt_asset_id16_location_ipv6_nz_in_consumption_message(
                    "mmtp-signalling-si-mpt-asset-id16-location-ipv6-nz-consumption-msg", 2, 2u, sig_e,
                    abu_id16_ipv6_nz_ingress);
            }
            failures +=
                run_mmtp_signalling_prefix_with_mpt_asset_id8_descriptors4_in_consumption_message(
                    "mmtp-signalling-si-mpt-id8-desc4-consumption-msg", 2, 2u,
                    sig_e,
                    std::vector<std::byte>{
                        std::byte{0x20}, std::byte{0x01}, std::byte{0x00},
                        std::byte{0x18}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                        std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x04},
                        std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE},
                        std::byte{0xEF}});
            failures +=
                run_mmtp_signalling_prefix_with_plt_delivery_info_ipv4_in_consumption_message(
                    "mmtp-signalling-si-plt-delivery-ipv4-consumption-msg", 2,
                    0x10u, sig_e,
                    std::vector<std::byte>{
                        std::byte{0x80}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x13}, std::byte{0x00}, std::byte{0x01},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x01}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}});
            failures += run_mmtp_signalling_prefix_with_plt_consumption_message(
                "mmtp-signalling-si-plt-consumption-msg", 2, 0x10u, sig_e,
                std::vector<std::byte>{std::byte{0x80}, std::byte{0x00},
                                       std::byte{0x00}, std::byte{0x02},
                                       std::byte{0x00}, std::byte{0x00}});
            failures += run_mmtp_signalling_prefix_with_mpt_asset_in_message(
                "mmtp-signalling-si-mpt-asset+msg", 2, 0x10u, sig_e,
                std::vector<std::byte>{
                    std::byte{0x20}, std::byte{0x01}, std::byte{0x00},
                    std::byte{0x13}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}});
            failures += run_mmtp_signalling_prefix_with_mpt_asset_descriptors4_in_message(
                "mmtp-signalling-si-mpt-asset-descriptors4+msg", 2, 0x10u, sig_e,
                std::vector<std::byte>{
                    std::byte{0x20}, std::byte{0x01}, std::byte{0x00},
                    std::byte{0x17}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x04},
                    std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE},
                    std::byte{0xEF}});
            failures += run_mmtp_signalling_prefix_with_mpt_asset_id8_in_message(
                "mmtp-signalling-si-mpt-asset-id8+msg", 2, 0x10u, sig_e,
                std::vector<std::byte>{
                    std::byte{0x20}, std::byte{0x01}, std::byte{0x00},
                    std::byte{0x14}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                    std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00}});
            failures += run_mmtp_signalling_prefix_with_mpt_asset_id16_in_message(
                "mmtp-signalling-si-mpt-asset-id16+msg", 2, 0x10u, sig_e,
                std::vector<std::byte>{
                    std::byte{0x20}, std::byte{0x01}, std::byte{0x00},
                    std::byte{0x15}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x02},
                    std::byte{0x01}, std::byte{0x02}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}});
            failures += run_mmtp_signalling_prefix_with_mpt_asset_location0_in_message(
                "mmtp-signalling-si-mpt-asset-location0+msg", 2, 0x10u, sig_e,
                std::vector<std::byte>{
                    std::byte{0x20}, std::byte{0x01}, std::byte{0x00},
                    std::byte{0x16}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}});
            failures += run_mmtp_signalling_prefix_with_mpt_asset_location_ipv4_in_message(
                "mmtp-signalling-si-mpt-asset-location-ipv4+msg", 2, 0x10u, sig_e,
                std::vector<std::byte>{
                    std::byte{0x20}, std::byte{0x01}, std::byte{0x00},
                    std::byte{0x1E}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                    std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}});
            failures += run_mmtp_signalling_prefix_with_mpt_asset_location_ipv4_nz_in_message(
                "mmtp-signalling-si-mpt-asset-location-ipv4-nz+msg", 2, 0x10u, sig_e,
                std::vector<std::byte>{
                    std::byte{0x20}, std::byte{0x01}, std::byte{0x00},
                    std::byte{0x1E}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                    std::byte{0x01}, std::byte{0x0A}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x01}, std::byte{0xE0},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                    std::byte{0x13}, std::byte{0x88}, std::byte{0x00},
                    std::byte{0x00}});
            {
                std::vector<std::byte> aah_ingress;
                aah_ingress.reserve(58u);
                for (const unsigned b :
                     {0x20u, 0x01u, 0x00u, 0x36u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u}) {
                    aah_ingress.push_back(static_cast<std::byte>(b));
                }
                const std::uint8_t asset[] = {
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0xff, 0xff, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xe0, 0x00, 0x00,
                    0x01, 0x13, 0x88, 0x00, 0x00};
                for (const auto b : asset) {
                    aah_ingress.push_back(static_cast<std::byte>(b));
                }
                failures +=
                    run_mmtp_signalling_prefix_with_mpt_asset_location_ipv6_nz_in_message(
                        "mmtp-signalling-si-mpt-asset-location-ipv6-nz+msg", 2, 0x10u,
                        sig_e, aah_ingress);
            }
            {
                std::vector<std::byte> zy_ingress;
                zy_ingress.reserve(58u);
                for (const unsigned b :
                     {0x20u, 0x01u, 0x00u, 0x36u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u}) {
                    zy_ingress.push_back(static_cast<std::byte>(b));
                }
                zy_ingress.insert(zy_ingress.end(), 49u, std::byte{0x00});
                zy_ingress[20] = std::byte{0x01};
                zy_ingress[21] = std::byte{0x02};
                failures += run_mmtp_signalling_prefix_with_mpt_asset_location_ipv6_in_message(
                    "mmtp-signalling-si-mpt-asset-location-ipv6+msg", 2, 0x10u,
                    sig_e, zy_ingress);
            }
            failures += run_mmtp_signalling_prefix_with_mpt_asset_id8_location_ipv4_in_message(
                "mmtp-signalling-si-mpt-asset-id8-location-ipv4+msg", 2, 0x10u, sig_e,
                std::vector<std::byte>{
                    std::byte{0x20}, std::byte{0x01}, std::byte{0x00},
                    std::byte{0x1F}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                    std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x01}, std::byte{0x01}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}});
            failures +=
                run_mmtp_signalling_prefix_with_mpt_asset_id8_location_ipv4_nz_in_message(
                    "mmtp-signalling-si-mpt-asset-id8-location-ipv4-nz+msg", 2,
                    0x10u, sig_e,
                    std::vector<std::byte>{
                        std::byte{0x20}, std::byte{0x01}, std::byte{0x00},
                        std::byte{0x1F}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                        std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x01}, std::byte{0x01}, std::byte{0x0A},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                        std::byte{0xE0}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x01}, std::byte{0x13}, std::byte{0x88},
                        std::byte{0x00}, std::byte{0x00}});
            {
                static const char *aaa_hex =
                    "2001003700000000010000000000010100000000000102000000000000000000000000000000000000000000000000000000000000000000000000";
                std::vector<std::byte> aaa_ingress;
                aaa_ingress.reserve(59u);
                for (std::size_t i = 0; aaa_hex[i] != '\0'; i += 2) {
                    const auto nyb = [](char c) -> unsigned {
                        if (c >= '0' && c <= '9') {
                            return static_cast<unsigned>(c - '0');
                        }
                        return static_cast<unsigned>(c - 'a' + 10);
                    };
                    aaa_ingress.push_back(static_cast<std::byte>(
                        (nyb(aaa_hex[i]) << 4) | nyb(aaa_hex[i + 1])));
                }
                failures +=
                    run_mmtp_signalling_prefix_with_mpt_asset_id8_location_ipv6_in_message(
                        "mmtp-signalling-si-mpt-asset-id8-location-ipv6+msg", 2,
                        0x10u, sig_e, aaa_ingress);
            }
            {
                static const char *aan_hex =
                    "200100370000000001000000000001010000000000010200000000000000000000ffff0a00000100000000000000000000ffffe000000113880000";
                std::vector<std::byte> aan_ingress;
                aan_ingress.reserve(59u);
                for (std::size_t i = 0; aan_hex[i] != '\0'; i += 2) {
                    const auto nyb = [](char c) -> unsigned {
                        if (c >= '0' && c <= '9') {
                            return static_cast<unsigned>(c - '0');
                        }
                        return static_cast<unsigned>(c - 'a' + 10);
                    };
                    aan_ingress.push_back(static_cast<std::byte>(
                        (nyb(aan_hex[i]) << 4) | nyb(aan_hex[i + 1])));
                }
                failures +=
                    run_mmtp_signalling_prefix_with_mpt_asset_id8_location_ipv6_nz_in_message(
                        "mmtp-signalling-si-mpt-asset-id8-location-ipv6-nz+msg", 2,
                        0x10u, sig_e, aan_ingress);
            }

            {
                const char *hx = "200100200000000001000000000002010200000000000101000000000000000000000000";
                std::vector<std::byte> ingress;
                ingress.reserve(36u);
                for (std::size_t i = 0; hx[i] != '\0'; i += 2) {
                    const auto nyb = [](char c) -> unsigned {
                        if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
                        return static_cast<unsigned>(c - 'a' + 10);
                    };
                    ingress.push_back(static_cast<std::byte>((nyb(hx[i]) << 4) | nyb(hx[i + 1])));
                }
                failures += run_mmtp_signalling_prefix_with_mpt_asset_id16_location_ipv4_in_message(
                    "mmtp-signalling-si-mpt-asset-id16_location_ipv4+msg", 2, 0x10u, sig_e, ingress);
            }
            {
                const char *hx = "2001002000000000010000000000020102000000000001010a000001e000000113880000";
                std::vector<std::byte> ingress;
                ingress.reserve(36u);
                for (std::size_t i = 0; hx[i] != '\0'; i += 2) {
                    const auto nyb = [](char c) -> unsigned {
                        if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
                        return static_cast<unsigned>(c - 'a' + 10);
                    };
                    ingress.push_back(static_cast<std::byte>((nyb(hx[i]) << 4) | nyb(hx[i + 1])));
                }
                failures += run_mmtp_signalling_prefix_with_mpt_asset_id16_location_ipv4_nz_in_message(
                    "mmtp-signalling-si-mpt-asset-id16_location_ipv4_nz+msg", 2, 0x10u, sig_e, ingress);
            }
            {
                const char *hx = "2001003700000000010000000000020102000000000001020000000000000000000000000000000000000000000000000000000000000000000000";
                std::vector<std::byte> ingress;
                ingress.reserve(59u);
                for (std::size_t i = 0; hx[i] != '\0'; i += 2) {
                    const auto nyb = [](char c) -> unsigned {
                        if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
                        return static_cast<unsigned>(c - 'a' + 10);
                    };
                    ingress.push_back(static_cast<std::byte>((nyb(hx[i]) << 4) | nyb(hx[i + 1])));
                }
                failures += run_mmtp_signalling_prefix_with_mpt_asset_id16_location_ipv6_in_message(
                    "mmtp-signalling-si-mpt-asset-id16_location_ipv6+msg", 2, 0x10u, sig_e, ingress);
            }
            {
                const char *hx = "20010038000000000100000000000201020000000000010200000000000000000000ffff0a00000100000000000000000000ffffe000000113880000";
                std::vector<std::byte> ingress;
                ingress.reserve(60u);
                for (std::size_t i = 0; hx[i] != '\0'; i += 2) {
                    const auto nyb = [](char c) -> unsigned {
                        if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
                        return static_cast<unsigned>(c - 'a' + 10);
                    };
                    ingress.push_back(static_cast<std::byte>((nyb(hx[i]) << 4) | nyb(hx[i + 1])));
                }
                failures += run_mmtp_signalling_prefix_with_mpt_asset_id16_location_ipv6_nz_in_message(
                    "mmtp-signalling-si-mpt-asset-id16_location_ipv6_nz+msg", 2, 0x10u, sig_e, ingress);
            }
            {
                const char *hx = "20010019000000000100000000000201020000000000000004deadbeef";
                std::vector<std::byte> ingress;
                ingress.reserve(29u);
                for (std::size_t i = 0; hx[i] != '\0'; i += 2) {
                    const auto nyb = [](char c) -> unsigned {
                        if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
                        return static_cast<unsigned>(c - 'a' + 10);
                    };
                    ingress.push_back(static_cast<std::byte>((nyb(hx[i]) << 4) | nyb(hx[i + 1])));
                }
                failures += run_mmtp_signalling_prefix_with_mpt_asset_id16_descriptors4_in_message(
                    "mmtp-signalling-si-mpt-asset-id16_descriptors4+msg", 2, 0x10u, sig_e, ingress);
            }
            {
                const char *hx = "200100180000000001000000000001010000000000000004deadbeef";
                std::vector<std::byte> ingress;
                ingress.reserve(28u);
                for (std::size_t i = 0; hx[i] != '\0'; i += 2) {
                    const auto nyb = [](char c) -> unsigned {
                        if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
                        return static_cast<unsigned>(c - 'a' + 10);
                    };
                    ingress.push_back(static_cast<std::byte>((nyb(hx[i]) << 4) | nyb(hx[i + 1])));
                }
                failures += run_mmtp_signalling_prefix_with_mpt_asset_id8_descriptors4_in_message(
                    "mmtp-signalling-si-mpt-asset-id8_descriptors4+msg", 2, 0x10u, sig_e, ingress);
            }            failures += run_mmtp_signalling_prefix_with_plt_delivery_info_in_message(
                "mmtp-signalling-si-plt-delivery+msg", 2, 0x10u, sig_e,
                std::vector<std::byte>{
                    std::byte{0x80}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x09}, std::byte{0x00}, std::byte{0x01},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}});
            failures += run_mmtp_signalling_prefix_with_plt_delivery_info_ipv4_in_message(
                "mmtp-signalling-si-plt-delivery-ipv4+msg", 2, 0x10u, sig_e,
                std::vector<std::byte>{
                    std::byte{0x80}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x13}, std::byte{0x00}, std::byte{0x01},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}});
            {
                std::vector<std::byte> zn_ingress{
                    std::byte{0x80}, std::byte{0x00}, std::byte{0x00}, std::byte{0x2B},
                    std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x02}};
                zn_ingress.insert(zn_ingress.end(), 36, std::byte{0x00});
                failures +=
                    run_mmtp_signalling_prefix_with_plt_delivery_info_ipv6_in_message(
                        "mmtp-signalling-si-plt-delivery-ipv6+msg", 2, 0x10u,
                        sig_e, zn_ingress);
            }
            failures += run_mmtp_signalling_prefix_with_plt_delivery_info_url_in_message(
                "mmtp-signalling-si-plt-delivery-url+msg", 2, 0x10u, sig_e,
                std::vector<std::byte>{
                    std::byte{0x80}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x0A}, std::byte{0x00}, std::byte{0x01},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x05}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}});
            failures += run_mmtp_signalling_prefix_with_plt_package_entry_in_message(
                "mmtp-signalling-si-plt-package-entry+msg", 2, 0x10u, sig_e,
                std::vector<std::byte>{
                    std::byte{0x80}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x06}, std::byte{0x01}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}});
            failures += run_mmtp_signalling_prefix_with_plt_delivery_info_url_3_in_message(
                "mmtp-signalling-si-plt-delivery-url3+msg", 2, 0x10u, sig_e,
                std::vector<std::byte>{
                    std::byte{0x80}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x0D}, std::byte{0x00}, std::byte{0x01},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x05}, std::byte{0x03},
                    std::byte{0x6C}, std::byte{0x61}, std::byte{0x62},
                    std::byte{0x00}, std::byte{0x00}});
            failures += run_mmtp_signalling_prefix_with_plt_delivery_info_url_4_in_message(
                "mmtp-signalling-si-plt-delivery-url4+msg", 2, 0x10u, sig_e,
                std::vector<std::byte>{
                    std::byte{0x80}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x0E}, std::byte{0x00}, std::byte{0x01},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x05}, std::byte{0x04},
                    std::byte{0x68}, std::byte{0x74}, std::byte{0x74},
                    std::byte{0x70}, std::byte{0x00}, std::byte{0x00}});
            failures += run_mmtp_signalling_prefix_with_plt_delivery_info_ipv4_nz_in_message(
                "mmtp-signalling-si-plt-delivery-ipv4-nz+msg", 2, 0x10u, sig_e,
                std::vector<std::byte>{
                    std::byte{0x80}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x13}, std::byte{0x00}, std::byte{0x01},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x01}, std::byte{0x0A},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                    std::byte{0xE0}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x01}, std::byte{0x13}, std::byte{0x88},
                    std::byte{0x00}, std::byte{0x00}});
            failures += run_mmtp_signalling_prefix_with_plt_package_entry_id8_in_message(
                "mmtp-signalling-si-plt-package-entry-id8+msg", 2, 0x10u, sig_e,
                std::vector<std::byte>{
                    std::byte{0x80}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x07}, std::byte{0x01}, std::byte{0x00},
                    std::byte{0x01}, std::byte{0x01}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}});
            failures += run_mmtp_signalling_prefix_with_plt_package_entry_ipv4_in_message(
                "mmtp-signalling-si-plt-package-entry-ipv4+msg", 2, 0x10u, sig_e,
                std::vector<std::byte>{
                    std::byte{0x80}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x0E}, std::byte{0x01}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x01}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x00}});
            failures += run_mmtp_signalling_prefix_with_plt_package_entry_ipv4_nz_in_message(
                "mmtp-signalling-si-plt-package-entry-ipv4-nz+msg", 2, 0x10u, sig_e,
                std::vector<std::byte>{
                    std::byte{0x80}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x0E}, std::byte{0x01}, std::byte{0x00},
                    std::byte{0x00}, std::byte{0x01}, std::byte{0x0A},
                    std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
                    std::byte{0xE0}, std::byte{0x00}, std::byte{0x00},
                    std::byte{0x01}, std::byte{0x13}, std::byte{0x88}});
            failures +=
                run_mmtp_signalling_prefix_with_plt_package_entry_id8_location_ipv4_in_message(
                    "mmtp-signalling-si-plt-package-entry-id8-location-ipv4+msg", 2,
                    0x10u, sig_e,
                    std::vector<std::byte>{
                        std::byte{0x80}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x0F}, std::byte{0x01}, std::byte{0x00},
                        std::byte{0x01}, std::byte{0x01}, std::byte{0x01},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}});
            {
                std::vector<std::byte> zz_ingress;
                zz_ingress.reserve(42u);
                for (const unsigned b :
                     {0x80u, 0x00u, 0x00u, 0x26u, 0x01u, 0x00u, 0x00u, 0x02u}) {
                    zz_ingress.push_back(static_cast<std::byte>(b));
                }
                zz_ingress.insert(zz_ingress.end(), 34u, std::byte{0x00});
                failures += run_mmtp_signalling_prefix_with_plt_package_entry_ipv6_in_message(
                    "mmtp-signalling-si-plt-package-entry-ipv6+msg", 2, 0x10u,
                    sig_e, zz_ingress);
            }
            {
                std::vector<std::byte> aaj_ingress;
                aaj_ingress.reserve(42u);
                for (const unsigned b :
                     {0x80u, 0x00u, 0x00u, 0x26u, 0x01u, 0x00u, 0x00u, 0x02u}) {
                    aaj_ingress.push_back(static_cast<std::byte>(b));
                }
                const std::uint8_t tail[] = {
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0xff, 0xff, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xe0, 0x00,
                    0x00, 0x01, 0x13, 0x88};
                for (const auto b : tail) {
                    aaj_ingress.push_back(static_cast<std::byte>(b));
                }
                failures +=
                    run_mmtp_signalling_prefix_with_plt_package_entry_ipv6_nz_in_message(
                        "mmtp-signalling-si-plt-package-entry-ipv6-nz+msg", 2,
                        0x10u, sig_e, aaj_ingress);
            }
            failures +=
                run_mmtp_signalling_prefix_with_plt_package_entry_id8_location_ipv4_nz_in_message(
                    "mmtp-signalling-si-plt-package-entry-id8-location-ipv4-nz+msg",
                    2, 0x10u, sig_e,
                    std::vector<std::byte>{
                        std::byte{0x80}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x0F}, std::byte{0x01}, std::byte{0x00},
                        std::byte{0x01}, std::byte{0x01}, std::byte{0x01},
                        std::byte{0x0A}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x01}, std::byte{0xE0}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x01}, std::byte{0x13},
                        std::byte{0x88}});
            {
                std::vector<std::byte> aal_ingress;
                aal_ingress.reserve(43u);
                for (const unsigned b :
                     {0x80u, 0x00u, 0x00u, 0x27u, 0x01u, 0x00u, 0x01u, 0x01u, 0x02u}) {
                    aal_ingress.push_back(static_cast<std::byte>(b));
                }
                const std::uint8_t tail[] = {
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0xff, 0xff, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xe0, 0x00,
                    0x00, 0x01, 0x13, 0x88};
                for (const auto b : tail) {
                    aal_ingress.push_back(static_cast<std::byte>(b));
                }
                failures +=
                    run_mmtp_signalling_prefix_with_plt_package_entry_id8_location_ipv6_nz_in_message(
                        "mmtp-signalling-si-plt-package-entry-id8-location-ipv6-nz+msg",
                        2, 0x10u, sig_e, aal_ingress);
            }
            {
                std::vector<std::byte> aab_ingress;
                aab_ingress.reserve(43u);
                for (const unsigned b :
                     {0x80u, 0x00u, 0x00u, 0x27u, 0x01u, 0x00u, 0x01u, 0x01u, 0x02u}) {
                    aab_ingress.push_back(static_cast<std::byte>(b));
                }
                aab_ingress.insert(aab_ingress.end(), 34u, std::byte{0x00});
                failures +=
                    run_mmtp_signalling_prefix_with_plt_package_entry_id8_location_ipv6_in_message(
                        "mmtp-signalling-si-plt-package-entry-id8-location-ipv6+msg",
                        2, 0x10u, sig_e, aab_ingress);
            }
            {
                atsc3::gw::encoder_pipeline::config cfg =
                    atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
                        sig_e,
                        atsc3::gw::with_prepended_lab_mmtp_word0(2, 0x10u));
                cfg.prepend_mmt_si_message_header_len32 = true;
                cfg.mmt_si_message_id                   = 0;
                cfg.prepend_mmt_si_pa_table_headers     = true;
                cfg.mmt_si_pa_table_header_rows = {
                    atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row{
                        32, 1, 4},
                    atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row{
                        128, 0, 0}};
                atsc3::gw::encoder_pipeline enc{std::move(cfg)};
                auto bad = enc.encode(std::span<const std::byte>(
                    std::vector<std::byte>{std::byte{0x01}, std::byte{0x02},
                                           std::byte{0x03}}));
                if (bad.ok) {
                    std::fprintf(stderr,
                                 "[pa-mixed-body-tail-too-short] expected encode "
                                 "failure\n");
                    ++failures;
                }
            }
        }
        {
            atsc3::mmtp_payload_signalling_prefix::decoded_t sig{};
            sig.fragmentation_indicator         = 0;
            sig.reserved                        = 0;
            sig.length_extension_flag           = true;
            sig.aggregation_flag                = true;
            sig.fragment_counter                = 0;
            std::vector<std::vector<std::byte>> agg{
                {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}},
                {std::byte{0xFE}, std::byte{0xED}}};
            failures += run_mmtp_signalling_prefix_with_aggregate(
                "mmtp-signalling-aggregate-32", 2, 0x10u, sig, agg,
                std::vector<std::byte>{std::byte{0x99}});
        }
        {
            atsc3::mmtp_payload_isobmff_prefix::decoded_t iso{};
            iso.fragment_type           = 2;
            iso.timed_flag              = true;
            iso.fragmentation_indicator = 0;
            iso.aggregation_flag        = false;
            iso.fragment_counter        = 0;
            iso.sequence_number         = 287454020;
            std::vector<std::byte> user(94u, std::byte{0x5A});
            failures += run_mmtp_isobmff_prefix("mmtp-isobmff-prefix-lab", 16u,
                                                 iso, user);
            {
                atsc3::mmtp_payload_isobmff_prefix::decoded_t iso_mfu{};
                iso_mfu.fragment_type           = 1;
                iso_mfu.timed_flag              = false;
                iso_mfu.fragmentation_indicator = 0;
                iso_mfu.aggregation_flag        = false;
                iso_mfu.fragment_counter        = 0;
                iso_mfu.sequence_number         = 0x11223344u;
                std::vector<std::byte> mfu_user{std::byte{0x01}, std::byte{0x02}};
                failures += run_mmtp_isobmff_prefix("mmtp-isobmff-mfu-ft1", 16u,
                                                     iso_mfu, mfu_user);
            }
            iso.aggregation_flag = true;
            std::vector<std::vector<std::byte>> agg{
                {std::byte{0xA0}, std::byte{0xA1}},
                {std::byte{0xB0}}};
            std::vector<std::byte> tail{std::byte{0xC0}, std::byte{0xC1}};
            failures += run_mmtp_isobmff_aggregate("mmtp-isobmff-aggregate-lab",
                                                   16u, iso, agg, tail);
            {
                atsc3::mmtp_payload_isobmff_prefix::decoded_t iso_du{};
                iso_du.fragment_type           = 2;
                iso_du.timed_flag              = false;
                iso_du.fragmentation_indicator = 0;
                iso_du.aggregation_flag        = false;
                iso_du.fragment_counter        = 0;
                iso_du.sequence_number         = 0;
                std::vector<std::byte> user{std::byte{0x11}, std::byte{0x22}};
                failures += run_mmtp_isobmff_non_agg_du_header_non_timed(
                    "mmtp-isobmff-duhdr-nonagg-T0", 16u, iso_du, 0xAABBCCDDu,
                    user);
            }
            {
                atsc3::mmtp_payload_isobmff_prefix::decoded_t iso_du{};
                iso_du.fragment_type           = 2;
                iso_du.timed_flag              = true;
                iso_du.fragmentation_indicator = 0;
                iso_du.aggregation_flag        = false;
                iso_du.fragment_counter        = 0;
                iso_du.sequence_number         = 3;
                atsc3::mmtp_payload_isobmff_du_header_timed::decoded_t duh{};
                duh.movie_fragment_sequence_number = 10;
                duh.sample_number                  = 11;
                duh.offset                         = 12;
                duh.subsample_priority             = 13;
                duh.dependency_counter             = 14;
                std::vector<std::byte> user{std::byte{0x33}};
                failures += run_mmtp_isobmff_non_agg_du_header_timed(
                    "mmtp-isobmff-duhdr-nonagg-T1", 16u, iso_du, duh, user);
            }
            {
                atsc3::mmtp_payload_isobmff_prefix::decoded_t iso_du{};
                iso_du.fragment_type           = 2;
                iso_du.timed_flag              = false;
                iso_du.fragmentation_indicator = 0;
                iso_du.aggregation_flag        = true;
                iso_du.fragment_counter        = 1;
                iso_du.sequence_number         = 2;
                std::vector<std::vector<std::byte>> agg_du{
                    {std::byte{0x01}, std::byte{0x02}}};
                std::vector<std::byte> tail_du{std::byte{0xEE}};
                failures += run_mmtp_isobmff_aggregate_du_header_non_timed(
                    "mmtp-isobmff-aggregate-duhdr", 16u, iso_du, 0x11223344u,
                    agg_du, tail_du);
            }
            {
                atsc3::mmtp_payload_isobmff_prefix::decoded_t iso_du{};
                iso_du.fragment_type           = 2;
                iso_du.timed_flag              = true;
                iso_du.fragmentation_indicator = 0;
                iso_du.aggregation_flag        = true;
                iso_du.fragment_counter        = 0;
                iso_du.sequence_number         = 5;
                atsc3::mmtp_payload_isobmff_du_header_timed::decoded_t duh{};
                duh.movie_fragment_sequence_number = 0;
                duh.sample_number                   = 0;
                duh.offset                          = 0;
                duh.subsample_priority              = 0;
                duh.dependency_counter              = 0;
                std::vector<std::vector<std::byte>> agg_du{
                    {std::byte{0xAA}, std::byte{0xBB}},
                    {std::byte{0xCC}}};
                std::vector<std::byte> tail_du{};
                failures += run_mmtp_isobmff_aggregate_du_header_timed(
                    "mmtp-isobmff-aggregate-duhdr-T1", 16u, iso_du, duh,
                    agg_du, tail_du);
            }
        }
        {
            atsc3::gw::encoder_pipeline::config cfg =
                atsc3::gw::with_prepended_lab_mmtp_isobmff_prefix(
                    atsc3::mmtp_payload_isobmff_prefix::decoded_t{},
                    atsc3::gw::with_prepended_lab_mmtp_word0(0, 1));
            cfg.mmtp_isobmff_prefix.fragment_type           = 0;
            cfg.mmtp_isobmff_prefix.timed_flag              = false;
            cfg.mmtp_isobmff_prefix.fragmentation_indicator = 0;
            cfg.mmtp_isobmff_prefix.aggregation_flag        = false;
            cfg.mmtp_isobmff_prefix.fragment_counter        = 0;
            cfg.mmtp_isobmff_prefix.sequence_number         = 0;
            cfg.prepend_mmtp_isobmff_du_header              = true;
            atsc3::gw::encoder_pipeline enc{std::move(cfg)};
            auto r = enc.encode(std::span<const std::byte>(
                std::vector<std::byte>{std::byte{0x01}}));
            if (r.ok) {
                std::fprintf(stderr,
                             "[mmtp-isobmff-duhdr-ft-not2] expected encode failure\n");
                ++failures;
            } else {
                std::printf("[mmtp-isobmff-duhdr-ft-not2] OK (rejected: %s)\n",
                            r.error.c_str());
            }
        }
        {
            atsc3::gw::encoder_pipeline::config cfg =
                atsc3::gw::with_prepended_lab_mmtp_isobmff_prefix(
                    atsc3::mmtp_payload_isobmff_prefix::decoded_t{},
                    atsc3::gw::with_prepended_lab_mmtp_word0(0, 1));
            cfg.mmtp_isobmff_prefix.fragment_type           = 2;
            cfg.mmtp_isobmff_prefix.timed_flag              = false;
            cfg.mmtp_isobmff_prefix.fragmentation_indicator = 0;
            cfg.mmtp_isobmff_prefix.aggregation_flag        = false;
            cfg.mmtp_isobmff_prefix.fragment_counter        = 0;
            cfg.mmtp_isobmff_prefix.sequence_number         = 1;
            cfg.mmtp_isobmff_aggregate_bodies = {
                {std::byte{0x01}}};
            atsc3::gw::encoder_pipeline enc{std::move(cfg)};
            auto r = enc.encode(std::span<const std::byte>(
                std::vector<std::byte>{std::byte{0x02}}));
            if (r.ok) {
                std::fprintf(stderr,
                             "[mmtp-isobmff-agg-without-flag] expected encode failure\n");
                ++failures;
            } else {
                std::printf("[mmtp-isobmff-agg-without-flag] OK (rejected: %s)\n",
                            r.error.c_str());
            }
        }
    }
    {
        atsc3::mmtp_payload_signalling_prefix::decoded_t sig{};
        atsc3::gw::encoder_pipeline enc{
            atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(sig, {})};
        auto r = enc.encode(std::span<const std::byte>(
            std::vector<std::byte>{std::byte{0x01}}));
        if (r.ok) {
            std::fprintf(stderr,
                         "[mmtp-signalling-without-word0] expected encode failure\n");
            ++failures;
        } else {
            std::printf("[mmtp-signalling-without-word0] OK (rejected: %s)\n",
                        r.error.c_str());
        }
    }
    {
        atsc3::gw::encoder_pipeline::config cfg =
            atsc3::gw::with_prepended_lab_mmtp_word0(0, 1);
        cfg.prepend_mmtp_signalling_prefix = true;
        cfg.prepend_mmtp_isobmff_prefix    = true;
        atsc3::gw::encoder_pipeline enc{std::move(cfg)};
        auto r = enc.encode(std::span<const std::byte>(
            std::vector<std::byte>{std::byte{0x01}}));
        if (r.ok) {
            std::fprintf(stderr,
                         "[mmtp-isobmff-signalling-both] expected encode failure\n");
            ++failures;
        } else {
            std::printf("[mmtp-isobmff-signalling-both] OK (rejected: %s)\n",
                        r.error.c_str());
        }
    }

    // 6c) MMTP word‑0 then RFC 5651 LCT word‑0 (gw stitch order)
    {
        std::vector<std::byte> p{std::byte{0xCC}};
        failures += run_mmtp_then_lct("mmtp-then-lct", 2, 0x0010u, 9u, p);
    }

    // 6d) MMTP word‑0 + ts_psn (ISO/IEC 23008-1), optional LCT after
    {
        std::vector<std::byte> p{std::byte{0x55}};
        failures += run_mmtp_tspsn_prefix("mmtp-tspsn-only", 2, 16u,
                                          0x12345678u, 7u, p);
        failures += run_mmtp_tspsn_then_lct("mmtp-tspsn-then-lct", 2, 16u,
                                            0xABCDEF00u, 99u, 3u, p);
    }
    {
        atsc3::gw::encoder_pipeline enc{atsc3::gw::with_prepended_lab_mmtp_ts_psn(
            1u, 2u, {})};
        auto r = enc.encode(std::span<const std::byte>(
            std::vector<std::byte>{std::byte{0x01}}));
        if (r.ok) {
            std::fprintf(stderr,
                         "[mmtp-tspsn-without-word0] expected encode failure\n");
            ++failures;
        } else {
            std::printf("[mmtp-tspsn-without-word0] OK (rejected: %s)\n",
                        r.error.c_str());
        }
    }

    // 6e) MMTP extension TLV (one X block) after word‑0 / optional ts_psn
    {
        std::vector<std::byte> extv = {std::byte{0xDE}, std::byte{0xAD},
                                       std::byte{0xBE}, std::byte{0xEF}};
        std::vector<std::byte> p{std::byte{0x77}};
        failures += run_mmtp_extension_prefix("mmtp-ext-only", 2, 16u,
                                                43981u, std::move(extv), p);
    }
    {
        std::vector<std::byte> ext_a{};
        std::vector<std::byte> ext_b = {std::byte{0x01}, std::byte{0x02}};
        std::vector<std::byte> p{std::byte{0x88}};
        failures += run_mmtp_extension_chain2("mmtp-ext-chain2", 2, 16u, 1u,
                                              std::move(ext_a), 7u,
                                              std::move(ext_b), p);
    }
    {
        std::vector<std::byte> extv = {std::byte{0xDE}, std::byte{0xAD},
                                       std::byte{0xBE}, std::byte{0xEF}};
        std::vector<std::byte> p{std::byte{0x33}};
        failures += run_mmtp_tspsn_extension_prefix(
            "mmtp-tspsn-ext", 2, 16u, 0x11111111u, 0x22222222u, 43981u,
            std::move(extv), p);
    }
    {
        atsc3::gw::encoder_pipeline enc{
            atsc3::gw::with_prepended_lab_mmtp_extension(7u, {}, {})};
        auto r = enc.encode(std::span<const std::byte>(
            std::vector<std::byte>{std::byte{0x01}}));
        if (r.ok) {
            std::fprintf(stderr,
                         "[mmtp-ext-without-word0] expected encode failure\n");
            ++failures;
        } else {
            std::printf("[mmtp-ext-without-word0] OK (rejected: %s)\n",
                        r.error.c_str());
        }
    }

    // 6f) MMTP packet_counter (C=1) after ts_psn; extension after counter
    {
        std::vector<std::byte> p{std::byte{0x99}};
        failures += run_mmtp_tspsn_counter_prefix(
            "mmtp-tspsn-counter", 2, 16u, 0x33333333u, 0x44444444u,
            0xDEADBEEFu, p);
    }
    {
        std::vector<std::byte> extv = {std::byte{0x01}, std::byte{0x02}};
        std::vector<std::byte> p{std::byte{0xEE}};
        failures += run_mmtp_tspsn_counter_ext_prefix(
            "mmtp-tspsn-counter-ext", 2, 16u, 0x55555555u, 0x66666666u,
            0xCAFEBABEu, 99u, std::move(extv), p);
    }
    {
        atsc3::gw::encoder_pipeline enc{atsc3::gw::with_prepended_lab_mmtp_packet_counter(
            1u, atsc3::gw::with_prepended_lab_mmtp_word0(2, 16u))};
        auto r = enc.encode(std::span<const std::byte>(
            std::vector<std::byte>{std::byte{0x01}}));
        if (r.ok) {
            std::fprintf(stderr,
                         "[mmtp-counter-without-tspsn] expected encode failure\n");
            ++failures;
        } else {
            std::printf("[mmtp-counter-without-tspsn] OK (rejected: %s)\n",
                        r.error.c_str());
        }
    }

    // 7) RFC 5651 word-0 lab prefix rides inside ALP (M8 stitch)
    {
        std::vector<std::byte> p{std::byte{0xDE}, std::byte{0xAD}};
        failures += run_lct_prefix("lct-prefix-cp42", 42, p);
    }
    failures += run_lct_prefix("lct-prefix-empty", 0,
                               std::vector<std::byte>{});

    // 8) with 4-byte LCT prefix, max user octets is ALP_max - 4
    {
        std::vector<std::byte> p(2043, std::byte{0x7E});
        failures += run_lct_prefix("alp-max-prepend-user-2043", 0, p);
        std::vector<std::byte> too_big(2044, std::byte{0x7E});
        atsc3::gw::encoder_pipeline enc_bad{
            atsc3::gw::with_prepended_lab_lct_word0(5)};
        auto r = enc_bad.encode(std::span<const std::byte>(too_big));
        if (r.ok) {
            std::fprintf(stderr,
                         "[prepend-oversize-2044] expected failure, got ok\n");
            ++failures;
        } else {
            std::printf("[prepend-oversize-2044] OK (rejected: %s)\n",
                        r.error.c_str());
        }
    }

    // 9) word-0 + 32-bit BE TSI prefix (8-byte header + user)
    {
        std::vector<std::byte> p{std::byte{0xDE}, std::byte{0xAD}};
        failures += run_lct_prefix_tsi("lct-prefix-tsi-cp43", 43, 0xAABBCCDDu, p);
    }
    failures +=
        run_lct_prefix_tsi("lct-prefix-tsi-empty", 0, 0u, std::vector<std::byte>{});

    // 10) with 8-byte LCT prefix, max user octets is ALP_max - 8
    {
        std::vector<std::byte> p(2039, std::byte{0x55});
        failures += run_lct_prefix_tsi("alp-max-prepend-tsi-user-2039", 11, 999u, p);
        std::vector<std::byte> too_big(2040, std::byte{0x55});
        atsc3::gw::encoder_pipeline enc_bad{
            atsc3::gw::with_prepended_lab_lct_word0_tsi(11, 999u)};
        auto r = enc_bad.encode(std::span<const std::byte>(too_big));
        if (r.ok) {
            std::fprintf(stderr,
                         "[prepend-tsi-oversize-2040] expected failure, got ok\n");
            ++failures;
        } else {
            std::printf("[prepend-tsi-oversize-2040] OK (rejected: %s)\n",
                        r.error.c_str());
        }
    }

    // 11) word-0 + 32-bit BE TOI (**RFC5651 O**=1 lab prefix)
    {
        std::vector<std::byte> p{std::byte{0x01}};
        failures += run_lct_prefix_toi("lct-prefix-toi-cp5", 5, 0x11223344u, p);
    }
    failures +=
        run_lct_prefix_toi("lct-prefix-toi-empty", 0, 7u,
                           std::vector<std::byte>{});

    // 12) word-0 + TSI BE32 + TOI BE32 (RFC order; header_length_words = 3)
    {
        std::vector<std::byte> p{std::byte{0xFA}};
        failures += run_lct_prefix_tsi_toi(
            "lct-prefix-tsi-toi-cp9", 9, 0xDEADBEEFu, 0x00C0FFEEu, p);
    }
    failures +=
        run_lct_prefix_tsi_toi("lct-prefix-tsi-toi-empty", 0, 3u, 777u,
                               std::vector<std::byte>{});

    // 13) 12-byte LCT TSI + TOI prefix: max user 2035, reject 2036
    {
        std::vector<std::byte> p(2035, std::byte{0x31});
        failures += run_lct_prefix_tsi_toi("alp-max-prepend-tsi-toi-user-2035",
                                         8, 0x11112222u, 0x33334444u, p);
        std::vector<std::byte> too_big(2036, std::byte{0x31});
        atsc3::gw::encoder_pipeline enc_bad{atsc3::gw::
            with_prepended_lab_lct_word0_tsi_toi(8, 0x11112222u, 0x33334444u)};
        auto r = enc_bad.encode(std::span<const std::byte>(too_big));
        if (r.ok) {
            std::fprintf(stderr,
                         "[prepend-tsi-toi-oversize-2036] expected failure, got "
                         "ok\n");
            ++failures;
        } else {
            std::printf("[prepend-tsi-toi-oversize-2036] OK (rejected: %s)\n",
                        r.error.c_str());
        }
    }

    // 14) 8-byte LCT TOI prefix: max user 2039, reject 2040
    {
        std::vector<std::byte> p(2039, std::byte{0xEE});
        failures += run_lct_prefix_toi("alp-max-prepend-toi-user-2039", 3,
                                       4242u, p);
        std::vector<std::byte> too_big(2040, std::byte{0xEE});
        atsc3::gw::encoder_pipeline enc_bad{
            atsc3::gw::with_prepended_lab_lct_word0_toi(3, 4242u)};
        auto r = enc_bad.encode(std::span<const std::byte>(too_big));
        if (r.ok) {
            std::fprintf(stderr,
                         "[prepend-toi-oversize-2040] expected failure, got ok\n");
            ++failures;
        } else {
            std::printf("[prepend-toi-oversize-2040] OK (rejected: %s)\n",
                        r.error.c_str());
        }
    }

    if (failures == 0) {
        std::printf("encoder_pipeline_test: all cases passed\n");
        return 0;
    }
    std::fprintf(stderr,
                 "encoder_pipeline_test: %d failure(s)\n", failures);
    return 1;
}

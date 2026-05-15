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
#include "mmtp_payload_isobmff_prefix_decoder.h"
#include "mmtp_payload_signalling_prefix_decoder.h"
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

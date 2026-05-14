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

    // 12) 8-byte LCT TOI prefix: max user 2039, reject 2040
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

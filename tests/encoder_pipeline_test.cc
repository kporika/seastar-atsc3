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
#include "tlv_mux_decoder.h"
#include "tlv_mux_types.h"

namespace {

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

    if (failures == 0) {
        std::printf("encoder_pipeline_test: all cases passed\n");
        return 0;
    }
    std::fprintf(stderr,
                 "encoder_pipeline_test: %d failure(s)\n", failures);
    return 1;
}

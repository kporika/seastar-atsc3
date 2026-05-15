// SPDX-License-Identifier: Apache-2.0
//
// mmt_probe — standalone gateway test client.
//
// Subcommands:
//
//   send  --target HOST:PORT [--payloads HEX[,HEX,...]]
//                            [--rtcm-file PATH] [--repeat N]
//                            [--burst N --payload HEX] [--rate PPS]
//                            [--duration SECS]
//
//       Open one TCP connection to the gateway and write each payload
//       as [u32 length, big-endian][payload bytes].
//
//       Source modes (mutually exclusive):
//         --payloads   comma-separated hex blobs (M4 default)
//         --rtcm-file  walk the file as RTCM v3 frames; one per payload
//         --burst      synthetic load: send N copies of --payload
//                      (or 64-byte default), bounded by --duration
//
//       --rate caps payloads-per-second (best-effort).
//       --repeat N replays the source N times in a loop.
//
//   verify  --file PATH --expected-payloads HEX[,HEX,...]
//                       [--validate-rtcm]
//                       [--strip-mmtp-word0 [--expect-mmtp-payload-type N]
//                                             [--expect-mmtp-packet-id U16]]]
//                       [--strip-mmtp-ts-psn [--expect-mmtp-timestamp U32]
//                                             [--expect-mmtp-psn U32]]]
//                       [--strip-mmtp-packet-counter [--expect-mmtp-packet-counter U32]]]
//                       [--strip-mmtp-extension [--strip-mmtp-extension-count N]
//                            [--expect-mmtp-extension-type U16]
//                            [--expect-mmtp-extension-hex HEX]
//                            (N>1: repeated --expect-mmtp-extension-pair TYPE:HEX)]]
//                       [--strip-mmtp-signalling-prefix
//                            [--expect-mmtp-signalling-fragmentation N]
//                            [--expect-mmtp-signalling-reserved N]
//                            [--expect-mmtp-signalling-length-extension 0|1]
//                            [--expect-mmtp-signalling-aggregation 0|1]
//                            [--expect-mmtp-signalling-fragment-counter N]
//                            [--strip-mmtp-signalling-aggregate-count N]
//                            [--expect-mmtp-signalling-aggregate-hex HEX ...]]]
//                       [--strip-mmtp-isobmff-prefix
//                            [--expect-mmtp-isobmff-payload-length-excluding N]
//                            [--expect-mmtp-isobmff-fragment-type N]
//                            [--expect-mmtp-isobmff-timed 0|1]
//                            [--expect-mmtp-isobmff-fragmentation N]
//                            [--expect-mmtp-isobmff-aggregation 0|1]
//                            [--expect-mmtp-isobmff-fragment-counter N]
//                            [--expect-mmtp-isobmff-sequence-number U32]
//                            [--expect-mmtp-isobmff-aggregate-hex HEX ...]]]
//                       [--strip-lct-word0 [--expect-lct-codepoint N]
//                                            [--expect-lct-tsi U32]
//                                            [--expect-lct-toi U32]]]
//
//       Walk the gw sink file as TLV-mux packets, decode the inner ALP,
//       and assert each recovered payload matches expectations. With
//       --validate-rtcm, also CRC-validates each recovered payload as
//       a stand-alone RTCM v3 frame.
//
//       When --strip-mmtp-word0 is set (gateway was run with
//       --prepend-mmtp-word0), peel the ISO/IEC 23008-1 MMTP packet header
//       word‑0 (32b) from the front of each ALP opaque body **before** optional
//       **ts_psn** / **packet_counter** / **extension** chain / **LCT** peels (wire order:
//       MMTP word‑0, optional ts_psn, optional packet_counter, optional extension TLVs,
//       optional **signalling payload prefix** (16b §**9.3.4**) or optional **ISOBMFF**
//       **payload prefix** (64b Figure 3 when **payload_type**=**0**), optional LCT).
//
//       --strip-mmtp-ts-psn peels the 64b **mmtp_header_ts_psn** block **after**
//       --strip-mmtp-word0 (requires **--strip-mmtp-word0**).
//
//       --strip-mmtp-packet-counter peels the 32b **mmtp_header_counter32** block
//       after **ts_psn** (requires **--strip-mmtp-ts-psn**).
//
//       --strip-mmtp-extension peels **mmtp_header_extension** TLV(s) after
//       optional **packet_counter** removal (requires **--strip-mmtp-word0**).
//       Default count is **1**; use **--strip-mmtp-extension-count N** (1–32) when the
//       gateway emitted a chain of **X** TLVs. With count **1**, optional
//       **--expect-mmtp-extension-type** / **--expect-mmtp-extension-hex** apply to that
//       TLV. With count **N>1**, pass **N** **--expect-mmtp-extension-pair TYPE:HEX**
//       arguments in wire order (do not mix with the single-TLV expect flags).
//
//       --strip-mmtp-signalling-aggregate-count N (after the 16b prefix) peels **N**
//       **length**+**body** pairs when **aggregation_flag** was **1** on the wire;
//       each **length** is **16** or **32** bits BE per **length_extension_flag**.
//       Optional **--expect-mmtp-signalling-aggregate-hex** (repeat, same **N**) checks
//       each body.
//
//       With **--strip-mmtp-isobmff-prefix**, when **aggregation_flag** is **1** on the
//       wire, peel **DU_length** (16b BE) + **DU** octets until the ISOBMFF payload
//       length (**payload_length_excluding_length_field** − **6**) is consumed;
//       optional **--expect-mmtp-isobmff-aggregate-hex** (repeat, one per DU) checks
//       each **DU** blob.
//       When --strip-lct-word0 is set (gateway was run with
//       --prepend-lct-word0), peel the RFC 5651 §5.1 word-0 from each ALP
//       opaque body (after optional MMTP peel). Lab extensions after word‑0:
//       32‑bit **TSI** (**S**) and/or (RFC order) **O**=1 **TOI** 32‑bit
//       (`toi_flag` value **1**); match with --expect-lct-tsi / --expect-lct-toi
//       when asserting values.
//
//   rtcm-gen --out PATH --frames N [--msg-type T] [--seed S]
//                                  [--payload-bytes B]
//
//       Deterministically generate a binary file containing N RTCM v3
//       frames suitable for `send --rtcm-file`. Produces stable bytes
//       for a given seed, no external GNSS deps.
//
// Exit code: 0 = success; non-zero = failure (with a stderr message).

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "alp_decoder.h"
#include "lct_rfc5651_word0_decoder.h"
#include "mmtp_header_counter32_decoder.h"
#include "mmtp_header_extension_decoder.h"
#include "mmtp_header_ts_psn_decoder.h"
#include "mmtp_header_word0_decoder.h"
#include "mmtp_payload_isobmff_prefix_decoder.h"
#include "mmtp_payload_signalling_prefix_decoder.h"
#include "tlv_mux_decoder.h"

#include "rtcm_v3.h"

namespace {

// ---- helpers ---------------------------------------------------------------

std::vector<std::byte> hex_to_bytes(std::string_view hex) {
    std::vector<std::byte> out;
    out.reserve(hex.size() / 2);
    auto hexval = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("hex_to_bytes: odd-length hex string");
    }
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const int hi = hexval(hex[i]);
        const int lo = hexval(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            throw std::runtime_error("hex_to_bytes: non-hex character");
        }
        out.push_back(static_cast<std::byte>((hi << 4) | lo));
    }
    return out;
}

std::pair<std::uint16_t, std::vector<std::byte>> parse_mmtp_extension_expect_pair(
    std::string_view spec) {
    const auto colon = spec.find(':');
    if (colon == std::string_view::npos) {
        throw std::runtime_error(
            "--expect-mmtp-extension-pair expects TYPE:HEX (colon required)");
    }
    const std::string type_part(spec.substr(0, colon));
    const unsigned long ty = std::stoul(type_part, nullptr, 0);
    if (ty > 65535ul) {
        throw std::runtime_error(
            "--expect-mmtp-extension-pair: extension type out of range");
    }
    std::string_view hex_sv = spec.substr(colon + 1);
    while (!hex_sv.empty() &&
           std::isspace(static_cast<unsigned char>(hex_sv.front()))) {
        hex_sv.remove_prefix(1);
    }
    while (!hex_sv.empty() &&
           std::isspace(static_cast<unsigned char>(hex_sv.back()))) {
        hex_sv.remove_suffix(1);
    }
    std::vector<std::byte> payload = hex_to_bytes(hex_sv);
    return {static_cast<std::uint16_t>(ty), std::move(payload)};
}

inline std::uint16_t read_be16(std::span<const std::byte> two) noexcept {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(static_cast<std::uint8_t>(two[0])) << 8) |
        static_cast<std::uint16_t>(static_cast<std::uint8_t>(two[1])));
}

constexpr std::size_t k_lct_word0_bytes  = sizeof(std::uint32_t);
constexpr std::size_t k_mmtp_word0_bytes = sizeof(std::uint32_t);
constexpr std::size_t k_mmtp_ts_psn_bytes = 8;
constexpr std::size_t k_mmtp_counter32_bytes = 4;
constexpr std::size_t k_mmtp_signalling_prefix_bytes = 2;
constexpr std::size_t k_mmtp_isobmff_prefix_bytes   = 8;

inline std::uint32_t read_be32(std::span<const std::byte> four) noexcept {
    std::uint32_t x = 0;
    for (auto b : four) {
        x = static_cast<std::uint32_t>(
            (x << 8) | static_cast<std::uint8_t>(b));
    }
    return x;
}

std::string bytes_to_hex(std::span<const std::byte> b) {
    static const char *digits = "0123456789ABCDEF";
    std::string s;
    s.reserve(b.size() * 2);
    for (auto x : b) {
        const auto v = static_cast<std::uint8_t>(x);
        s.push_back(digits[v >> 4]);
        s.push_back(digits[v & 0xF]);
    }
    return s;
}

std::vector<std::string> split_csv(std::string_view s) {
    std::vector<std::string> out;
    std::size_t i = 0;
    while (i < s.size()) {
        const auto j = s.find(',', i);
        const auto end = (j == std::string_view::npos) ? s.size() : j;
        out.emplace_back(s.substr(i, end - i));
        i = (j == std::string_view::npos) ? s.size() : j + 1;
    }
    return out;
}

std::vector<std::byte> read_file(const std::string &path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open " + path);
    std::ostringstream ss;
    ss << f.rdbuf();
    const auto s = ss.str();
    std::vector<std::byte> out(s.size());
    if (!s.empty()) std::memcpy(out.data(), s.data(), s.size());
    return out;
}

void write_file(const std::string &path, std::span<const std::byte> data) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) throw std::runtime_error("cannot create " + path);
    if (!data.empty()) {
        f.write(reinterpret_cast<const char *>(data.data()),
                static_cast<std::streamsize>(data.size()));
    }
}

// Tiny argv parser. Avoids pulling in boost::program_options for a CLI
// that ships as a standalone diagnostic tool.
struct opts {
    std::string subcommand;
    std::string target;
    std::string file;
    std::string out;
    std::string payloads;
    std::string expected;
    std::string rtcm_file;
    std::string single_payload;
    std::uint32_t burst = 0;
    std::uint32_t repeat = 1;
    std::uint32_t rate_pps = 0;       // 0 == unthrottled
    std::uint32_t duration_s = 0;     // 0 == no time bound
    std::uint32_t frames = 0;
    std::uint32_t msg_type = 1005;    // RTCM Stationary RTK Reference Station ARP
    std::uint32_t payload_bytes = 64;
    std::uint64_t seed = 0xC0FFEEu;
    bool validate_rtcm = false;
    /// Peel RFC 5651 §5.1 header word–0 before comparing / RTCM-validation.
    bool strip_lct_word0 = false;
    /// When set with --strip-lct-word0, require this codepoint octet.
    std::optional<std::uint8_t> expect_lct_codepoint;
    /// When set with --strip-lct-word0, compare against the 32-bit TSI peel.
    std::optional<std::uint32_t> expect_lct_tsi;
    /// When set with --strip-lct-word0, compare against the 32-bit TOI peel (O==1).
    std::optional<std::uint32_t> expect_lct_toi;
    /// Peel MMTP packet header word‑0 (32b) before LCT / payload compare.
    bool strip_mmtp_word0 = false;
    /// With --strip-mmtp-word0: require payload_type (0–63).
    std::optional<std::uint8_t> expect_mmtp_payload_type;
    /// With --strip-mmtp-word0: require packet_id (0–65535).
    std::optional<std::uint16_t> expect_mmtp_packet_id;
    /// After MMTP word‑0 peel: remove **mmtp_header_ts_psn** (64b).
    bool strip_mmtp_ts_psn = false;
    /// With --strip-mmtp-ts-psn: require timestamp field.
    std::optional<std::uint32_t> expect_mmtp_timestamp;
    /// With --strip-mmtp-ts-psn: require packet_sequence_number field.
    std::optional<std::uint32_t> expect_mmtp_psn;
    /// After **ts_psn** peel: remove **mmtp_header_counter32** (32b).
    bool strip_mmtp_packet_counter = false;
    std::optional<std::uint32_t> expect_mmtp_packet_counter;
    /// After optional packet_counter peel: remove **mmtp_header_extension** TLV(s).
    bool strip_mmtp_extension = false;
    /// With --strip-mmtp-extension: how many chained **X** TLVs to peel (default **1**).
    std::optional<unsigned> mmtp_extension_strip_count;
    std::optional<std::uint16_t> expect_mmtp_extension_type;
    /// When set, compare extension payload octets exactly after peel.
    std::optional<std::vector<std::byte>> expect_mmtp_extension_payload;
    /// When non-empty, size must equal the extension strip count; wire order **TYPE:HEX** per TLV.
    std::vector<std::pair<std::uint16_t, std::vector<std::byte>>> expect_mmtp_extension_pairs;
    /// After optional extension peel: remove **mmtp_payload_signalling_prefix** (16b).
    bool strip_mmtp_signalling_prefix = false;
    std::optional<std::uint8_t> expect_mmtp_signalling_fragmentation;
    std::optional<std::uint8_t> expect_mmtp_signalling_reserved;
    std::optional<bool> expect_mmtp_signalling_length_extension;
    std::optional<bool> expect_mmtp_signalling_aggregation;
    std::optional<std::uint8_t> expect_mmtp_signalling_fragment_counter;
    /// After **--strip-mmtp-signalling-prefix**: peel **N** aggregated length+body pairs
    /// (**requires** prefix had **aggregation_flag** **1** on the wire). **0** = disabled.
    std::uint32_t mmtp_signalling_aggregate_strip_count = 0;
    /// When non-empty, size must equal **mmtp_signalling_aggregate_strip_count**; each
    /// entry is the expected body octets for that pair (wire order).
    std::vector<std::vector<std::byte>> expect_mmtp_signalling_aggregate_hex;
    /// After optional extension peel: remove **mmtp_payload_isobmff_prefix** (64b;
    /// **payload_type** must be **0**). Mutually exclusive with signalling strip.
    bool strip_mmtp_isobmff_prefix = false;
    std::optional<std::uint16_t> expect_mmtp_isobmff_payload_length_excluding;
    std::optional<std::uint8_t> expect_mmtp_isobmff_fragment_type;
    std::optional<bool> expect_mmtp_isobmff_timed;
    std::optional<std::uint8_t> expect_mmtp_isobmff_fragmentation;
    std::optional<bool> expect_mmtp_isobmff_aggregation;
    std::optional<std::uint8_t> expect_mmtp_isobmff_fragment_counter;
    std::optional<std::uint32_t> expect_mmtp_isobmff_sequence_number;
    /// When non-empty, each entry is expected **DU** octets (after **DU_length**) in
    /// wire order when **aggregation_flag** was **1** (**requires** **--strip-mmtp-isobmff-prefix**).
    std::vector<std::vector<std::byte>> expect_mmtp_isobmff_aggregate_hex;
};

opts parse_args(int argc, char **argv) {
    if (argc < 2) {
        throw std::runtime_error(
            "usage: mmt_probe {send|verify|rtcm-gen} [options]");
    }
    opts o{};
    o.subcommand = argv[1];
    for (int i = 2; i < argc; ++i) {
        std::string_view k = argv[i];
        auto next = [&]() -> std::string_view {
            if (i + 1 >= argc) {
                throw std::runtime_error(
                    std::string("missing value for ") + std::string(k));
            }
            return argv[++i];
        };
        auto next_uint = [&]() -> std::uint64_t {
            return std::stoull(std::string(next()));
        };
        if      (k == "--target")              o.target = next();
        else if (k == "--file")                o.file = next();
        else if (k == "--out")                 o.out = next();
        else if (k == "--payloads")            o.payloads = next();
        else if (k == "--expected-payloads")   o.expected = next();
        else if (k == "--rtcm-file")           o.rtcm_file = next();
        else if (k == "--payload")             o.single_payload = next();
        else if (k == "--burst")               o.burst = static_cast<std::uint32_t>(next_uint());
        else if (k == "--repeat")              o.repeat = static_cast<std::uint32_t>(next_uint());
        else if (k == "--rate")                o.rate_pps = static_cast<std::uint32_t>(next_uint());
        else if (k == "--duration")            o.duration_s = static_cast<std::uint32_t>(next_uint());
        else if (k == "--frames")              o.frames = static_cast<std::uint32_t>(next_uint());
        else if (k == "--msg-type")            o.msg_type = static_cast<std::uint32_t>(next_uint());
        else if (k == "--payload-bytes")       o.payload_bytes = static_cast<std::uint32_t>(next_uint());
        else if (k == "--seed")                o.seed = next_uint();
        else if (k == "--validate-rtcm")       o.validate_rtcm = true;
        else if (k == "--strip-lct-word0")      o.strip_lct_word0 = true;
        else if (k == "--strip-mmtp-word0")     o.strip_mmtp_word0 = true;
        else if (k == "--expect-lct-codepoint") {
            const auto v = next_uint();
            if (v > 255u) {
                throw std::runtime_error("--expect-lct-codepoint must be <= 255");
            }
            o.expect_lct_codepoint = static_cast<std::uint8_t>(v);
        } else if (k == "--expect-lct-tsi") {
            const auto v = next_uint();
            if (v > std::numeric_limits<std::uint32_t>::max()) {
                throw std::runtime_error("--expect-lct-tsi out of uint32 range");
            }
            o.expect_lct_tsi = static_cast<std::uint32_t>(v);
        } else if (k == "--expect-lct-toi") {
            const auto v = next_uint();
            o.expect_lct_toi = static_cast<std::uint32_t>(v);
        } else if (k == "--expect-mmtp-payload-type") {
            const auto v = next_uint();
            if (v > 63u) {
                throw std::runtime_error(
                    "--expect-mmtp-payload-type must be <= 63");
            }
            o.expect_mmtp_payload_type = static_cast<std::uint8_t>(v);
        } else if (k == "--expect-mmtp-packet-id") {
            const auto v = next_uint();
            if (v > 65535u) {
                throw std::runtime_error(
                    "--expect-mmtp-packet-id must be <= 65535");
            }
            o.expect_mmtp_packet_id = static_cast<std::uint16_t>(v);
        } else if (k == "--strip-mmtp-ts-psn") {
            o.strip_mmtp_ts_psn = true;
        } else if (k == "--expect-mmtp-timestamp") {
            const auto v = next_uint();
            o.expect_mmtp_timestamp = static_cast<std::uint32_t>(v);
        } else if (k == "--expect-mmtp-psn") {
            const auto v = next_uint();
            o.expect_mmtp_psn = static_cast<std::uint32_t>(v);
        } else if (k == "--strip-mmtp-packet-counter") {
            o.strip_mmtp_packet_counter = true;
        } else if (k == "--expect-mmtp-packet-counter") {
            const auto v = next_uint();
            o.expect_mmtp_packet_counter = static_cast<std::uint32_t>(v);
        } else if (k == "--strip-mmtp-extension") {
            o.strip_mmtp_extension = true;
        } else if (k == "--strip-mmtp-extension-count") {
            const auto v = next_uint();
            if (v < 1u || v > 32u) {
                throw std::runtime_error(
                    "--strip-mmtp-extension-count must be in 1..32");
            }
            o.mmtp_extension_strip_count = static_cast<unsigned>(v);
        } else if (k == "--expect-mmtp-extension-pair") {
            o.expect_mmtp_extension_pairs.push_back(
                parse_mmtp_extension_expect_pair(next()));
        } else if (k == "--expect-mmtp-extension-type") {
            const auto v = next_uint();
            if (v > 65535u) {
                throw std::runtime_error(
                    "--expect-mmtp-extension-type must be <= 65535");
            }
            o.expect_mmtp_extension_type =
                static_cast<std::uint16_t>(v);
        } else if (k == "--expect-mmtp-extension-hex") {
            o.expect_mmtp_extension_payload =
                hex_to_bytes(std::string(next()));
        } else if (k == "--strip-mmtp-signalling-prefix") {
            o.strip_mmtp_signalling_prefix = true;
        } else if (k == "--expect-mmtp-signalling-fragmentation") {
            const auto v = next_uint();
            if (v > 3u) {
                throw std::runtime_error(
                    "--expect-mmtp-signalling-fragmentation must be <= 3");
            }
            o.expect_mmtp_signalling_fragmentation =
                static_cast<std::uint8_t>(v);
        } else if (k == "--expect-mmtp-signalling-reserved") {
            const auto v = next_uint();
            if (v > 15u) {
                throw std::runtime_error(
                    "--expect-mmtp-signalling-reserved must be <= 15");
            }
            o.expect_mmtp_signalling_reserved =
                static_cast<std::uint8_t>(v);
        } else if (k == "--expect-mmtp-signalling-length-extension") {
            const auto v = next_uint();
            if (v > 1u) {
                throw std::runtime_error(
                    "--expect-mmtp-signalling-length-extension must be 0 or 1");
            }
            o.expect_mmtp_signalling_length_extension = (v != 0);
        } else if (k == "--expect-mmtp-signalling-aggregation") {
            const auto v = next_uint();
            if (v > 1u) {
                throw std::runtime_error(
                    "--expect-mmtp-signalling-aggregation must be 0 or 1");
            }
            o.expect_mmtp_signalling_aggregation = (v != 0);
        } else if (k == "--expect-mmtp-signalling-fragment-counter") {
            const auto v = next_uint();
            if (v > 255u) {
                throw std::runtime_error(
                    "--expect-mmtp-signalling-fragment-counter must be <= 255");
            }
            o.expect_mmtp_signalling_fragment_counter =
                static_cast<std::uint8_t>(v);
        } else if (k == "--strip-mmtp-signalling-aggregate-count") {
            const auto v = next_uint();
            if (v < 1u || v > 256u) {
                throw std::runtime_error(
                    "--strip-mmtp-signalling-aggregate-count must be 1..256");
            }
            o.mmtp_signalling_aggregate_strip_count =
                static_cast<std::uint32_t>(v);
        } else if (k == "--expect-mmtp-signalling-aggregate-hex") {
            o.expect_mmtp_signalling_aggregate_hex.push_back(
                hex_to_bytes(std::string(next())));
        } else if (k == "--strip-mmtp-isobmff-prefix") {
            o.strip_mmtp_isobmff_prefix = true;
        } else if (k == "--expect-mmtp-isobmff-payload-length-excluding") {
            const auto v = next_uint();
            if (v > 65535u) {
                throw std::runtime_error(
                    "--expect-mmtp-isobmff-payload-length-excluding must be <= 65535");
            }
            o.expect_mmtp_isobmff_payload_length_excluding =
                static_cast<std::uint16_t>(v);
        } else if (k == "--expect-mmtp-isobmff-fragment-type") {
            const auto v = next_uint();
            if (v > 15u) {
                throw std::runtime_error(
                    "--expect-mmtp-isobmff-fragment-type must be <= 15");
            }
            o.expect_mmtp_isobmff_fragment_type =
                static_cast<std::uint8_t>(v);
        } else if (k == "--expect-mmtp-isobmff-timed") {
            const auto v = next_uint();
            if (v > 1u) {
                throw std::runtime_error(
                    "--expect-mmtp-isobmff-timed must be 0 or 1");
            }
            o.expect_mmtp_isobmff_timed = (v != 0);
        } else if (k == "--expect-mmtp-isobmff-fragmentation") {
            const auto v = next_uint();
            if (v > 3u) {
                throw std::runtime_error(
                    "--expect-mmtp-isobmff-fragmentation must be <= 3");
            }
            o.expect_mmtp_isobmff_fragmentation =
                static_cast<std::uint8_t>(v);
        } else if (k == "--expect-mmtp-isobmff-aggregation") {
            const auto v = next_uint();
            if (v > 1u) {
                throw std::runtime_error(
                    "--expect-mmtp-isobmff-aggregation must be 0 or 1");
            }
            o.expect_mmtp_isobmff_aggregation = (v != 0);
        } else if (k == "--expect-mmtp-isobmff-fragment-counter") {
            const auto v = next_uint();
            if (v > 255u) {
                throw std::runtime_error(
                    "--expect-mmtp-isobmff-fragment-counter must be <= 255");
            }
            o.expect_mmtp_isobmff_fragment_counter =
                static_cast<std::uint8_t>(v);
        } else if (k == "--expect-mmtp-isobmff-sequence-number") {
            const auto v = next_uint();
            o.expect_mmtp_isobmff_sequence_number =
                static_cast<std::uint32_t>(v);
        } else if (k == "--expect-mmtp-isobmff-aggregate-hex") {
            o.expect_mmtp_isobmff_aggregate_hex.push_back(
                hex_to_bytes(std::string(next())));
        } else throw std::runtime_error(
            std::string("unknown option: ") + std::string(k));
    }
    return o;
}

// ---- network helpers -------------------------------------------------------

int dial(const std::string &target) {
    const auto colon = target.find(':');
    if (colon == std::string::npos) {
        throw std::runtime_error("--target must be HOST:PORT");
    }
    const auto host = target.substr(0, colon);
    const auto port = target.substr(colon + 1);
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo *res = nullptr;
    if (const int rc = ::getaddrinfo(
            host.c_str(), port.c_str(), &hints, &res);
        rc != 0) {
        throw std::runtime_error(
            std::string("getaddrinfo: ") + gai_strerror(rc));
    }
    const int fd = ::socket(
        res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        const auto e = errno;
        ::freeaddrinfo(res);
        throw std::runtime_error(
            std::string("socket: ") + std::strerror(e));
    }
    if (::connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        const auto e = errno;
        ::close(fd);
        ::freeaddrinfo(res);
        throw std::runtime_error(
            "connect " + target + ": " + std::strerror(e));
    }
    ::freeaddrinfo(res);
    return fd;
}

bool send_frame(int fd, std::span<const std::byte> payload) {
    const auto n = static_cast<std::uint32_t>(payload.size());
    std::uint8_t hdr[4] = {
        static_cast<std::uint8_t>((n >> 24) & 0xFF),
        static_cast<std::uint8_t>((n >> 16) & 0xFF),
        static_cast<std::uint8_t>((n >>  8) & 0xFF),
        static_cast<std::uint8_t>( n        & 0xFF),
    };
    if (::send(fd, hdr, 4, 0) != 4) return false;
    std::size_t written = 0;
    while (written < payload.size()) {
        const auto m = ::send(
            fd,
            reinterpret_cast<const char *>(payload.data()) + written,
            payload.size() - written,
            0);
        if (m <= 0) return false;
        written += static_cast<std::size_t>(m);
    }
    return true;
}

// Sleep (best-effort) to maintain --rate. Pass `now` so the caller can
// avoid an extra clock read per iteration.
void rate_pace(std::uint32_t rate_pps, std::uint64_t sent_so_far,
               std::chrono::steady_clock::time_point start) {
    if (rate_pps == 0) return;
    const auto target = start + std::chrono::nanoseconds(
        sent_so_far * 1'000'000'000ull / rate_pps);
    const auto now = std::chrono::steady_clock::now();
    if (target > now) {
        std::this_thread::sleep_for(target - now);
    }
}

// ---- send ------------------------------------------------------------------

int do_send(const opts &o) {
    if (o.target.empty()) {
        std::cerr << "send: --target is required\n";
        return 2;
    }
    const int sources =
        (!o.payloads.empty()  ? 1 : 0) +
        (!o.rtcm_file.empty() ? 1 : 0) +
        (o.burst > 0          ? 1 : 0);
    if (sources != 1) {
        std::cerr << "send: pick exactly one of --payloads / --rtcm-file / --burst\n";
        return 2;
    }

    // Materialize the source frames once. For --burst we synthesize a
    // single template buffer and reuse it to keep memory low.
    std::vector<std::vector<std::byte>> source_frames;
    std::vector<std::byte> burst_template;

    if (!o.payloads.empty()) {
        for (const auto &p : split_csv(o.payloads)) {
            if (!p.empty()) source_frames.push_back(hex_to_bytes(p));
        }
    } else if (!o.rtcm_file.empty()) {
        auto buf = read_file(o.rtcm_file);
        std::vector<mmt_probe::rtcm_v3::frame> frames;
        std::string err;
        const auto n = mmt_probe::rtcm_v3::decode_all(buf, frames, &err);
        if (n == 0 && !err.empty()) {
            std::cerr << "send: rtcm parse error: " << err << "\n";
            return 1;
        }
        source_frames.reserve(frames.size());
        for (const auto &f : frames) {
            source_frames.emplace_back(f.bytes.begin(), f.bytes.end());
        }
        std::cerr << "send: parsed " << source_frames.size()
                  << " RTCM frames from " << o.rtcm_file << "\n";
    } else /* burst */ {
        if (!o.single_payload.empty()) {
            burst_template = hex_to_bytes(o.single_payload);
        } else {
            // Synthetic 0xAA-filled payload; --payload-bytes (default 64)
            // controls the size.
            burst_template.assign(o.payload_bytes, std::byte{0xAA});
        }
    }

    const int fd = dial(o.target);

    std::uint64_t sent = 0;
    const auto start = std::chrono::steady_clock::now();
    const auto deadline = (o.duration_s > 0)
        ? start + std::chrono::seconds(o.duration_s)
        : std::chrono::steady_clock::time_point::max();

    auto over_deadline = [&]() {
        return std::chrono::steady_clock::now() >= deadline;
    };

    auto send_one = [&](std::span<const std::byte> p) -> bool {
        if (!send_frame(fd, p)) {
            std::cerr << "send: short write at frame " << sent << ": "
                      << std::strerror(errno) << "\n";
            return false;
        }
        ++sent;
        rate_pace(o.rate_pps, sent, start);
        return true;
    };

    if (o.burst > 0) {
        for (std::uint32_t i = 0; i < o.burst; ++i) {
            if (over_deadline()) break;
            if (!send_one(burst_template)) { ::close(fd); return 1; }
        }
    } else {
        for (std::uint32_t r = 0; r < o.repeat; ++r) {
            for (const auto &p : source_frames) {
                if (over_deadline()) break;
                if (!send_one(p)) { ::close(fd); return 1; }
            }
            if (over_deadline()) break;
        }
    }

    ::shutdown(fd, SHUT_WR);
    char drain[64];
    while (::recv(fd, drain, sizeof(drain), 0) > 0) { /* discard */ }
    ::close(fd);

    const auto elapsed = std::chrono::steady_clock::now() - start;
    const auto secs =
        std::chrono::duration<double>(elapsed).count();
    const double pps = (secs > 0) ? (sent / secs) : 0.0;
    std::cout << "send: " << sent << " payloads delivered to " << o.target
              << " in " << secs << "s (" << pps << " pps)\n";
    return 0;
}

// ---- verify ----------------------------------------------------------------

int do_verify(const opts &o) {
    if (o.file.empty()) {
        std::cerr << "verify: --file is required\n";
        return 2;
    }
    if (o.expect_mmtp_payload_type.has_value() && !o.strip_mmtp_word0) {
        std::cerr << "verify: --expect-mmtp-payload-type requires "
                     "--strip-mmtp-word0\n";
        return 2;
    }
    if (o.expect_mmtp_packet_id.has_value() && !o.strip_mmtp_word0) {
        std::cerr << "verify: --expect-mmtp-packet-id requires --strip-mmtp-word0\n";
        return 2;
    }
    if (o.expect_mmtp_timestamp.has_value() && !o.strip_mmtp_ts_psn) {
        std::cerr << "verify: --expect-mmtp-timestamp requires --strip-mmtp-ts-psn\n";
        return 2;
    }
    if (o.expect_mmtp_psn.has_value() && !o.strip_mmtp_ts_psn) {
        std::cerr << "verify: --expect-mmtp-psn requires --strip-mmtp-ts-psn\n";
        return 2;
    }
    if (o.strip_mmtp_ts_psn && !o.strip_mmtp_word0) {
        std::cerr << "verify: --strip-mmtp-ts-psn requires --strip-mmtp-word0\n";
        return 2;
    }
    if (o.strip_mmtp_packet_counter && !o.strip_mmtp_ts_psn) {
        std::cerr << "verify: --strip-mmtp-packet-counter requires "
                     "--strip-mmtp-ts-psn\n";
        return 2;
    }
    if (o.strip_mmtp_packet_counter && !o.strip_mmtp_word0) {
        std::cerr << "verify: --strip-mmtp-packet-counter requires "
                     "--strip-mmtp-word0\n";
        return 2;
    }
    if (o.expect_mmtp_packet_counter.has_value() &&
        !o.strip_mmtp_packet_counter) {
        std::cerr << "verify: --expect-mmtp-packet-counter requires "
                     "--strip-mmtp-packet-counter\n";
        return 2;
    }
    if (o.strip_mmtp_extension && !o.strip_mmtp_word0) {
        std::cerr << "verify: --strip-mmtp-extension requires --strip-mmtp-word0\n";
        return 2;
    }
    if (o.expect_mmtp_extension_type.has_value() &&
        !o.strip_mmtp_extension) {
        std::cerr << "verify: --expect-mmtp-extension-type requires "
                     "--strip-mmtp-extension\n";
        return 2;
    }
    if (o.expect_mmtp_extension_payload.has_value() &&
        !o.strip_mmtp_extension) {
        std::cerr << "verify: --expect-mmtp-extension-hex requires "
                     "--strip-mmtp-extension\n";
        return 2;
    }
    if (o.mmtp_extension_strip_count.has_value() && !o.strip_mmtp_extension) {
        std::cerr << "verify: --strip-mmtp-extension-count requires "
                     "--strip-mmtp-extension\n";
        return 2;
    }
    const unsigned mmtp_ext_strip_n =
        o.strip_mmtp_extension ? o.mmtp_extension_strip_count.value_or(1u) : 0u;
    if (!o.expect_mmtp_extension_pairs.empty() && !o.strip_mmtp_extension) {
        std::cerr << "verify: --expect-mmtp-extension-pair requires "
                     "--strip-mmtp-extension\n";
        return 2;
    }
    if (o.strip_mmtp_extension) {
        if (mmtp_ext_strip_n < 1u || mmtp_ext_strip_n > 32u) {
            std::cerr << "verify: --strip-mmtp-extension-count must be in 1..32\n";
            return 2;
        }
        if (!o.expect_mmtp_extension_pairs.empty() &&
            o.expect_mmtp_extension_pairs.size() != mmtp_ext_strip_n) {
            std::cerr << "verify: need " << mmtp_ext_strip_n
                      << " --expect-mmtp-extension-pair values, got "
                      << o.expect_mmtp_extension_pairs.size() << "\n";
            return 2;
        }
        if (mmtp_ext_strip_n > 1u &&
            o.expect_mmtp_extension_pairs.empty() &&
            (o.expect_mmtp_extension_type.has_value() ||
             o.expect_mmtp_extension_payload.has_value())) {
            std::cerr << "verify: when stripping multiple MMTP extensions, use "
                         "--expect-mmtp-extension-pair per TLV\n";
            return 2;
        }
    }
    if (!o.expect_mmtp_extension_pairs.empty() &&
        (o.expect_mmtp_extension_type.has_value() ||
         o.expect_mmtp_extension_payload.has_value())) {
        std::cerr << "verify: do not combine --expect-mmtp-extension-pair with "
                     "--expect-mmtp-extension-type/--expect-mmtp-extension-hex\n";
        return 2;
    }
    if (o.strip_mmtp_signalling_prefix && !o.strip_mmtp_word0) {
        std::cerr << "verify: --strip-mmtp-signalling-prefix requires "
                     "--strip-mmtp-word0\n";
        return 2;
    }
    if (o.expect_mmtp_signalling_fragmentation.has_value() &&
        !o.strip_mmtp_signalling_prefix) {
        std::cerr << "verify: --expect-mmtp-signalling-fragmentation requires "
                     "--strip-mmtp-signalling-prefix\n";
        return 2;
    }
    if (o.expect_mmtp_signalling_reserved.has_value() &&
        !o.strip_mmtp_signalling_prefix) {
        std::cerr << "verify: --expect-mmtp-signalling-reserved requires "
                     "--strip-mmtp-signalling-prefix\n";
        return 2;
    }
    if (o.expect_mmtp_signalling_length_extension.has_value() &&
        !o.strip_mmtp_signalling_prefix) {
        std::cerr << "verify: --expect-mmtp-signalling-length-extension requires "
                     "--strip-mmtp-signalling-prefix\n";
        return 2;
    }
    if (o.expect_mmtp_signalling_aggregation.has_value() &&
        !o.strip_mmtp_signalling_prefix) {
        std::cerr << "verify: --expect-mmtp-signalling-aggregation requires "
                     "--strip-mmtp-signalling-prefix\n";
        return 2;
    }
    if (o.expect_mmtp_signalling_fragment_counter.has_value() &&
        !o.strip_mmtp_signalling_prefix) {
        std::cerr << "verify: --expect-mmtp-signalling-fragment-counter requires "
                     "--strip-mmtp-signalling-prefix\n";
        return 2;
    }
    if (o.mmtp_signalling_aggregate_strip_count != 0 &&
        !o.strip_mmtp_signalling_prefix) {
        std::cerr << "verify: --strip-mmtp-signalling-aggregate-count requires "
                     "--strip-mmtp-signalling-prefix\n";
        return 2;
    }
    if (!o.expect_mmtp_signalling_aggregate_hex.empty() &&
        o.mmtp_signalling_aggregate_strip_count == 0) {
        std::cerr << "verify: --expect-mmtp-signalling-aggregate-hex requires "
                     "--strip-mmtp-signalling-aggregate-count\n";
        return 2;
    }
    if (o.mmtp_signalling_aggregate_strip_count != 0 &&
        !o.expect_mmtp_signalling_aggregate_hex.empty() &&
        o.expect_mmtp_signalling_aggregate_hex.size() !=
            static_cast<std::size_t>(o.mmtp_signalling_aggregate_strip_count)) {
        std::cerr << "verify: need " << o.mmtp_signalling_aggregate_strip_count
                  << " --expect-mmtp-signalling-aggregate-hex values, got "
                  << o.expect_mmtp_signalling_aggregate_hex.size() << "\n";
        return 2;
    }
    if (o.strip_mmtp_signalling_prefix && o.strip_mmtp_isobmff_prefix) {
        std::cerr << "verify: --strip-mmtp-signalling-prefix and "
                     "--strip-mmtp-isobmff-prefix are mutually exclusive\n";
        return 2;
    }
    if (o.strip_mmtp_isobmff_prefix && !o.strip_mmtp_word0) {
        std::cerr << "verify: --strip-mmtp-isobmff-prefix requires "
                     "--strip-mmtp-word0\n";
        return 2;
    }
    if (o.strip_mmtp_isobmff_prefix &&
        (!o.expect_mmtp_payload_type.has_value() ||
         *o.expect_mmtp_payload_type != 0)) {
        std::cerr << "verify: --strip-mmtp-isobmff-prefix requires "
                     "--expect-mmtp-payload-type 0 (ISOBMFF mode)\n";
        return 2;
    }
    if (o.expect_mmtp_isobmff_payload_length_excluding.has_value() &&
        !o.strip_mmtp_isobmff_prefix) {
        std::cerr << "verify: --expect-mmtp-isobmff-payload-length-excluding requires "
                     "--strip-mmtp-isobmff-prefix\n";
        return 2;
    }
    if (o.expect_mmtp_isobmff_fragment_type.has_value() &&
        !o.strip_mmtp_isobmff_prefix) {
        std::cerr << "verify: --expect-mmtp-isobmff-fragment-type requires "
                     "--strip-mmtp-isobmff-prefix\n";
        return 2;
    }
    if (o.expect_mmtp_isobmff_timed.has_value() &&
        !o.strip_mmtp_isobmff_prefix) {
        std::cerr << "verify: --expect-mmtp-isobmff-timed requires "
                     "--strip-mmtp-isobmff-prefix\n";
        return 2;
    }
    if (o.expect_mmtp_isobmff_fragmentation.has_value() &&
        !o.strip_mmtp_isobmff_prefix) {
        std::cerr << "verify: --expect-mmtp-isobmff-fragmentation requires "
                     "--strip-mmtp-isobmff-prefix\n";
        return 2;
    }
    if (o.expect_mmtp_isobmff_aggregation.has_value() &&
        !o.strip_mmtp_isobmff_prefix) {
        std::cerr << "verify: --expect-mmtp-isobmff-aggregation requires "
                     "--strip-mmtp-isobmff-prefix\n";
        return 2;
    }
    if (o.expect_mmtp_isobmff_fragment_counter.has_value() &&
        !o.strip_mmtp_isobmff_prefix) {
        std::cerr << "verify: --expect-mmtp-isobmff-fragment-counter requires "
                     "--strip-mmtp-isobmff-prefix\n";
        return 2;
    }
    if (o.expect_mmtp_isobmff_sequence_number.has_value() &&
        !o.strip_mmtp_isobmff_prefix) {
        std::cerr << "verify: --expect-mmtp-isobmff-sequence-number requires "
                     "--strip-mmtp-isobmff-prefix\n";
        return 2;
    }
    if (!o.expect_mmtp_isobmff_aggregate_hex.empty() &&
        !o.strip_mmtp_isobmff_prefix) {
        std::cerr << "verify: --expect-mmtp-isobmff-aggregate-hex requires "
                     "--strip-mmtp-isobmff-prefix\n";
        return 2;
    }
    if (!o.expect_mmtp_isobmff_aggregate_hex.empty() &&
        (!o.expect_mmtp_isobmff_aggregation.has_value() ||
         !*o.expect_mmtp_isobmff_aggregation)) {
        std::cerr << "verify: --expect-mmtp-isobmff-aggregate-hex requires "
                     "--expect-mmtp-isobmff-aggregation 1\n";
        return 2;
    }
    if (o.expect_lct_codepoint.has_value() && !o.strip_lct_word0) {
        std::cerr << "verify: --expect-lct-codepoint requires --strip-lct-word0\n";
        return 2;
    }
    if (o.expect_lct_tsi.has_value() && !o.strip_lct_word0) {
        std::cerr << "verify: --expect-lct-tsi requires --strip-lct-word0\n";
        return 2;
    }
    if (o.expect_lct_toi.has_value() && !o.strip_lct_word0) {
        std::cerr << "verify: --expect-lct-toi requires --strip-lct-word0\n";
        return 2;
    }
    if (o.expected.empty() && !o.validate_rtcm) {
        std::cerr << "verify: --expected-payloads or --validate-rtcm required\n";
        return 2;
    }
    auto sink = read_file(o.file);
    auto expected_hex = o.expected.empty()
        ? std::vector<std::string>{}
        : split_csv(o.expected);

    std::span<const std::byte> cur(sink);
    std::size_t idx = 0;
    while (!cur.empty()) {
        auto tlv = atsc3::tlv_mux::decode(cur);
        if (!tlv.ok) {
            std::cerr << "verify: tlv_mux decode failed at offset "
                      << (sink.size() - cur.size()) << ": " << tlv.error
                      << "\n";
            return 1;
        }
        auto alp = atsc3::alp::decode(tlv.value.payload);
        if (!alp.ok) {
            std::cerr << "verify: alp decode failed inside TLV-mux #"
                      << idx << ": " << alp.error << "\n";
            return 1;
        }

        const auto alp_body = alp.value.payload;
        std::span<const std::byte> work(alp_body);

        if (o.strip_mmtp_word0) {
            if (work.size() < k_mmtp_word0_bytes) {
                std::cerr << "verify: TLV #" << idx << " ALP opaque too short for "
                             "MMTP word0\n";
                return 1;
            }
            auto mhd = atsc3::mmtp_header_word0::decode(
                work.subspan(0, k_mmtp_word0_bytes));
            if (!mhd.ok) {
                std::cerr << "verify: TLV #" << idx << " MMTP word0 decode: "
                          << mhd.error << "\n";
                return 1;
            }
            if (o.expect_mmtp_payload_type.has_value() &&
                *o.expect_mmtp_payload_type != mhd.value.payload_type) {
                std::cerr << "verify: TLV #" << idx << " MMTP payload_type want "
                          << static_cast<unsigned>(*o.expect_mmtp_payload_type)
                          << " got "
                          << static_cast<unsigned>(mhd.value.payload_type)
                          << "\n";
                return 1;
            }
            if (o.expect_mmtp_packet_id.has_value() &&
                *o.expect_mmtp_packet_id != mhd.value.packet_id) {
                std::cerr << "verify: TLV #" << idx << " MMTP packet_id want "
                          << *o.expect_mmtp_packet_id << " got "
                          << mhd.value.packet_id << "\n";
                return 1;
            }
            work = work.subspan(k_mmtp_word0_bytes);
        }

        if (o.strip_mmtp_ts_psn) {
            if (work.size() < k_mmtp_ts_psn_bytes) {
                std::cerr << "verify: TLV #" << idx << " ALP opaque too short for "
                             "MMTP ts_psn\n";
                return 1;
            }
            auto tsd = atsc3::mmtp_header_ts_psn::decode(
                work.subspan(0, k_mmtp_ts_psn_bytes));
            if (!tsd.ok) {
                std::cerr << "verify: TLV #" << idx << " MMTP ts_psn decode: "
                          << tsd.error << "\n";
                return 1;
            }
            if (o.expect_mmtp_timestamp.has_value() &&
                *o.expect_mmtp_timestamp != tsd.value.timestamp) {
                std::cerr << "verify: TLV #" << idx << " MMTP timestamp want 0x"
                          << std::hex << *o.expect_mmtp_timestamp << " got 0x"
                          << tsd.value.timestamp << std::dec << "\n";
                return 1;
            }
            if (o.expect_mmtp_psn.has_value() &&
                *o.expect_mmtp_psn != tsd.value.packet_sequence_number) {
                std::cerr << "verify: TLV #" << idx << " MMTP PSN want 0x"
                          << std::hex << *o.expect_mmtp_psn << " got 0x"
                          << tsd.value.packet_sequence_number << std::dec
                          << "\n";
                return 1;
            }
            work = work.subspan(k_mmtp_ts_psn_bytes);
        }

        if (o.strip_mmtp_packet_counter) {
            if (work.size() < k_mmtp_counter32_bytes) {
                std::cerr << "verify: TLV #" << idx << " ALP opaque too short for "
                             "MMTP packet_counter\n";
                return 1;
            }
            auto cd = atsc3::mmtp_header_counter32::decode(
                work.subspan(0, k_mmtp_counter32_bytes));
            if (!cd.ok) {
                std::cerr << "verify: TLV #" << idx << " MMTP packet_counter decode: "
                          << cd.error << "\n";
                return 1;
            }
            if (o.expect_mmtp_packet_counter.has_value() &&
                *o.expect_mmtp_packet_counter != cd.value.packet_counter) {
                std::cerr << "verify: TLV #" << idx << " MMTP packet_counter want 0x"
                          << std::hex << *o.expect_mmtp_packet_counter << " got 0x"
                          << cd.value.packet_counter << std::dec << "\n";
                return 1;
            }
            work = work.subspan(k_mmtp_counter32_bytes);
        }

        if (o.strip_mmtp_extension) {
            for (unsigned ext_i = 0; ext_i < mmtp_ext_strip_n; ++ext_i) {
                auto exd = atsc3::mmtp_header_extension::decode(work);
                if (!exd.ok) {
                    std::cerr << "verify: TLV #" << idx << " MMTP extension decode: "
                              << exd.error << "\n";
                    return 1;
                }
                if (!o.expect_mmtp_extension_pairs.empty()) {
                    const auto& pr = o.expect_mmtp_extension_pairs[ext_i];
                    if (pr.first != exd.value.extension_type) {
                        std::cerr << "verify: TLV #" << idx
                                  << " MMTP extension_type want "
                                  << pr.first << " got "
                                  << exd.value.extension_type << "\n";
                        return 1;
                    }
                    const auto& want = pr.second;
                    if (want.size() != exd.value.payload.size() ||
                        !std::equal(want.begin(), want.end(),
                                    exd.value.payload.begin())) {
                        std::cerr << "verify: TLV #" << idx
                                  << " MMTP extension payload mismatch want "
                                  << bytes_to_hex(std::span<const std::byte>(
                                         want.data(), want.size()))
                                  << " got "
                                  << bytes_to_hex(exd.value.payload) << "\n";
                        return 1;
                    }
                } else {
                    if (ext_i == 0) {
                        if (o.expect_mmtp_extension_type.has_value() &&
                            *o.expect_mmtp_extension_type !=
                                exd.value.extension_type) {
                            std::cerr << "verify: TLV #" << idx
                                      << " MMTP extension_type want "
                                      << *o.expect_mmtp_extension_type << " got "
                                      << exd.value.extension_type << "\n";
                            return 1;
                        }
                        if (o.expect_mmtp_extension_payload.has_value()) {
                            const auto& want =
                                *o.expect_mmtp_extension_payload;
                            if (want.size() != exd.value.payload.size() ||
                                !std::equal(
                                    want.begin(), want.end(),
                                    exd.value.payload.begin())) {
                                std::cerr << "verify: TLV #" << idx
                                          << " MMTP extension payload mismatch want "
                                          << bytes_to_hex(std::span<const std::byte>(
                                                 want.data(), want.size()))
                                          << " got "
                                          << bytes_to_hex(exd.value.payload)
                                          << "\n";
                                return 1;
                            }
                        }
                    }
                }
                work = work.subspan(exd.bytes_consumed);
            }
        }

        if (o.strip_mmtp_signalling_prefix) {
            if (work.size() < k_mmtp_signalling_prefix_bytes) {
                std::cerr << "verify: TLV #" << idx << " ALP opaque too short for "
                             "MMTP signalling payload prefix\n";
                return 1;
            }
            auto sgd = atsc3::mmtp_payload_signalling_prefix::decode(
                work.subspan(0, k_mmtp_signalling_prefix_bytes));
            if (!sgd.ok) {
                std::cerr << "verify: TLV #" << idx
                          << " MMTP signalling payload prefix decode: "
                          << sgd.error << "\n";
                return 1;
            }
            if (o.expect_mmtp_signalling_fragmentation.has_value() &&
                *o.expect_mmtp_signalling_fragmentation !=
                    sgd.value.fragmentation_indicator) {
                std::cerr << "verify: TLV #" << idx
                          << " MMTP signalling fragmentation_indicator want "
                          << static_cast<unsigned>(
                                 *o.expect_mmtp_signalling_fragmentation)
                          << " got "
                          << static_cast<unsigned>(
                                 sgd.value.fragmentation_indicator)
                          << "\n";
                return 1;
            }
            if (o.expect_mmtp_signalling_reserved.has_value() &&
                *o.expect_mmtp_signalling_reserved != sgd.value.reserved) {
                std::cerr << "verify: TLV #" << idx
                          << " MMTP signalling reserved want "
                          << static_cast<unsigned>(
                                 *o.expect_mmtp_signalling_reserved)
                          << " got "
                          << static_cast<unsigned>(sgd.value.reserved) << "\n";
                return 1;
            }
            if (o.expect_mmtp_signalling_length_extension.has_value() &&
                *o.expect_mmtp_signalling_length_extension !=
                    sgd.value.length_extension_flag) {
                std::cerr << "verify: TLV #" << idx
                          << " MMTP signalling length_extension_flag mismatch\n";
                return 1;
            }
            if (o.expect_mmtp_signalling_aggregation.has_value() &&
                *o.expect_mmtp_signalling_aggregation !=
                    sgd.value.aggregation_flag) {
                std::cerr << "verify: TLV #" << idx
                          << " MMTP signalling aggregation_flag mismatch\n";
                return 1;
            }
            if (o.expect_mmtp_signalling_fragment_counter.has_value() &&
                *o.expect_mmtp_signalling_fragment_counter !=
                    sgd.value.fragment_counter) {
                std::cerr << "verify: TLV #" << idx
                          << " MMTP signalling fragment_counter want "
                          << static_cast<unsigned>(
                                 *o.expect_mmtp_signalling_fragment_counter)
                          << " got "
                          << static_cast<unsigned>(sgd.value.fragment_counter)
                          << "\n";
                return 1;
            }
            const bool sig_len_ext = sgd.value.length_extension_flag;
            const bool sig_agg   = sgd.value.aggregation_flag;
            work = work.subspan(k_mmtp_signalling_prefix_bytes);
            if (o.mmtp_signalling_aggregate_strip_count != 0) {
                if (!sig_agg) {
                    std::cerr << "verify: TLV #" << idx
                              << " --strip-mmtp-signalling-aggregate-count requires "
                                 "aggregation_flag=1 on the signalling prefix\n";
                    return 1;
                }
                for (std::uint32_t ai = 0;
                     ai < o.mmtp_signalling_aggregate_strip_count; ++ai) {
                    std::size_t body_len = 0;
                    if (sig_len_ext) {
                        if (work.size() < sizeof(std::uint32_t)) {
                            std::cerr << "verify: TLV #" << idx
                                      << " ALP opaque too short for signalling "
                                         "aggregate 32-bit length\n";
                            return 1;
                        }
                        const std::uint32_t bl =
                            read_be32(work.subspan(0, sizeof(std::uint32_t)));
                        work = work.subspan(sizeof(std::uint32_t));
                        body_len = static_cast<std::size_t>(bl);
                    } else {
                        if (work.size() < sizeof(std::uint16_t)) {
                            std::cerr << "verify: TLV #" << idx
                                      << " ALP opaque too short for signalling "
                                         "aggregate 16-bit length\n";
                            return 1;
                        }
                        body_len = read_be16(
                            work.subspan(0, sizeof(std::uint16_t)));
                        work = work.subspan(sizeof(std::uint16_t));
                    }
                    if (work.size() < body_len) {
                        std::cerr << "verify: TLV #" << idx
                                  << " ALP opaque too short for signalling "
                                     "aggregate body (declared len="
                                  << body_len << ")\n";
                        return 1;
                    }
                    const auto body = work.subspan(0, body_len);
                    if (!o.expect_mmtp_signalling_aggregate_hex.empty()) {
                        const auto& want =
                            o.expect_mmtp_signalling_aggregate_hex[ai];
                        if (want.size() != body.size() ||
                            !std::equal(want.begin(), want.end(), body.begin())) {
                            std::cerr << "verify: TLV #" << idx
                                      << " MMTP signalling aggregate body #" << ai
                                      << " mismatch want "
                                      << bytes_to_hex(std::span<const std::byte>(
                                             want.data(), want.size()))
                                      << " got " << bytes_to_hex(body) << "\n";
                            return 1;
                        }
                    }
                    work = work.subspan(body_len);
                }
            }
        }

        if (o.strip_mmtp_isobmff_prefix) {
            if (work.size() < k_mmtp_isobmff_prefix_bytes) {
                std::cerr << "verify: TLV #" << idx << " ALP opaque too short for "
                             "MMTP ISOBMFF payload prefix\n";
                return 1;
            }
            auto isod = atsc3::mmtp_payload_isobmff_prefix::decode(
                work.subspan(0, k_mmtp_isobmff_prefix_bytes));
            if (!isod.ok) {
                std::cerr << "verify: TLV #" << idx
                          << " MMTP ISOBMFF payload prefix decode: "
                          << isod.error << "\n";
                return 1;
            }
            const auto& iso = isod.value;
            const std::size_t tail_octets =
                work.size() - k_mmtp_isobmff_prefix_bytes;
            const std::size_t want_len_exc = 6u + tail_octets;
            if (static_cast<std::size_t>(iso.payload_length_excluding_length_field) !=
                want_len_exc) {
                std::cerr << "verify: TLV #" << idx
                          << " ISOBMFF payload_length_excluding_length_field "
                             "inconsistent with remainder (expected "
                          << want_len_exc << " (= 6 + " << tail_octets
                          << " octets after prefix), got "
                          << iso.payload_length_excluding_length_field << ")\n";
                return 1;
            }
            const std::size_t tail_target =
                static_cast<std::size_t>(iso.payload_length_excluding_length_field) -
                6u;
            const auto tail = work.subspan(k_mmtp_isobmff_prefix_bytes);
            std::size_t du_peel = 0;
            if (iso.aggregation_flag) {
                if (!o.expect_mmtp_isobmff_aggregate_hex.empty()) {
                    for (const auto& want :
                         o.expect_mmtp_isobmff_aggregate_hex) {
                        if (du_peel + 2 > tail_target) {
                            std::cerr << "verify: TLV #" << idx
                                      << " ISOBMFF aggregate DU_length truncated\n";
                            return 1;
                        }
                        const std::uint16_t du_len =
                            read_be16(tail.subspan(du_peel, 2));
                        du_peel += 2;
                        if (static_cast<std::size_t>(du_len) != want.size()) {
                            std::cerr << "verify: TLV #" << idx
                                      << " ISOBMFF DU_length " << du_len
                                      << " != expected body " << want.size()
                                      << "\n";
                            return 1;
                        }
                        if (du_peel + du_len > tail_target) {
                            std::cerr << "verify: TLV #" << idx
                                      << " ISOBMFF aggregate body truncated\n";
                            return 1;
                        }
                        const auto got = tail.subspan(du_peel, du_len);
                        if (!std::equal(got.begin(), got.end(), want.begin())) {
                            std::cerr << "verify: TLV #" << idx
                                      << " ISOBMFF aggregate DU body mismatch want "
                                      << bytes_to_hex(std::span<const std::byte>(
                                             want.data(), want.size()))
                                      << " got " << bytes_to_hex(got) << "\n";
                            return 1;
                        }
                        du_peel += du_len;
                    }
                } else {
                    while (du_peel < tail_target) {
                        if (du_peel + 2 > tail_target) {
                            std::cerr << "verify: TLV #" << idx
                                      << " ISOBMFF DU_length truncated "
                                         "(aggregation, no expect hex)\n";
                            return 1;
                        }
                        const std::uint16_t du_len =
                            read_be16(tail.subspan(du_peel, 2));
                        du_peel += 2;
                        if (du_peel + du_len > tail_target) {
                            std::cerr << "verify: TLV #" << idx
                                      << " ISOBMFF aggregate body overruns "
                                         "declared MMTP payload (no expect hex)\n";
                            return 1;
                        }
                        du_peel += du_len;
                    }
                    if (du_peel != tail_target) {
                        std::cerr << "verify: TLV #" << idx
                                  << " ISOBMFF aggregation parse did not consume "
                                     "full MMTP payload tail\n";
                        return 1;
                    }
                }
            } else {
                if (!o.expect_mmtp_isobmff_aggregate_hex.empty()) {
                    std::cerr << "verify: TLV #" << idx
                              << " ISOBMFF aggregation_flag=0 but "
                                 "--expect-mmtp-isobmff-aggregate-hex given\n";
                    return 1;
                }
                du_peel = tail_target;
            }
            if (o.expect_mmtp_isobmff_payload_length_excluding.has_value() &&
                *o.expect_mmtp_isobmff_payload_length_excluding !=
                    iso.payload_length_excluding_length_field) {
                std::cerr << "verify: TLV #" << idx
                          << " MMTP ISOBMFF payload_length_excluding_length_field want "
                          << *o.expect_mmtp_isobmff_payload_length_excluding
                          << " got " << iso.payload_length_excluding_length_field
                          << "\n";
                return 1;
            }
            if (o.expect_mmtp_isobmff_fragment_type.has_value() &&
                *o.expect_mmtp_isobmff_fragment_type != iso.fragment_type) {
                std::cerr << "verify: TLV #" << idx
                          << " MMTP ISOBMFF fragment_type mismatch\n";
                return 1;
            }
            if (o.expect_mmtp_isobmff_timed.has_value() &&
                *o.expect_mmtp_isobmff_timed != iso.timed_flag) {
                std::cerr << "verify: TLV #" << idx
                          << " MMTP ISOBMFF timed_flag mismatch\n";
                return 1;
            }
            if (o.expect_mmtp_isobmff_fragmentation.has_value() &&
                *o.expect_mmtp_isobmff_fragmentation !=
                    iso.fragmentation_indicator) {
                std::cerr << "verify: TLV #" << idx
                          << " MMTP ISOBMFF fragmentation_indicator mismatch\n";
                return 1;
            }
            if (o.expect_mmtp_isobmff_aggregation.has_value() &&
                *o.expect_mmtp_isobmff_aggregation != iso.aggregation_flag) {
                std::cerr << "verify: TLV #" << idx
                          << " MMTP ISOBMFF aggregation_flag mismatch\n";
                return 1;
            }
            if (o.expect_mmtp_isobmff_fragment_counter.has_value() &&
                *o.expect_mmtp_isobmff_fragment_counter != iso.fragment_counter) {
                std::cerr << "verify: TLV #" << idx
                          << " MMTP ISOBMFF fragment_counter mismatch\n";
                return 1;
            }
            if (o.expect_mmtp_isobmff_sequence_number.has_value() &&
                *o.expect_mmtp_isobmff_sequence_number != iso.sequence_number) {
                std::cerr << "verify: TLV #" << idx
                          << " MMTP ISOBMFF sequence_number mismatch\n";
                return 1;
            }
            if (iso.aggregation_flag) {
                work = work.subspan(k_mmtp_isobmff_prefix_bytes + du_peel);
            } else {
                work = work.subspan(k_mmtp_isobmff_prefix_bytes);
            }
        }

        if (o.strip_lct_word0) {
            if (work.size() < k_lct_word0_bytes) {
                std::cerr << "verify: TLV #" << idx << " ALP opaque too short for "
                             "LCT word0\n";
                return 1;
            }
            auto lctd = atsc3::lct_rfc5651_word0::decode(
                work.subspan(0, k_lct_word0_bytes));
            if (!lctd.ok) {
                std::cerr << "verify: TLV #" << idx << " LCT word0 decode: "
                          << lctd.error << "\n";
                return 1;
            }

            std::size_t off = k_lct_word0_bytes;
            const auto& lv = lctd.value;

            if (!lv.tsi_flag && lv.toi_flag == 0) {
                if (lv.header_length_words != 1) {
                    std::cerr << "verify: TLV #" << idx
                              << " LCT word0-only mode expects "
                                 "header_length_words==1 got "
                              << static_cast<unsigned>(lv.header_length_words)
                              << "\n";
                    return 1;
                }
                if (o.expect_lct_tsi.has_value()) {
                    std::cerr << "verify: TLV #" << idx
                              << " LCT header omits TSI but --expect-lct-tsi "
                                 "given\n";
                    return 1;
                }
                if (o.expect_lct_toi.has_value()) {
                    std::cerr << "verify: TLV #" << idx
                              << " LCT header omits TOI but --expect-lct-toi "
                                 "given\n";
                    return 1;
                }
            } else if (lv.tsi_flag && lv.toi_flag == 0 &&
                       !lv.half_word_flag &&
                       lv.header_length_words == 2) {
                if (o.expect_lct_toi.has_value()) {
                    std::cerr << "verify: TLV #" << idx
                              << " LCT TSI peel but --expect-lct-toi given\n";
                    return 1;
                }
                if (work.size() < off + sizeof(std::uint32_t)) {
                    std::cerr << "verify: TLV #" << idx << " truncated TSI after "
                                                                   "word0\n";
                    return 1;
                }
                const std::uint32_t got_ts =
                    read_be32(work.subspan(off, sizeof(std::uint32_t)));
                if (o.expect_lct_tsi.has_value() &&
                    *o.expect_lct_tsi != got_ts) {
                    std::cerr << "verify: TLV #" << idx << " LCT TSI want 0x"
                              << std::hex << *o.expect_lct_tsi << " got 0x"
                              << got_ts << std::dec << "\n";
                    return 1;
                }
                off += sizeof(std::uint32_t);
            } else if (lv.tsi_flag && lv.toi_flag == 1 &&
                       !lv.half_word_flag &&
                       lv.header_length_words == 3) {
                if (work.size() < off + 2 * sizeof(std::uint32_t)) {
                    std::cerr << "verify: TLV #" << idx
                              << " truncated TSI+TOI after word0\n";
                    return 1;
                }
                const std::uint32_t got_ts =
                    read_be32(work.subspan(off, sizeof(std::uint32_t)));
                if (o.expect_lct_tsi.has_value() &&
                    *o.expect_lct_tsi != got_ts) {
                    std::cerr << "verify: TLV #" << idx << " LCT TSI want 0x"
                              << std::hex << *o.expect_lct_tsi << " got 0x"
                              << got_ts << std::dec << "\n";
                    return 1;
                }
                off += sizeof(std::uint32_t);
                const std::uint32_t got_toi =
                    read_be32(work.subspan(off, sizeof(std::uint32_t)));
                if (o.expect_lct_toi.has_value() &&
                    *o.expect_lct_toi != got_toi) {
                    std::cerr << "verify: TLV #" << idx << " LCT TOI want 0x"
                              << std::hex << *o.expect_lct_toi << " got 0x"
                              << got_toi << std::dec << "\n";
                    return 1;
                }
                off += sizeof(std::uint32_t);
            } else if (!lv.tsi_flag && lv.toi_flag == 1 &&
                       !lv.half_word_flag &&
                       lv.header_length_words == 2) {
                if (o.expect_lct_tsi.has_value()) {
                    std::cerr << "verify: TLV #" << idx
                              << " LCT TOI peel but --expect-lct-tsi given\n";
                    return 1;
                }
                if (work.size() < off + sizeof(std::uint32_t)) {
                    std::cerr << "verify: TLV #" << idx << " truncated TOI after "
                                                                   "word0\n";
                    return 1;
                }
                const std::uint32_t got_toi =
                    read_be32(work.subspan(off, sizeof(std::uint32_t)));
                if (o.expect_lct_toi.has_value() &&
                    *o.expect_lct_toi != got_toi) {
                    std::cerr << "verify: TLV #" << idx << " LCT TOI want 0x"
                              << std::hex << *o.expect_lct_toi << " got 0x"
                              << got_toi << std::dec << "\n";
                    return 1;
                }
                off += sizeof(std::uint32_t);
            } else {
                std::cerr << "verify: TLV #" << idx
                          << " unsupported LCT lab header for --strip-lct-word0\n";
                return 1;
            }

            if (o.expect_lct_codepoint.has_value() &&
                *o.expect_lct_codepoint != lctd.value.codepoint) {
                std::cerr << "verify: TLV #" << idx << " LCT codepoint want "
                          << static_cast<unsigned>(*o.expect_lct_codepoint)
                          << " got "
                          << static_cast<unsigned>(lctd.value.codepoint)
                          << "\n";
                return 1;
            }

            work = work.subspan(off);
        }

        const std::span<const std::byte> inner = work;

        if (!expected_hex.empty()) {
            if (idx >= expected_hex.size()) {
                std::cerr << "verify: extra TLV-mux packet #" << idx
                          << " (no expected)\n";
                return 1;
            }
            const auto expected_bytes = hex_to_bytes(expected_hex[idx]);
            const auto got = bytes_to_hex(inner);
            const auto want = bytes_to_hex(std::span<const std::byte>(
                expected_bytes.data(), expected_bytes.size()));
            if (got != want) {
                std::cerr << "verify: payload mismatch #" << idx
                          << "\n  want: " << want
                          << "\n  got:  " << got << "\n";
                return 1;
            }
        }

        if (o.validate_rtcm) {
            auto rd = mmt_probe::rtcm_v3::decode(inner);
            if (!rd.ok) {
                std::cerr << "verify: payload #" << idx
                          << " is not a valid RTCM frame: " << rd.error
                          << "\n";
                return 1;
            }
            if (rd.bytes_consumed != inner.size()) {
                std::cerr << "verify: payload #" << idx
                          << " has trailing bytes after RTCM frame ("
                          << (inner.size() - rd.bytes_consumed)
                          << ")\n";
                return 1;
            }
        }

        cur = cur.subspan(tlv.bytes_consumed);
        ++idx;
    }

    if (!expected_hex.empty() && idx != expected_hex.size()) {
        std::cerr << "verify: expected " << expected_hex.size()
                  << " payloads, decoded " << idx << "\n";
        return 1;
    }

    std::cout << "verify: OK — " << idx
              << " payload(s) round-tripped through gw ("
              << sink.size() << " sink bytes)";
    if (o.validate_rtcm) std::cout << ", RTCM-CRC validated";
    std::cout << "\n";
    return 0;
}

// ---- rtcm-gen --------------------------------------------------------------

// xorshift64* — small deterministic PRNG so we don't have to pull in <random>'s
// implementation-specific bit pattern. Stable across libstdc++/libc++ versions.
inline std::uint64_t xorshift64s(std::uint64_t &state) {
    auto x = state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    state = x;
    return x * 0x2545F4914F6CDD1Dull;
}

int do_rtcm_gen(const opts &o) {
    if (o.out.empty() || o.frames == 0) {
        std::cerr << "rtcm-gen: --out and --frames are required\n";
        return 2;
    }
    if (o.payload_bytes < 2) {
        std::cerr << "rtcm-gen: --payload-bytes must be >= 2 "
                     "(needs room for the 12-bit message_type prefix)\n";
        return 2;
    }
    if (o.payload_bytes > mmt_probe::rtcm_v3::k_max_payload) {
        std::cerr << "rtcm-gen: --payload-bytes "
                  << o.payload_bytes << " > RTCM 10-bit max "
                  << mmt_probe::rtcm_v3::k_max_payload << "\n";
        return 2;
    }
    if (o.msg_type > 0xFFFu) {
        std::cerr << "rtcm-gen: --msg-type must fit in 12 bits\n";
        return 2;
    }

    std::vector<std::byte> file;
    file.reserve(o.frames * (mmt_probe::rtcm_v3::k_overhead + o.payload_bytes));

    std::uint64_t state = o.seed ? o.seed : 0xC0FFEEu;
    std::vector<std::byte> tail(o.payload_bytes - 2);

    for (std::uint32_t i = 0; i < o.frames; ++i) {
        for (auto &b : tail) {
            b = static_cast<std::byte>(xorshift64s(state) & 0xFFu);
        }
        auto frame_bytes = mmt_probe::rtcm_v3::build(
            static_cast<std::uint16_t>(o.msg_type),
            std::span<const std::byte>(tail.data(), tail.size()));
        if (frame_bytes.empty()) {
            std::cerr << "rtcm-gen: build() failed at frame " << i << "\n";
            return 1;
        }
        file.insert(file.end(), frame_bytes.begin(), frame_bytes.end());
    }

    write_file(o.out, file);
    std::cout << "rtcm-gen: wrote " << o.frames << " frames ("
              << file.size() << " bytes) to " << o.out
              << " — msg_type=" << o.msg_type
              << " payload_bytes=" << o.payload_bytes
              << " seed=0x" << std::hex << o.seed << std::dec << "\n";
    return 0;
}

}  // namespace

int main(int argc, char **argv) {
    try {
        const auto o = parse_args(argc, argv);
        if (o.subcommand == "send")     return do_send(o);
        if (o.subcommand == "verify")   return do_verify(o);
        if (o.subcommand == "rtcm-gen") return do_rtcm_gen(o);
        std::cerr << "unknown subcommand: " << o.subcommand << "\n";
        return 2;
    } catch (const std::exception &e) {
        std::cerr << "mmt_probe: " << e.what() << "\n";
        return 2;
    }
}

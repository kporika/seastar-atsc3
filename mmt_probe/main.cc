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
//                       [--strip-lct-word0 [--expect-lct-codepoint N]
//                                            [--expect-lct-tsi U32]
//                                            [--expect-lct-toi U32]]]
//
//       Walk the gw sink file as TLV-mux packets, decode the inner ALP,
//       and assert each recovered payload matches expectations. With
//       --validate-rtcm, also CRC-validates each recovered payload as
//       a stand-alone RTCM v3 frame.
//
//       When --strip-lct-word0 is set (gateway was run with
//       --prepend-lct-word0), peel the RFC 5651 §5.1 word-0 from each ALP
//       opaque body. Lab extensions after word‑0: 32-bit TSI (**S** set) or
//       32-bit TOI (**O**=1, `toi_flag` value 1 — --expect-lct-toi).
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

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "alp_decoder.h"
#include "lct_rfc5651_word0_decoder.h"
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

constexpr std::size_t k_lct_word0_bytes = sizeof(std::uint32_t);

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
    if (o.expect_lct_tsi.has_value() && o.expect_lct_toi.has_value()) {
        std::cerr << "verify: --expect-lct-tsi and --expect-lct-toi are mutually exclusive\n";
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
        std::span<const std::byte> inner(alp_body);

        if (o.strip_lct_word0) {
            if (alp_body.size() < k_lct_word0_bytes) {
                std::cerr << "verify: TLV #" << idx << " ALP opaque too short for "
                             "LCT word0\n";
                return 1;
            }
            auto lctd = atsc3::lct_rfc5651_word0::decode(
                alp_body.subspan(0, k_lct_word0_bytes));
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
                if (alp_body.size() < off + sizeof(std::uint32_t)) {
                    std::cerr << "verify: TLV #" << idx << " truncated TSI after "
                                                                   "word0\n";
                    return 1;
                }
                const std::uint32_t got_ts =
                    read_be32(alp_body.subspan(off, sizeof(std::uint32_t)));
                if (o.expect_lct_tsi.has_value() &&
                    *o.expect_lct_tsi != got_ts) {
                    std::cerr << "verify: TLV #" << idx << " LCT TSI want 0x"
                              << std::hex << *o.expect_lct_tsi << " got 0x"
                              << got_ts << std::dec << "\n";
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
                if (alp_body.size() < off + sizeof(std::uint32_t)) {
                    std::cerr << "verify: TLV #" << idx << " truncated TOI after "
                                                                   "word0\n";
                    return 1;
                }
                const std::uint32_t got_toi =
                    read_be32(alp_body.subspan(off, sizeof(std::uint32_t)));
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

            inner = alp_body.subspan(off);
        }

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

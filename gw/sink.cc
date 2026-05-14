// SPDX-License-Identifier: Apache-2.0

#include "sink.h"

#include <fcntl.h>
#include <cstdio>
#include <unistd.h>

#include <charconv>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <zlib.h>

#include <seastar/core/coroutine.hh>
#include <seastar/core/file.hh>
#include <seastar/core/fstream.hh>
#include <seastar/core/iostream.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/seastar.hh>
#include <seastar/core/sstring.hh>
#include <seastar/net/dns.hh>
#include <seastar/net/inet_address.hh>
#include <seastar/net/packet.hh>
#include <seastar/util/log.hh>

#include "ipv4_udp.hh"

namespace atsc3::gw {

static seastar::logger slog("sink");

namespace {

// ============================================================================
// Helpers — big-endian, UDP host resolution, gzip (LLS), CTP RTP (STLTP)
// ============================================================================
void put_u16_be(char* p, std::uint16_t v) noexcept {
    p[0] = static_cast<char>((v >> 8) & 0xFF);
    p[1] = static_cast<char>(v & 0xFF);
}

void put_u32_be(char* p, std::uint32_t v) noexcept {
    p[0] = static_cast<char>((v >> 24) & 0xFF);
    p[1] = static_cast<char>((v >> 16) & 0xFF);
    p[2] = static_cast<char>((v >> 8) & 0xFF);
    p[3] = static_cast<char>(v & 0xFF);
}

std::uint16_t parse_port(std::string_view sv) {
    if (sv.empty()) {
        throw std::runtime_error("sink: URI port is empty");
    }
    int v = 0;
    for (unsigned char c : sv) {
        if (c < '0' || c > '9') {
            throw std::runtime_error("sink: URI port must be decimal digits");
        }
        v = v * 10 + static_cast<int>(c - '0');
        if (v > 65535) {
            throw std::runtime_error("sink: URI port out of range");
        }
    }
    if (v == 0) {
        throw std::runtime_error("sink: URI port must be > 0");
    }
    return static_cast<std::uint16_t>(v);
}

void trim_sv(std::string_view& s) noexcept {
    while (!s.empty() &&
           std::isspace(static_cast<unsigned char>(s.front()))) {
        s.remove_prefix(1);
    }
    while (!s.empty() &&
           std::isspace(static_cast<unsigned char>(s.back()))) {
        s.remove_suffix(1);
    }
}

std::uint32_t parse_ipv4_dotted(std::string_view sv) {
    trim_sv(sv);
    if (sv.empty()) {
        throw std::runtime_error("sink: IPv4 address is empty");
    }
    std::string s(sv);
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (std::sscanf(s.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        throw std::runtime_error("sink: IPv4 address must be dotted quad a.b.c.d");
    }
    if (a > 255u || b > 255u || c > 255u || d > 255u) {
        throw std::runtime_error("sink: IPv4 octet out of range");
    }
    return atsc3::runtime::ipv4_quad(static_cast<std::uint8_t>(a),
                                       static_cast<std::uint8_t>(b),
                                       static_cast<std::uint8_t>(c),
                                       static_cast<std::uint8_t>(d));
}

std::uint8_t parse_u8_dec_or_hex(std::string_view v) {
    trim_sv(v);
    if (v.empty()) {
        throw std::runtime_error("sink: lls query value is empty");
    }
    int base = 10;
    if (v.size() >= 3 && v[0] == '0' && (v[1] == 'x' || v[1] == 'X')) {
        v.remove_prefix(2);
        base = 16;
    }
    unsigned int out = 0;
    const char* first = v.data();
    const char* last = v.data() + v.size();
    const auto res = std::from_chars(first, last, out, base);
    if (res.ec != std::errc{} || res.ptr != last || out > 255u) {
        throw std::runtime_error(
            "sink: lls query value must be 0..255 (decimal or 0x hex)");
    }
    return static_cast<std::uint8_t>(out);
}

seastar::future<seastar::socket_address> resolve_ipv4_host_port(
    std::string_view host, std::uint16_t port) {
    if (host.empty()) {
        throw std::runtime_error("sink: URI host is empty");
    }
    if (host.front() == '[') {
        throw std::runtime_error("sink: IPv6 host in URI not supported yet");
    }
    seastar::net::inet_address ia = co_await seastar::net::dns::resolve_name(
        seastar::sstring(host.data(), host.size()),
        seastar::net::inet_address::family::INET);
    co_return seastar::socket_address(ia, port);
}

constexpr bool is_gzip_magic(const char* p, std::size_t len) noexcept {
    return len >= 2u && static_cast<unsigned char>(p[0]) == 0x1Fu &&
           static_cast<unsigned char>(p[1]) == 0x8Bu;
}

bool is_lls_table_id(std::uint8_t id) noexcept {
    switch (id) {
    case 0x01:
    case 0x02:
    case 0x03:
    case 0x04:
    case 0x05:
    case 0xFE:
    case 0xFF:
        return true;
    default:
        return false;
    }
}

std::uint64_t fnv1a64_update(std::uint64_t h, const void* data, std::size_t len) noexcept {
    const auto* b = static_cast<const unsigned char*>(data);
    for (std::size_t i = 0; i < len; ++i) {
        h ^= b[i];
        h *= 1099511628211ull;
    }
    return h;
}

std::vector<unsigned char> gzip_compress_rfc1952(std::string_view in) {
    if (in.size() > static_cast<std::size_t>(std::numeric_limits<uInt>::max())) {
        throw std::runtime_error("sink: lls gzip input too large for zlib uInt");
    }
    z_stream zs{};
    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK) {
        throw std::runtime_error("sink: lls gzip deflateInit2 failed");
    }
    zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));
    zs.avail_in = static_cast<uInt>(in.size());

    std::vector<unsigned char> out;
    unsigned char chunk[16384];
    int zret = 0;
    do {
        zs.next_out = chunk;
        zs.avail_out = sizeof(chunk);
        zret = deflate(&zs, Z_FINISH);
        const std::size_t produced = sizeof(chunk) - zs.avail_out;
        if (produced != 0u) {
            out.insert(out.end(), chunk, chunk + produced);
        }
        if (zret == Z_STREAM_ERROR) {
            deflateEnd(&zs);
            throw std::runtime_error("sink: lls gzip Z_STREAM_ERROR");
        }
    } while (zret != Z_STREAM_END);
    deflateEnd(&zs);
    return out;
}

// A/324 §6 / Table 6.1 — CTP RTP fixed header for STLTP (PT=97), 12 bytes on the wire.
// Bytes 8–11 repurpose the RFC 3550 SSRC field (protocol_version, redundancy,
// number_of_channels, reserved, packet_offset) per the standard.
void write_ctp_rtp_stltp_header(char* p, std::uint16_t seq,
                              std::uint32_t timestamp_field,
                              std::uint16_t packet_offset) noexcept {
    p[0] = static_cast<char>(0x80);  // V=2, P=0, X=0, CC=0
    p[1] = static_cast<char>(0x80 | 97);  // M=1, PT=97 (STLTP)
    put_u16_be(p + 2, seq);
    put_u32_be(p + 4, timestamp_field);
    const std::uint32_t protocol_version = 1;  // '01'
    const std::uint32_t redundancy = 0;
    const std::uint32_t number_of_channels = 0;
    const std::uint32_t reserved10 = 0;
    const std::uint32_t w =
        (protocol_version << 30) | (redundancy << 28) |
        (number_of_channels << 26) | (reserved10 << 16) |
        (static_cast<std::uint32_t>(packet_offset) & 0xFFFFu);
    put_u32_be(p + 8, w);
}

// Lab-only inner layout after the CTP RTP header (not a full A/324 inner RTP stack).
// See docs/END_TO_END_GAPS.md — "minimal STLTP" bench hook.
constexpr std::size_t k_l1b_stub_bytes = 25;   // 200 bits — L1B size in A/322
constexpr std::size_t k_l1d_stub_bytes = 64;   // placeholder L1D var portion
constexpr std::size_t k_time_stub_bytes = 8;   // two u32 BE (counter + seq echo)
constexpr std::uint16_t k_lab_bbp_mux_type =
    0xA5A5;  // synthetic "BBP carries TLV-mux lab" type

constexpr std::size_t k_ctp_rtp_bytes = 12;
// Last +4 bytes: synthetic BBP mux_type (0xA5A5) + u16 BE TLV length — must
// match scripts/_stltp_lab_udp_to_tlvmux.py::_STLTP_LAB_OVERHEAD.
constexpr std::size_t k_stltp_overhead =
    k_ctp_rtp_bytes + k_l1b_stub_bytes + k_l1d_stub_bytes + k_time_stub_bytes + 4;
constexpr std::size_t k_max_stltp_datagram = 1400;  // stay under typical Ethernet MTU

// ============================================================================
// file:// — per-shard append-only file
// ============================================================================
class file_sink final : public sink {
public:
    explicit file_sink(seastar::output_stream<char> out, std::string path)
        : _out(std::move(out)), _path(std::move(path)) {}

    seastar::future<> write(seastar::temporary_buffer<char> buf) override {
        return _out.write(buf.get(), buf.size());
    }
    seastar::future<> flush() override { return _out.flush(); }
    seastar::future<> close() override { return _out.close(); }

    std::string describe() const override {
        return "file://" + _path;
    }

private:
    seastar::output_stream<char> _out;
    std::string _path;
};

seastar::future<std::unique_ptr<sink>> make_file_sink(std::string base_path) {
    auto shard_path =
        base_path + ".shard" + std::to_string(seastar::this_shard_id());

    seastar::open_flags flags =
        seastar::open_flags::wo |
        seastar::open_flags::create |
        seastar::open_flags::truncate;

    return seastar::open_file_dma(shard_path, flags)
        .then([shard_path](seastar::file f) {
            // 64 KiB buffer; tunable later for higher throughput sinks.
            auto out = seastar::make_file_output_stream(std::move(f), 64 * 1024)
                           .get();
            slog.info("shard {} sink: file://{}",
                      seastar::this_shard_id(), shard_path);
            return std::unique_ptr<sink>(
                new file_sink(std::move(out), shard_path));
        });
}

// ============================================================================
// ipv4udp-file:///path?src=&dst=&srcport=&dstport=[&ttl=] — append M8 wire
// ============================================================================
struct ipv4udp_file_qopts {
    std::optional<std::string_view> src;
    std::optional<std::string_view> dst;
    std::optional<std::string_view> srcport;
    std::optional<std::string_view> dstport;
    std::optional<std::string_view> ttl;
};

ipv4udp_file_qopts parse_ipv4udp_file_query(std::string_view query) {
    ipv4udp_file_qopts o;
    while (!query.empty()) {
        const std::size_t amp = query.find('&');
        const std::string_view pair = query.substr(0, amp);
        if (amp == std::string_view::npos) {
            query = "";
        } else {
            query.remove_prefix(amp + 1);
        }
        const std::size_t eq = pair.find('=');
        std::string_view key = pair.substr(0, eq);
        std::string_view val =
            (eq == std::string_view::npos) ? "" : pair.substr(eq + 1);
        trim_sv(key);
        trim_sv(val);
        if (key.empty()) {
            continue;
        }
        if (key == "src") {
            o.src = val;
        } else if (key == "dst") {
            o.dst = val;
        } else if (key == "srcport") {
            o.srcport = val;
        } else if (key == "dstport") {
            o.dstport = val;
        } else if (key == "ttl") {
            o.ttl = val;
        }
    }
    return o;
}

class ipv4udp_file_sink final : public sink {
public:
    ipv4udp_file_sink(seastar::output_stream<char> out, std::string path,
                      std::string describe_uri, atsc3::runtime::ipv4_addrs addrs,
                      std::uint16_t src_port, std::uint16_t dst_port, std::uint8_t ttl)
        : _out(std::move(out)),
          _path(std::move(path)),
          _describe_uri(std::move(describe_uri)),
          _addrs(addrs),
          _src_port(src_port),
          _dst_port(dst_port),
          _ttl(ttl) {}

    seastar::future<> write(seastar::temporary_buffer<char> tlv_mux) override {
        const auto pl = std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(tlv_mux.get()), tlv_mux.size());
        auto wire = atsc3::runtime::encapsulate_ipv4_udp(
            _addrs, _src_port, _dst_port, pl, _ttl, _ident++);
        if (wire.empty()) {
            return seastar::make_exception_future<>(
                std::runtime_error(
                    "sink: ipv4udp-file payload too large for encapsulate_ipv4_udp"));
        }
        return _out.write(reinterpret_cast<const char*>(wire.data()), wire.size());
    }
    seastar::future<> flush() override { return _out.flush(); }
    seastar::future<> close() override { return _out.close(); }
    std::string describe() const override { return _describe_uri; }

private:
    seastar::output_stream<char> _out;
    std::string _path;
    std::string _describe_uri;
    atsc3::runtime::ipv4_addrs _addrs;
    std::uint16_t _src_port;
    std::uint16_t _dst_port;
    std::uint8_t _ttl;
    std::uint16_t _ident = 0;
};

seastar::future<std::unique_ptr<sink>> make_ipv4udp_file_sink(std::string uri) {
    constexpr std::string_view kPref = "ipv4udp-file://";
    if (!std::string_view(uri).starts_with(kPref)) {
        throw std::runtime_error("sink: internal ipv4udp-file factory");
    }
    std::string_view u(uri);
    u.remove_prefix(kPref.size());
    const auto qm = u.find('?');
    if (qm == std::string_view::npos) {
        throw std::runtime_error(
            "sink: ipv4udp-file:// requires query "
            "?src=a.b.c.d&dst=e.f.g.h&srcport=N&dstport=M (optional &ttl=)");
    }
    std::string_view path_sv = u.substr(0, qm);
    const std::string_view query = u.substr(qm + 1);
    trim_sv(path_sv);
    if (path_sv.empty()) {
        throw std::runtime_error("sink: ipv4udp-file:// path is empty");
    }
    const ipv4udp_file_qopts qo = parse_ipv4udp_file_query(query);
    if (!qo.src || !qo.dst || !qo.srcport || !qo.dstport) {
        throw std::runtime_error(
            "sink: ipv4udp-file:// requires src,dst,srcport,dstport in query");
    }
    atsc3::runtime::ipv4_addrs addrs{};
    addrs.src = parse_ipv4_dotted(*qo.src);
    addrs.dst = parse_ipv4_dotted(*qo.dst);
    const std::uint16_t srcp = parse_port(*qo.srcport);
    const std::uint16_t dstp = parse_port(*qo.dstport);
    std::uint8_t ttl = 64;
    if (qo.ttl) {
        ttl = parse_u8_dec_or_hex(*qo.ttl);
    }

    std::string base_path(path_sv);
    const std::string shard_path =
        base_path + ".shard" + std::to_string(seastar::this_shard_id());

    seastar::open_flags flags = seastar::open_flags::wo | seastar::open_flags::create |
                                seastar::open_flags::truncate;
    seastar::file f = co_await seastar::open_file_dma(shard_path, flags);
    auto out = seastar::make_file_output_stream(std::move(f), 64 * 1024).get();
    slog.info("shard {} sink: ipv4udp-file -> {}",
              seastar::this_shard_id(), shard_path);
    co_return std::unique_ptr<sink>(new ipv4udp_file_sink(
        std::move(out), std::move(shard_path), std::move(uri), addrs, srcp, dstp, ttl));
}

// ============================================================================
// stdout:// — write to fd 1
// NOTE: ::write blocks the reactor; acceptable for dev/demo workloads, not
// production. Replaced in a later cut with a proper Seastar output_stream
// over fd 1, or just removed once a real sink (DPDK) lands.
// ============================================================================
class stdout_sink final : public sink {
public:
    seastar::future<> write(seastar::temporary_buffer<char> buf) override {
        const char *p = buf.get();
        size_t left = buf.size();
        while (left > 0) {
            auto n = ::write(STDOUT_FILENO, p, left);
            if (n < 0) {
                if (errno == EINTR) continue;
                return seastar::make_exception_future<>(
                    std::system_error(errno, std::system_category(),
                                      "stdout_sink write"));
            }
            p += n;
            left -= static_cast<size_t>(n);
        }
        return seastar::make_ready_future<>();
    }
    seastar::future<> flush() override { return seastar::make_ready_future<>(); }
    seastar::future<> close() override { return seastar::make_ready_future<>(); }
    std::string describe() const override { return "stdout://"; }
};

// ============================================================================
// null:// — discard all writes; tracks bytes for stats only.
// Use for throughput soaks where the sink would otherwise be the bottleneck
// (or fill the disk).
// ============================================================================
class null_sink final : public sink {
public:
    seastar::future<> write(seastar::temporary_buffer<char> buf) override {
        _bytes += buf.size();
        return seastar::make_ready_future<>();
    }
    seastar::future<> flush() override { return seastar::make_ready_future<>(); }
    seastar::future<> close() override {
        slog.info("shard {} null sink discarded {} bytes",
                  seastar::this_shard_id(), _bytes);
        return seastar::make_ready_future<>();
    }
    std::string describe() const override { return "null://"; }

private:
    std::uint64_t _bytes = 0;
};

// ============================================================================
// udp://host:port — TLV-mux as UDP payload (kernel adds IPv4/UDP headers)
// ============================================================================
constexpr std::size_t k_max_udp_plain_payload = 1400;

class udp_sink final : public sink {
public:
    udp_sink(seastar::net::datagram_channel chan, seastar::socket_address dest,
             std::string describe_uri)
        : _chan(std::move(chan)),
          _dest(dest),
          _describe_uri(std::move(describe_uri)) {}

    seastar::future<> write(seastar::temporary_buffer<char> tlv_mux) override {
        const std::size_t n = tlv_mux.size();
        if (n > k_max_udp_plain_payload) {
            return seastar::make_exception_future<>(
                std::runtime_error(
                    "sink: udp TLV-mux exceeds MTU guard (shrink payload or raise "
                    "k_max_udp_plain_payload)"));
        }
        return _chan.send(_dest, seastar::net::packet(std::move(tlv_mux)));
    }

    seastar::future<> flush() override { return seastar::make_ready_future<>(); }

    seastar::future<> close() override {
        if (!_chan.is_closed()) {
            _chan.shutdown_output();
            _chan.shutdown_input();
            _chan.close();
        }
        return seastar::make_ready_future<>();
    }

    std::string describe() const override { return _describe_uri; }

private:
    seastar::net::datagram_channel _chan;
    seastar::socket_address _dest;
    std::string _describe_uri;
};

seastar::future<std::unique_ptr<sink>> make_udp_sink(std::string uri) {
    constexpr std::string_view kPrefix = "udp://";
    if (!std::string_view(uri).starts_with(kPrefix)) {
        throw std::runtime_error("sink: internal udp factory");
    }
    std::string_view rest(uri);
    rest.remove_prefix(kPrefix.size());
    const auto colon = rest.rfind(':');
    if (colon == std::string_view::npos || colon + 1 >= rest.size()) {
        throw std::runtime_error(
            "sink: udp:// requires host:port (e.g. udp://192.168.1.10:5000)");
    }
    const std::uint16_t port = parse_port(rest.substr(colon + 1));
    const std::string_view host = rest.substr(0, colon);

    seastar::socket_address dest =
        co_await resolve_ipv4_host_port(host, port);
    seastar::net::datagram_channel chan =
        seastar::make_unbound_datagram_channel(AF_INET);

    slog.info("shard {} sink: {} -> {}",
              seastar::this_shard_id(), uri, dest);

    co_return std::unique_ptr<sink>(
        new udp_sink(std::move(chan), dest, std::move(uri)));
}

// ============================================================================
// stltp://host:port — UDP toward exciter (lab / bench; not conformance-tested)
// ============================================================================
class stltp_sink final : public sink {
public:
    stltp_sink(seastar::net::datagram_channel chan, seastar::socket_address dest,
               std::string describe_uri)
        : _chan(std::move(chan)),
          _dest(dest),
          _describe_uri(std::move(describe_uri)) {}

    seastar::future<> write(seastar::temporary_buffer<char> tlv_mux) override {
        const std::size_t tlv_n = tlv_mux.size();
        if (tlv_n > 65535u) {
            return seastar::make_exception_future<>(
                std::runtime_error("sink: stltp TLV-mux larger than 16-bit length"));
        }
        const std::size_t total = k_stltp_overhead + tlv_n;
        if (total > k_max_stltp_datagram) {
            return seastar::make_exception_future<>(
                std::runtime_error("sink: stltp datagram would exceed MTU guard "
                                   "(shrink payload or raise k_max_stltp_datagram)"));
        }

        seastar::temporary_buffer<char> wire(total);
        char* w = wire.get_write();
        const std::uint16_t seq = ++_rtp_seq;
        const std::uint32_t ts = ++_rtp_ts_field;
        write_ctp_rtp_stltp_header(w, seq, ts, 0);
        w += k_ctp_rtp_bytes;
        std::memset(w, 0, k_l1b_stub_bytes + k_l1d_stub_bytes);
        w += k_l1b_stub_bytes + k_l1d_stub_bytes;
        put_u32_be(w, ts);
        put_u32_be(w + 4, static_cast<std::uint32_t>(seq));
        w += k_time_stub_bytes;
        put_u16_be(w, k_lab_bbp_mux_type);
        put_u16_be(w + 2, static_cast<std::uint16_t>(tlv_n));
        w += 4;
        if (tlv_n != 0u) {
            std::memcpy(w, tlv_mux.get(), tlv_n);
        }

        return _chan.send(_dest, seastar::net::packet(std::move(wire)));
    }

    seastar::future<> flush() override { return seastar::make_ready_future<>(); }

    seastar::future<> close() override {
        if (!_chan.is_closed()) {
            _chan.shutdown_output();
            _chan.shutdown_input();
            _chan.close();
        }
        return seastar::make_ready_future<>();
    }

    std::string describe() const override { return _describe_uri; }

private:
    seastar::net::datagram_channel _chan;
    seastar::socket_address _dest;
    std::string _describe_uri;
    std::uint16_t _rtp_seq = 0;
    std::uint32_t _rtp_ts_field = 0;
};

seastar::future<std::unique_ptr<sink>> make_stltp_sink(std::string uri) {
    constexpr std::string_view kPrefix = "stltp://";
    if (!std::string_view(uri).starts_with(kPrefix)) {
        throw std::runtime_error("sink: internal stltp factory");
    }
    std::string_view rest(uri);
    rest.remove_prefix(kPrefix.size());
    const auto colon = rest.rfind(':');
    if (colon == std::string_view::npos || colon + 1 >= rest.size()) {
        throw std::runtime_error("sink: stltp:// requires host:port "
                                 "(e.g. stltp://192.168.1.10:30000)");
    }
    const std::uint16_t port = parse_port(rest.substr(colon + 1));
    const std::string_view host = rest.substr(0, colon);

    seastar::socket_address dest =
        co_await resolve_ipv4_host_port(host, port);
    seastar::net::datagram_channel chan =
        seastar::make_unbound_datagram_channel(AF_INET);

    slog.info("shard {} sink: {} -> {}",
              seastar::this_shard_id(), uri, dest);

    co_return std::unique_ptr<sink>(
        new stltp_sink(std::move(chan), dest, std::move(uri)));
}

struct lls_query_opts {
    std::optional<std::uint8_t> table_id;
    std::optional<std::uint8_t> group_id;
    std::optional<std::uint8_t> group_count_minus1;
};

lls_query_opts parse_lls_query(std::string_view query) {
    lls_query_opts o;
    while (!query.empty()) {
        const std::size_t amp = query.find('&');
        const std::string_view pair = query.substr(0, amp);
        if (amp == std::string_view::npos) {
            query = "";
        } else {
            query.remove_prefix(amp + 1);
        }
        const std::size_t eq = pair.find('=');
        std::string_view key = pair.substr(0, eq);
        std::string_view val =
            (eq == std::string_view::npos) ? "" : pair.substr(eq + 1);
        trim_sv(key);
        trim_sv(val);
        if (key.empty()) {
            continue;
        }
        if (key == "table") {
            o.table_id = parse_u8_dec_or_hex(val);
        } else if (key == "group") {
            o.group_id = parse_u8_dec_or_hex(val);
        } else if (key == "gcm1" || key == "groups") {
            o.group_count_minus1 = parse_u8_dec_or_hex(val);
        }
    }
    return o;
}

constexpr std::size_t k_max_lls_udp_payload = 65400;

// A/331 Table 6.1 — first four bytes of every LLS UDP payload, followed by
// gzip-compressed XML for the table type identified by LLS_table_id.
class lls_sink final : public sink {
public:
    lls_sink(seastar::net::datagram_channel chan, seastar::socket_address dest,
             std::string describe_uri, std::uint8_t table_id,
             std::uint8_t group_id, std::uint8_t group_count_minus1)
        : _chan(std::move(chan)),
          _dest(dest),
          _describe_uri(std::move(describe_uri)),
          _table_id(table_id),
          _group_id(group_id),
          _group_count_minus1(group_count_minus1) {}

    seastar::future<> write(seastar::temporary_buffer<char> buf) override {
        const char* p = buf.get();
        const std::size_t n = buf.size();

        std::vector<unsigned char> wire;

        if (n >= 6u && is_gzip_magic(p + 4, n - 4u) &&
            is_lls_table_id(static_cast<unsigned char>(p[0]))) {
            wire.assign(p, p + n);
        } else if (n >= 2u && is_gzip_magic(p, n)) {
            const std::uint64_t fp =
                fnv1a64_update(14695981039346656037ull, p, n);
            bump_version_if_changed(fp);
            wire.reserve(4 + n);
            wire.push_back(_table_id);
            wire.push_back(_group_id);
            wire.push_back(_group_count_minus1);
            wire.push_back(_lls_table_version);
            wire.insert(wire.end(), p, p + n);
        } else {
            const std::uint64_t fp =
                fnv1a64_update(14695981039346656037ull, p, n);
            bump_version_if_changed(fp);
            const auto gz = gzip_compress_rfc1952(std::string_view(p, n));
            wire.reserve(4 + gz.size());
            wire.push_back(_table_id);
            wire.push_back(_group_id);
            wire.push_back(_group_count_minus1);
            wire.push_back(_lls_table_version);
            wire.insert(wire.end(), gz.begin(), gz.end());
        }

        if (wire.size() > k_max_lls_udp_payload) {
            return seastar::make_exception_future<>(
                std::runtime_error("sink: lls wire size exceeds UDP guard"));
        }

        seastar::temporary_buffer<char> tb(wire.size());
        std::memcpy(tb.get_write(), wire.data(), wire.size());
        return _chan.send(_dest, seastar::net::packet(std::move(tb)));
    }

    seastar::future<> flush() override { return seastar::make_ready_future<>(); }

    seastar::future<> close() override {
        if (!_chan.is_closed()) {
            _chan.shutdown_output();
            _chan.shutdown_input();
            _chan.close();
        }
        return seastar::make_ready_future<>();
    }

    std::string describe() const override { return _describe_uri; }

private:
    void bump_version_if_changed(std::uint64_t fp) noexcept {
        if (!_have_fp) {
            _have_fp = true;
            _last_fp = fp;
            return;
        }
        if (fp != _last_fp) {
            _last_fp = fp;
            _lls_table_version =
                static_cast<std::uint8_t>(_lls_table_version + 1u);
        }
    }

    seastar::net::datagram_channel _chan;
    seastar::socket_address _dest;
    std::string _describe_uri;
    const std::uint8_t _table_id;
    const std::uint8_t _group_id;
    const std::uint8_t _group_count_minus1;
    std::uint8_t _lls_table_version = 0;
    bool _have_fp = false;
    std::uint64_t _last_fp = 0;
};

seastar::future<std::unique_ptr<sink>> make_lls_sink(std::string uri) {
    constexpr std::string_view kPrefix = "lls://";
    if (!std::string_view(uri).starts_with(kPrefix)) {
        throw std::runtime_error("sink: internal lls factory");
    }
    std::string_view tail(uri);
    tail.remove_prefix(kPrefix.size());
    const std::size_t qmark = tail.find('?');
    std::string_view hostport = tail.substr(0, qmark);
    const std::string_view query =
        (qmark == std::string_view::npos) ? "" : tail.substr(qmark + 1);
    trim_sv(hostport);

    const lls_query_opts qopts = parse_lls_query(query);

    seastar::socket_address dest;
    if (hostport.empty()) {
        dest = seastar::socket_address(
            seastar::net::inet_address("224.0.23.60"), 4937);
    } else {
        const auto colon = hostport.rfind(':');
        if (colon == std::string_view::npos || colon + 1 >= hostport.size()) {
            throw std::runtime_error(
                "sink: lls:// with host requires host:port "
                "(or use lls:// for 224.0.23.60:4937; use lls://?table=… for defaults + query)");
        }
        const std::uint16_t port = parse_port(hostport.substr(colon + 1));
        const std::string_view host = hostport.substr(0, colon);
        dest = co_await resolve_ipv4_host_port(host, port);
    }

    seastar::net::datagram_channel chan =
        seastar::make_unbound_datagram_channel(AF_INET);

    const std::uint8_t table_id = qopts.table_id.value_or(0x01);
    const std::uint8_t group_id = qopts.group_id.value_or(0x01);
    const std::uint8_t group_count_minus1 =
        qopts.group_count_minus1.value_or(0x00);
    if (!is_lls_table_id(table_id)) {
        throw std::runtime_error(
            "sink: lls ?table= must be 1,2,3,4,5,254(0xFE),255(0xFF) per A/331 Table 6.1");
    }

    slog.info(
        "shard {} sink: {} -> {} (LLS_table_id={:02x} group={:02x} "
        "group_count_minus1={:02x})",
        seastar::this_shard_id(), uri, dest,
        static_cast<unsigned>(table_id), static_cast<unsigned>(group_id),
        static_cast<unsigned>(group_count_minus1));

    co_return std::unique_ptr<sink>(new lls_sink(
        std::move(chan), dest, std::move(uri), table_id, group_id,
        group_count_minus1));
}

}  // namespace

seastar::future<std::unique_ptr<sink>> make_sink(std::string_view uri) {
    constexpr std::string_view kFile   = "file://";
    constexpr std::string_view kStdout = "stdout://";
    constexpr std::string_view kNull   = "null://";
    constexpr std::string_view kStltp  = "stltp://";
    constexpr std::string_view kLls    = "lls://";
    constexpr std::string_view kUdp    = "udp://";
    constexpr std::string_view kIpv4UdpFile = "ipv4udp-file://";

    if (uri.starts_with(kStdout)) {
        return seastar::make_ready_future<std::unique_ptr<sink>>(
            std::make_unique<stdout_sink>());
    }
    if (uri.starts_with(kNull)) {
        return seastar::make_ready_future<std::unique_ptr<sink>>(
            std::make_unique<null_sink>());
    }
    if (uri.starts_with(kStltp)) {
        return make_stltp_sink(std::string(uri));
    }
    if (uri.starts_with(kLls)) {
        return make_lls_sink(std::string(uri));
    }
    if (uri.starts_with(kUdp)) {
        return make_udp_sink(std::string(uri));
    }
    if (uri.starts_with(kIpv4UdpFile)) {
        return make_ipv4udp_file_sink(std::string(uri));
    }
    if (uri.starts_with(kFile)) {
        std::string path(uri.substr(kFile.size()));
        if (path.empty()) {
            return seastar::make_exception_future<std::unique_ptr<sink>>(
                std::runtime_error("sink: file:// requires a path"));
        }
        return make_file_sink(std::move(path));
    }
    return seastar::make_exception_future<std::unique_ptr<sink>>(
        std::runtime_error("sink: unsupported URI scheme: " + std::string(uri)));
}

}  // namespace atsc3::gw

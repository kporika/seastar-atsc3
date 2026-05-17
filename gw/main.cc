// SPDX-License-Identifier: Apache-2.0
//
// atsc3_gw entry point. Parses CLI, builds a sharded<gw_server>, and runs
// until SIGINT/SIGTERM.

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <cctype>
#include <limits>
#include <cstdint>

#include <boost/program_options.hpp>

#include <seastar/core/app-template.hh>
#include <seastar/core/distributed.hh>
#include <seastar/core/future.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/signal.hh>
#include <seastar/core/sleep.hh>
#include <seastar/http/httpd.hh>
#include <seastar/net/tls.hh>
#include <seastar/net/socket_defs.hh>
#include <seastar/util/later.hh>
#include <seastar/util/log.hh>

#include "admin_http.h"
#include "atsc3_gw.h"
#include "encoder_pipeline.h"
#include "mmtp_payload_gfd_header_decoder.h"
#include "mmtp_payload_isobmff_prefix_decoder.h"

namespace bpo = boost::program_options;

namespace {

int hex_digit_value(char c) noexcept {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

bool parse_even_hex_bytes(const std::string& in, std::vector<std::byte>* out) {
    out->clear();
    std::string_view sv(in);
    while (!sv.empty() &&
           std::isspace(static_cast<unsigned char>(sv.front()))) {
        sv.remove_prefix(1);
    }
    if (sv.size() >= 2 && sv[0] == '0' &&
        (sv[1] == 'x' || sv[1] == 'X')) {
        sv.remove_prefix(2);
    }
    if ((sv.size() % 2u) != 0u) {
        return false;
    }
    for (std::size_t i = 0; i < sv.size(); i += 2) {
        const int hi = hex_digit_value(sv[i]);
        const int lo = hex_digit_value(sv[i + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out->push_back(static_cast<std::byte>((hi << 4) | lo));
    }
    return true;
}

bool parse_mmtp_extension_spec(const std::string& spec,
                               std::uint16_t* out_type,
                               std::vector<std::byte>* out_val) {
    const auto colon = spec.find(':');
    if (colon == std::string::npos) {
        return false;
    }
    try {
        const unsigned long ty =
            std::stoul(spec.substr(0, colon), nullptr, 0);
        if (ty > 65535ul) {
            return false;
        }
        *out_type = static_cast<std::uint16_t>(ty);
    } catch (...) {
        return false;
    }
    std::string hex = spec.substr(colon + 1);
    while (!hex.empty() &&
           std::isspace(static_cast<unsigned char>(hex.front()))) {
        hex.erase(hex.begin());
    }
    while (!hex.empty() &&
           std::isspace(static_cast<unsigned char>(hex.back()))) {
        hex.pop_back();
    }
    return parse_even_hex_bytes(hex, out_val);
}

bool parse_mmtp_si_pa_table_row(
    const std::string& tok,
    atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row* out) {
    const auto c1 = tok.find(':');
    if (c1 == std::string::npos) {
        return false;
    }
    const auto c2 = tok.find(':', c1 + 1);
    if (c2 == std::string::npos) {
        return false;
    }
    if (tok.find(':', c2 + 1) != std::string::npos) {
        return false;
    }
    const std::string a = tok.substr(0, c1);
    const std::string b = tok.substr(c1 + 1, c2 - c1 - 1);
    const std::string c = tok.substr(c2 + 1);
    if (a.empty() || b.empty() || c.empty()) {
        return false;
    }
    char* e = nullptr;
    const unsigned long v1 = std::strtoul(a.c_str(), &e, 0);
    if (e != a.c_str() + a.size() || v1 > 255ul) {
        return false;
    }
    const unsigned long v2 = std::strtoul(b.c_str(), &e, 0);
    if (e != b.c_str() + b.size() || v2 > 255ul) {
        return false;
    }
    const unsigned long v3 = std::strtoul(c.c_str(), &e, 0);
    if (e != c.c_str() + c.size() || v3 > 65535ul) {
        return false;
    }
    out->table_id      = static_cast<std::uint8_t>(v1);
    out->table_version = static_cast<std::uint8_t>(v2);
    out->table_length  = static_cast<std::uint16_t>(v3);
    return true;
}

}  // namespace

static seastar::logger mlog("main");

int main(int argc, char** argv) {
    seastar::app_template app;
    app.add_options()
        ("ingress",
         bpo::value<std::string>()->default_value("0.0.0.0:9000"),
         "ingress TCP bind address (host:port)")
        ("sink",
         bpo::value<std::string>()->default_value("stdout://"),
         "output sink URI (file:///…, stdout://, null://, udp://host:port, "
         "stltp://host:port, lls://[host:port][?table=&group=&gcm1=], "
         "ipv4udp-file:///path?src=&dst=&srcport=&dstport=[&ttl=])")
        ("admin-http",
         bpo::value<std::string>()->default_value(""),
         "optional HTTP/HTTPS admin bind host:port: / /healthz /readyz /metrics /config, "
         "PATCH+PUT /config POST /config/sink, GET+POST+PATCH+DELETE /services, POST /ingest "
         "(empty disables)")
        ("services-state-file",
         bpo::value<std::string>()->default_value(""),
         "optional JSON file for /services registry (shard 0); load at start, save on POST/PATCH/DELETE "
         "(schema_version 2; empty disables)")
        ("admin-bearer-token",
         bpo::value<std::string>()->default_value(""),
         "optional shared secret: require Authorization: Bearer <token> on mutating admin routes "
         "(POST/PATCH/PUT/DELETE; empty disables)")
        ("admin-tls-cert",
         bpo::value<std::string>()->default_value(""),
         "PEM certificate for HTTPS admin (requires --admin-tls-key; empty = plain HTTP)")
        ("admin-tls-key",
         bpo::value<std::string>()->default_value(""),
         "PEM private key for HTTPS admin (requires --admin-tls-cert)")
        ("prepend-lct-word0",
         bpo::bool_switch()->default_value(false),
         "M8 lab: prepend RFC 5651 LCT header word-0 before ALP (header_length_words=1;"
         " see protocol/lct_rfc5651_word0.yaml minimal_v1_c0)")
        ("lct-codepoint",
         bpo::value<unsigned>()->default_value(0),
         "when --prepend-lct-word0: LCT codepoint octet (0-255)")
        ("lct-include-tsi",
         bpo::bool_switch()->default_value(false),
         "when --prepend-lct-word0: append 32-bit big-endian RFC 5651 TSI after "
         "word‑0 (--lct-tsi); with --lct-include-toi, TSI precedes TOI "
         "(header_length_words=3)")
        ("lct-tsi",
         bpo::value<std::uint32_t>()->default_value(0),
         "when --prepend-lct-word0 and --lct-include-tsi: Transport Session Id")
        ("lct-include-toi",
         bpo::bool_switch()->default_value(false),
         "when --prepend-lct-word0: append 32-bit BE TOI per RFC 5651 O=1 "
         "(header_length_words=2 alone, or =3 combined with --lct-include-tsi)")
        ("lct-toi",
         bpo::value<std::uint32_t>()->default_value(0),
         "when --prepend-lct-word0 and --lct-include-toi: Transport Object Id")
        ("alp-payload-config",
         bpo::bool_switch()->default_value(false),
         "set ATSC A/330 ALP base header payload_configuration (pc); lab path still "
         "emits only the 16-bit base header + opaque body (no segmentation TLVs)")
        ("alp-header-mode",
         bpo::bool_switch()->default_value(false),
         "set ATSC A/330 ALP base header header_mode (hm); lab path still omits "
         "additional-header octets beyond the 16-bit base")
        ("prepend-mmtp-word0",
         bpo::bool_switch()->default_value(false),
         "M8 lab: prepend ISO/IEC 23008-1 MMTP packet header word-0 before ALP "
         "(before optional --prepend-lct-word0; see protocol/mmtp_header_word0.yaml)")
        ("mmtp-payload-type",
         bpo::value<unsigned>()->default_value(2),
         "when --prepend-mmtp-word0: MMTP payload_type field (0-63)")
        ("mmtp-packet-id",
         bpo::value<unsigned>()->default_value(1),
         "when --prepend-mmtp-word0: MMTP packet_id (0-65535)")
        ("prepend-mmtp-ts-psn",
         bpo::bool_switch()->default_value(false),
         "when --prepend-mmtp-word0: also prepend MMTP timestamp + "
         "packet_sequence_number (64b BE; protocol/mmtp_header_ts_psn.yaml)")
        ("mmtp-timestamp",
         bpo::value<std::uint32_t>()->default_value(0),
         "when --prepend-mmtp-ts-psn: 32-bit timestamp (big-endian on wire)")
        ("mmtp-psn",
         bpo::value<std::uint32_t>()->default_value(0),
         "when --prepend-mmtp-ts-psn: 32-bit packet_sequence_number (BE)")
        ("prepend-mmtp-packet-counter",
         bpo::bool_switch()->default_value(false),
         "when --prepend-mmtp-ts-psn: also prepend 32-bit MMTP packet_counter "
         "(protocol/mmtp_header_counter32.yaml; sets C=1 in word-0)")
        ("mmtp-packet-counter",
         bpo::value<std::uint32_t>()->default_value(0),
         "when --prepend-mmtp-packet-counter: packet_counter value (BE on wire)")
        ("prepend-mmtp-extension",
         bpo::bool_switch()->default_value(false),
         "when --prepend-mmtp-word0: append one or more MMTP header extension TLVs "
         "(protocol/mmtp_header_extension.yaml) after optional ts_psn and "
         "optional packet_counter; use --mmtp-extension TYPE:HEX for a chain, "
         "or legacy --mmtp-extension-type/--mmtp-extension-hex for a single TLV")
        ("mmtp-extension-type",
         bpo::value<unsigned>()->default_value(1),
         "when --prepend-mmtp-extension without --mmtp-extension: 16-bit extension_type (0-65535)")
        ("mmtp-extension-hex",
         bpo::value<std::string>()->default_value(""),
         "when --prepend-mmtp-extension without --mmtp-extension: even-length hex for extension payload "
         "octets only (length field is implicit; empty = zero-length value)")
        ("mmtp-extension",
         bpo::value<std::vector<std::string>>()->multitoken(),
         "when --prepend-mmtp-extension: chained TYPE:HEX extension TLVs "
         "(type decimal or 0x hex; hex may be empty after colon for length 0); "
         "repeat flag or pass multiple tokens after one flag; if omitted, "
         "--mmtp-extension-type/--mmtp-extension-hex build one TLV")
        ("prepend-mmtp-signalling-prefix",
         bpo::bool_switch()->default_value(false),
         "when --prepend-mmtp-word0: prepend MMTP signalling payload header "
         "(first 16 bits per ISO/IEC 23008-1 9.3.4; protocol/"
         "mmtp_payload_signalling_prefix.yaml) after optional ts_psn, "
         "packet_counter, extension")
        ("mmtp-signalling-fragmentation",
         bpo::value<unsigned>()->default_value(0),
         "when --prepend-mmtp-signalling-prefix: fragmentation_indicator (0-3)")
        ("mmtp-signalling-reserved",
         bpo::value<unsigned>()->default_value(0),
         "when --prepend-mmtp-signalling-prefix: reserved 4-bit field (0-15)")
        ("mmtp-signalling-length-extension",
         bpo::bool_switch()->default_value(false),
         "when --prepend-mmtp-signalling-prefix: set length_extension_flag")
        ("mmtp-signalling-aggregation",
         bpo::bool_switch()->default_value(false),
         "when --prepend-mmtp-signalling-prefix: set aggregation_flag")
        ("mmtp-signalling-fragment-counter",
         bpo::value<unsigned>()->default_value(0),
         "when --prepend-mmtp-signalling-prefix: fragment_counter (0-255)")
        ("mmtp-signalling-aggregate-hex",
         bpo::value<std::vector<std::string>>()->multitoken(),
         "when --prepend-mmtp-signalling-prefix with --mmtp-signalling-aggregation: "
         "even-length hex for each aggregated message body (length prefix on wire "
         "= octet count; 16- or 32-bit BE per --mmtp-signalling-length-extension)")
        ("prepend-mmt-si-length32-envelope",
         bpo::bool_switch()->default_value(false),
         "when --prepend-mmtp-signalling-prefix (aggregation off): prepend "
         "mmt_si_length32_envelope (BE32 ingress length + ingress) per "
         "protocol/mmt_si_length32_envelope.yaml; requires --mmtp-payload-type 2")
        ("prepend-mmt-si-descriptor-loop-u32",
         bpo::bool_switch()->default_value(false),
         "when --prepend-mmtp-signalling-prefix (aggregation off): prepend "
         "mmt_si_descriptor_loop_u32 (BE32 + ingress as mmtp_desc bytes) per "
         "protocol/mmt_si_descriptor_loop_u32.yaml; requires --mmtp-payload-type 2")
        ("prepend-mmt-si-message-header-len32",
         bpo::bool_switch()->default_value(false),
         "when --prepend-mmtp-signalling-prefix (aggregation off): prepend "
         "mmt_si_message_header_len32 (message_id + message_version + BE32 "
         "message_byte_length + SI tail) per protocol/mmt_si_message_header_len32.yaml; "
         "SI tail is optional mmt_si_pa_table_headers, optional mmt_si_descriptor_loop_u32, "
         "and/or mmt_si_length32_envelope over ingress; requires --mmtp-payload-type 2")
        ("mmtp-si-message-id",
         bpo::value<unsigned>()->default_value(0),
         "when --prepend-mmt-si-message-header-len32: 16-bit message_id (0=PA, 1..0xF=MPI, "
         "0x10..0x1F=MPT per ISO/IEC 23008-1 §10.3 lab mapping)")
        ("mmtp-si-message-version",
         bpo::value<unsigned>()->default_value(0),
         "when --prepend-mmt-si-message-header-len32: 8-bit message_version (0-255)")
        ("prepend-mmt-si-pa-table-headers",
         bpo::bool_switch()->default_value(false),
         "when --prepend-mmtp-signalling-prefix (aggregation off): prepend "
         "mmt_si_pa_table_headers (PA §10.3 table index + 4B header rows) per "
         "protocol/mmt_si_pa_table_headers.yaml before optional descriptor loop / "
         "§10.2 envelope; requires --prepend-mmt-si-message-header-len32 and "
         "--mmtp-si-message-id 0; requires --mmtp-payload-type 2")
        ("mmtp-si-pa-table-row",
         bpo::value<std::vector<std::string>>()->multitoken(),
         "when --prepend-mmt-si-pa-table-headers: one or more ID:VERSION:LENGTH "
         "rows (strtoul fields, e.g. 32:1:0 or 32:1:4); wire order = token order; "
         "with one row and LENGTH>0, each payload must be LENGTH octets (table body); "
         "with multiple rows all LENGTH>0, payload is bodies concatenated in token order; "
         "with mixed LENGTH 0 and >0, payload is bodies then optional SI tail")
        ("validate-mmt-si-mpt-table-body",
         bpo::bool_switch()->default_value(false),
         "ingress must decode as mmt_si_mpt_table (table_id 0x20) per "
         "protocol/mmt_si_mpt_table.yaml")
        ("validate-mmt-si-plt-table-body",
         bpo::bool_switch()->default_value(false),
         "ingress must decode as mmt_si_plt_table (table_id 0x80) per "
         "protocol/mmt_si_plt_table.yaml")
        ("validate-mmt-si-mpt-table-body-prefix",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-mpt-table-body; mmt_si_mpt_table table_length "
         "region must decode as mmt_si_mpt_table_body_prefix (minimal lab: length 5)")
        ("validate-mmt-si-mpt-asset",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-mpt-table-body; MPT body must decode as "
         "mmt_si_mpt_table_body_prefix + mmt_si_mpt_asset (ZK lab: table_length 19)")
        ("validate-mmt-si-mpt-asset-id8",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-mpt-table-body; MPT body must decode as "
         "mmt_si_mpt_table_body_prefix + mmt_si_mpt_asset_id8 (ZS lab: table_length 20)")
        ("validate-mmt-si-mpt-asset-id16",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-mpt-table-body; MPT body must decode as "
         "mmt_si_mpt_table_body_prefix + mmt_si_mpt_asset_id16 (AAG lab: table_length 21)")
        ("validate-mmt-si-mpt-asset-location0",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-mpt-table-body; MPT body must decode as "
         "mmt_si_mpt_table_body_prefix + mmt_si_mpt_asset_location0 (ZT lab: table_length 22)")
        ("validate-mmt-si-mpt-asset-location-ipv4",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-mpt-table-body; MPT body must decode as "
         "mmt_si_mpt_table_body_prefix + mmt_si_mpt_asset_location_ipv4 (ZV lab: table_length 30)")
        ("validate-mmt-si-mpt-asset-location-ipv4-nz",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-mpt-table-body; MPT body must decode as "
         "mmt_si_mpt_table_body_prefix + mmt_si_mpt_asset_location_ipv4_nz (AAF lab: table_length 30)")
        ("validate-mmt-si-mpt-asset-location-ipv6",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-mpt-table-body; MPT body must decode as "
         "mmt_si_mpt_table_body_prefix + mmt_si_mpt_asset_location_ipv6 (ZY lab: table_length 54)")
        ("validate-mmt-si-mpt-asset-location-ipv6-nz",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-mpt-table-body; MPT body must decode as "
         "mmt_si_mpt_table_body_prefix + mmt_si_mpt_asset_location_ipv6_nz (AAH lab: table_length 54)")
        ("validate-mmt-si-mpt-asset-id8-location-ipv4",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-mpt-table-body; MPT body must decode as "
         "mmt_si_mpt_table_body_prefix + mmt_si_mpt_asset_id8_location_ipv4 (ZW lab: table_length 31)")
        ("validate-mmt-si-mpt-asset-id8-location-ipv4-nz",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-mpt-table-body; MPT body must decode as "
         "mmt_si_mpt_table_body_prefix + mmt_si_mpt_asset_id8_location_ipv4_nz (AAM lab: table_length 31)")
        ("validate-mmt-si-mpt-asset-id8-location-ipv6",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-mpt-table-body; MPT body must decode as "
         "mmt_si_mpt_table_body_prefix + mmt_si_mpt_asset_id8_location_ipv6 (AAA lab: table_length 55)")
        ("validate-mmt-si-mpt-asset-id8-location-ipv6-nz",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-mpt-table-body; MPT body must decode as "
         "mmt_si_mpt_table_body_prefix + mmt_si_mpt_asset_id8_location_ipv6_nz (AAN lab: table_length 55)")
        ("validate-mmt-si-mpt-asset-id16-location-ipv4",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-mpt-table-body; MPT body must decode as "
         "mmt_si_mpt_table_body_prefix + mmt_si_mpt_asset_id16_location_ipv4 (AAO lab: table_length 32)")
        ("validate-mmt-si-mpt-asset-id16-location-ipv4-nz",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-mpt-table-body; MPT body must decode as "
         "mmt_si_mpt_table_body_prefix + mmt_si_mpt_asset_id16_location_ipv4_nz (AAP lab: table_length 32)")
        ("validate-mmt-si-mpt-asset-id16-location-ipv6",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-mpt-table-body; MPT body must decode as "
         "mmt_si_mpt_table_body_prefix + mmt_si_mpt_asset_id16_location_ipv6 (AAQ lab: table_length 55)")
        ("validate-mmt-si-mpt-asset-id16-location-ipv6-nz",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-mpt-table-body; MPT body must decode as "
         "mmt_si_mpt_table_body_prefix + mmt_si_mpt_asset_id16_location_ipv6_nz (AAR lab: table_length 56)")
        ("validate-mmt-si-mpt-asset-id16-descriptors4",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-mpt-table-body; MPT body must decode as "
         "mmt_si_mpt_table_body_prefix + mmt_si_mpt_asset_id16_descriptors4 (AAS lab: table_length 25)")
        ("validate-mmt-si-mpt-asset-id8-descriptors4",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-mpt-table-body; MPT body must decode as "
         "mmt_si_mpt_table_body_prefix + mmt_si_mpt_asset_id8_descriptors4 (AAT lab: table_length 24)")
        ("validate-mmt-si-mpt-asset-descriptors4",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-mpt-table-body; MPT body must decode as "
         "mmt_si_mpt_table_body_prefix + mmt_si_mpt_asset_descriptors4 (AAC lab: table_length 23)")
        ("validate-mmt-si-plt-table-body-prefix",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-plt-table-body; PLT table_length region must "
         "decode as mmt_si_plt_table_body_prefix (minimal lab: length 2)")
        ("validate-mmt-si-plt-delivery-info",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-plt-table-body; PLT body must decode as "
         "mmt_si_plt_table_body_prefix + mmt_si_plt_delivery_info (ZL lab: length 9)")
        ("validate-mmt-si-plt-delivery-info-ipv4",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-plt-table-body; PLT body must decode as "
         "mmt_si_plt_table_body_prefix + mmt_si_plt_delivery_info_ipv4 (ZM lab: length 19)")
        ("validate-mmt-si-plt-delivery-info-ipv6",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-plt-table-body; PLT body must decode as "
         "mmt_si_plt_table_body_prefix + mmt_si_plt_delivery_info_ipv6 (ZN lab: length 43)")
        ("validate-mmt-si-plt-delivery-info-url",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-plt-table-body; PLT body must decode as "
         "mmt_si_plt_table_body_prefix + mmt_si_plt_delivery_info_url (ZO lab: length 10)")
        ("validate-mmt-si-plt-delivery-info-url-3",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-plt-table-body; PLT body must decode as "
         "mmt_si_plt_table_body_prefix + mmt_si_plt_delivery_info_url_3 (ZQ lab: length 13)")
        ("validate-mmt-si-plt-delivery-info-url-4",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-plt-table-body; PLT body must decode as "
         "mmt_si_plt_table_body_prefix + mmt_si_plt_delivery_info_url_4 (AAD lab: length 14)")
        ("validate-mmt-si-plt-delivery-info-ipv4-nz",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-plt-table-body; PLT body must decode as "
         "mmt_si_plt_table_body_prefix + mmt_si_plt_delivery_info_ipv4_nz (AAE lab: length 19)")
        ("validate-mmt-si-plt-package-entry",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-plt-table-body; PLT body must decode as "
         "mmt_si_plt_table_body_prefix + mmt_si_plt_package_entry (ZP lab: length 6)")
        ("validate-mmt-si-plt-package-entry-id8",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-plt-table-body; PLT body must decode as "
         "mmt_si_plt_table_body_prefix + mmt_si_plt_package_entry_id8 (ZR lab: length 7)")
        ("validate-mmt-si-plt-package-entry-ipv4",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-plt-table-body; PLT body must decode as "
         "mmt_si_plt_table_body_prefix + mmt_si_plt_package_entry_ipv4 (ZU lab: length 14)")
        ("validate-mmt-si-plt-package-entry-ipv4-nz",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-plt-table-body; PLT body must decode as "
         "mmt_si_plt_table_body_prefix + mmt_si_plt_package_entry_ipv4_nz (AAI lab: length 14)")
        ("validate-mmt-si-plt-package-entry-id8-location-ipv4",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-plt-table-body; PLT body must decode as "
         "mmt_si_plt_table_body_prefix + mmt_si_plt_package_entry_id8_location_ipv4 "
         "(ZX lab: length 15)")
        ("validate-mmt-si-plt-package-entry-id8-location-ipv4-nz",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-plt-table-body; PLT body must decode as "
         "mmt_si_plt_table_body_prefix + mmt_si_plt_package_entry_id8_location_ipv4_nz "
         "(AAK lab: length 15)")
        ("validate-mmt-si-plt-package-entry-ipv6",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-plt-table-body; PLT body must decode as "
         "mmt_si_plt_table_body_prefix + mmt_si_plt_package_entry_ipv6 (ZZ lab: length 38)")
        ("validate-mmt-si-plt-package-entry-ipv6-nz",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-plt-table-body; PLT body must decode as "
         "mmt_si_plt_table_body_prefix + mmt_si_plt_package_entry_ipv6_nz (AAJ lab: length 38)")
        ("validate-mmt-si-plt-package-entry-id8-location-ipv6",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-plt-table-body; PLT body must decode as "
         "mmt_si_plt_table_body_prefix + mmt_si_plt_package_entry_id8_location_ipv6 "
         "(AAB lab: length 39)")
        ("validate-mmt-si-plt-package-entry-id8-location-ipv6-nz",
         bpo::bool_switch()->default_value(false),
         "requires --validate-mmt-si-plt-table-body; PLT body must decode as "
         "mmt_si_plt_table_body_prefix + mmt_si_plt_package_entry_id8_location_ipv6_nz "
         "(AAL lab: length 39)")
        ("prepend-mmtp-isobmff-prefix",
         bpo::bool_switch()->default_value(false),
         "when --prepend-mmtp-word0: prepend MMTP ISOBMFF-mode payload header "
         "(first 64 bits per ISO/IEC 23008-1 Figure 3; protocol/"
         "mmtp_payload_isobmff_prefix.yaml) after optional ts_psn, packet_counter, "
         "extension; mutually exclusive with --prepend-mmtp-signalling-prefix; "
         "implies payload_type 0; sets length_excluding_length_field = 6 + octets "
         "after the 64b prefix (ingress, or DU_length+body repeats when A=1, plus "
         "optional LCT lab prefix)")
        ("mmtp-isobmff-fragment-type",
         bpo::value<unsigned>()->default_value(2),
         "when --prepend-mmtp-isobmff-prefix: fragment_type (0-15)")
        ("mmtp-isobmff-timed",
         bpo::bool_switch()->default_value(false),
         "when --prepend-mmtp-isobmff-prefix: set timed_flag (T)")
        ("mmtp-isobmff-fragmentation",
         bpo::value<unsigned>()->default_value(0),
         "when --prepend-mmtp-isobmff-prefix: fragmentation_indicator (0-3)")
        ("mmtp-isobmff-aggregation",
         bpo::bool_switch()->default_value(false),
         "when --prepend-mmtp-isobmff-prefix: set aggregation_flag (A=1); "
         "requires --mmtp-isobmff-aggregate-hex (one DU per token)")
        ("mmtp-isobmff-aggregate-hex",
         bpo::value<std::vector<std::string>>()->multitoken(),
         "when --prepend-mmtp-isobmff-prefix with --mmtp-isobmff-aggregation: "
         "even-length hex per aggregated DU (DU_length on wire = octet count; "
         "16-bit BE per ISO/IEC 23008-1); with --prepend-mmtp-isobmff-du-header, "
         "each token is media-only (wire DU_length includes DU_header octets)")
        ("mmtp-isobmff-fragment-counter",
         bpo::value<unsigned>()->default_value(0),
         "when --prepend-mmtp-isobmff-prefix: fragment_counter (0-255)")
        ("mmtp-isobmff-sequence-number",
         bpo::value<std::uint32_t>()->default_value(0),
         "when --prepend-mmtp-isobmff-prefix: sequence_number (32-bit BE on wire)")
        ("prepend-mmtp-isobmff-du-header",
         bpo::bool_switch()->default_value(false),
         "when --prepend-mmtp-isobmff-prefix: emit DU_header (Fig. 4/5) for "
         "FT=2: after the 64b prefix when A=0, or once per aggregated DU when "
         "A=1; requires --mmtp-isobmff-fragment-type 2")
        ("mmtp-isobmff-du-item-id",
         bpo::value<std::uint32_t>()->default_value(0),
         "when --prepend-mmtp-isobmff-du-header with T=0: item_id (BE32)")
        ("mmtp-isobmff-du-mf-seq",
         bpo::value<std::uint32_t>()->default_value(0),
         "when --prepend-mmtp-isobmff-du-header with T=1: movie_fragment_sequence_number")
        ("mmtp-isobmff-du-sample",
         bpo::value<std::uint32_t>()->default_value(0),
         "when --prepend-mmtp-isobmff-du-header with T=1: sample_number")
        ("mmtp-isobmff-du-offset",
         bpo::value<std::uint32_t>()->default_value(0),
         "when --prepend-mmtp-isobmff-du-header with T=1: offset")
        ("mmtp-isobmff-du-priority",
         bpo::value<unsigned>()->default_value(0),
         "when --prepend-mmtp-isobmff-du-header with T=1: subsample_priority (0-255)")
        ("mmtp-isobmff-du-dep-counter",
         bpo::value<unsigned>()->default_value(0),
         "when --prepend-mmtp-isobmff-du-header with T=1: dependency_counter (0-255)")
        ("prepend-mmtp-gfd-header",
         bpo::bool_switch()->default_value(false),
         "when --prepend-mmtp-word0: prepend MMTP GFD-mode payload header "
         "(96b, ISO/IEC 23008-1 Figure 6, protocol/mmtp_payload_gfd_header.yaml) "
         "after optional ts_psn, packet_counter, extension; mutually exclusive with "
         "--prepend-mmtp-signalling-prefix and --prepend-mmtp-isobmff-prefix; "
         "requires --mmtp-payload-type 1 (GFD mode)")
        ("mmtp-gfd-session-last",
         bpo::bool_switch()->default_value(false),
         "when --prepend-mmtp-gfd-header: session_last_packet_flag (C)")
        ("mmtp-gfd-object-last-packet",
         bpo::bool_switch()->default_value(false),
         "when --prepend-mmtp-gfd-header: object_last_packet_flag (L)")
        ("mmtp-gfd-object-last-byte",
         bpo::bool_switch()->default_value(false),
         "when --prepend-mmtp-gfd-header: object_last_byte_flag (B)")
        ("mmtp-gfd-code-point",
         bpo::value<unsigned>()->default_value(0),
         "when --prepend-mmtp-gfd-header: code_point (0-255)")
        ("mmtp-gfd-reserved",
         bpo::value<unsigned>()->default_value(0),
         "when --prepend-mmtp-gfd-header: reserved field (0-31, 5 bits)")
        ("mmtp-gfd-toi",
         bpo::value<std::uint32_t>()->default_value(0),
         "when --prepend-mmtp-gfd-header: transport_object_identifier (BE32)")
        ("mmtp-gfd-start-offset",
         bpo::value<std::uint64_t>()->default_value(0),
         "when --prepend-mmtp-gfd-header: start_offset (BE48 on wire)");

    return app.run(argc, argv, [&app]() -> seastar::future<int> {
        auto& cfg = app.configuration();

        const std::string admin_bind = cfg["admin-http"].as<std::string>();
        const std::string services_state = cfg["services-state-file"].as<std::string>();
        const bool prepend_lct = cfg["prepend-lct-word0"].as<bool>();
        const bool lct_include_tsi = cfg["lct-include-tsi"].as<bool>();
        const bool lct_include_toi = cfg["lct-include-toi"].as<bool>();
        const unsigned cp_in = cfg["lct-codepoint"].as<unsigned>();
        const std::uint32_t lct_tsi = cfg["lct-tsi"].as<std::uint32_t>();
        const std::uint32_t lct_toi = cfg["lct-toi"].as<std::uint32_t>();
        const bool alp_pc = cfg["alp-payload-config"].as<bool>();
        const bool alp_hm = cfg["alp-header-mode"].as<bool>();
        const bool prepend_mmtp = cfg["prepend-mmtp-word0"].as<bool>();
        const unsigned mmtp_pt_in = cfg["mmtp-payload-type"].as<unsigned>();
        const unsigned mmtp_pid_in = cfg["mmtp-packet-id"].as<unsigned>();
        const bool prepend_mmtp_ts_psn = cfg["prepend-mmtp-ts-psn"].as<bool>();
        const std::uint32_t mmtp_ts = cfg["mmtp-timestamp"].as<std::uint32_t>();
        const std::uint32_t mmtp_psn = cfg["mmtp-psn"].as<std::uint32_t>();
        const bool prepend_mmtp_pkt_ctr =
            cfg["prepend-mmtp-packet-counter"].as<bool>();
        const std::uint32_t mmtp_pkt_ctr =
            cfg["mmtp-packet-counter"].as<std::uint32_t>();
        const bool prepend_mmtp_ext = cfg["prepend-mmtp-extension"].as<bool>();
        const unsigned mmtp_ext_type_in = cfg["mmtp-extension-type"].as<unsigned>();
        const std::string mmtp_ext_hex =
            cfg["mmtp-extension-hex"].as<std::string>();
        const bool prepend_mmtp_sig =
            cfg["prepend-mmtp-signalling-prefix"].as<bool>();
        const unsigned mmtp_sig_fi =
            cfg["mmtp-signalling-fragmentation"].as<unsigned>();
        const unsigned mmtp_sig_res =
            cfg["mmtp-signalling-reserved"].as<unsigned>();
        const bool mmtp_sig_len_ext =
            cfg["mmtp-signalling-length-extension"].as<bool>();
        const bool mmtp_sig_agg =
            cfg["mmtp-signalling-aggregation"].as<bool>();
        const unsigned mmtp_sig_frag_ctr =
            cfg["mmtp-signalling-fragment-counter"].as<unsigned>();
        const bool prepend_mmtp_isobmff =
            cfg["prepend-mmtp-isobmff-prefix"].as<bool>();
        const unsigned mmtp_iso_ft =
            cfg["mmtp-isobmff-fragment-type"].as<unsigned>();
        const bool mmtp_iso_timed = cfg["mmtp-isobmff-timed"].as<bool>();
        const unsigned mmtp_iso_fi =
            cfg["mmtp-isobmff-fragmentation"].as<unsigned>();
        const bool mmtp_iso_agg = cfg["mmtp-isobmff-aggregation"].as<bool>();
        const unsigned mmtp_iso_frag_ctr =
            cfg["mmtp-isobmff-fragment-counter"].as<unsigned>();
        const std::uint32_t mmtp_iso_seq =
            cfg["mmtp-isobmff-sequence-number"].as<std::uint32_t>();
        const bool prepend_mmtp_isobmff_du_hdr =
            cfg["prepend-mmtp-isobmff-du-header"].as<bool>();
        const std::uint32_t mmtp_iso_du_item_id =
            cfg["mmtp-isobmff-du-item-id"].as<std::uint32_t>();
        const std::uint32_t mmtp_iso_du_mf_seq =
            cfg["mmtp-isobmff-du-mf-seq"].as<std::uint32_t>();
        const std::uint32_t mmtp_iso_du_sample =
            cfg["mmtp-isobmff-du-sample"].as<std::uint32_t>();
        const std::uint32_t mmtp_iso_du_offset =
            cfg["mmtp-isobmff-du-offset"].as<std::uint32_t>();
        const unsigned mmtp_iso_du_priority =
            cfg["mmtp-isobmff-du-priority"].as<unsigned>();
        const unsigned mmtp_iso_du_dep_counter =
            cfg["mmtp-isobmff-du-dep-counter"].as<unsigned>();
        const bool prepend_mmtp_gfd =
            cfg["prepend-mmtp-gfd-header"].as<bool>();
        const bool mmtp_gfd_session_last =
            cfg["mmtp-gfd-session-last"].as<bool>();
        const bool mmtp_gfd_obj_last_pkt =
            cfg["mmtp-gfd-object-last-packet"].as<bool>();
        const bool mmtp_gfd_obj_last_byte =
            cfg["mmtp-gfd-object-last-byte"].as<bool>();
        const unsigned mmtp_gfd_code_point =
            cfg["mmtp-gfd-code-point"].as<unsigned>();
        const unsigned mmtp_gfd_reserved =
            cfg["mmtp-gfd-reserved"].as<unsigned>();
        const std::uint32_t mmtp_gfd_toi =
            cfg["mmtp-gfd-toi"].as<std::uint32_t>();
        const std::uint64_t mmtp_gfd_start_offset =
            cfg["mmtp-gfd-start-offset"].as<std::uint64_t>();
        const bool prepend_mmt_si_len32 =
            cfg["prepend-mmt-si-length32-envelope"].as<bool>();
        const bool prepend_mmt_si_desc_u32 =
            cfg["prepend-mmt-si-descriptor-loop-u32"].as<bool>();
        const bool prepend_mmt_si_msg_hdr =
            cfg["prepend-mmt-si-message-header-len32"].as<bool>();
        const bool prepend_mmt_si_pa_hdr =
            cfg["prepend-mmt-si-pa-table-headers"].as<bool>();
        const bool validate_mmt_si_mpt_body =
            cfg["validate-mmt-si-mpt-table-body"].as<bool>();
        const bool validate_mmt_si_plt_body =
            cfg["validate-mmt-si-plt-table-body"].as<bool>();
        const bool validate_mmt_si_mpt_body_prefix =
            cfg["validate-mmt-si-mpt-table-body-prefix"].as<bool>();
        const bool validate_mmt_si_mpt_asset =
            cfg["validate-mmt-si-mpt-asset"].as<bool>();
        const bool validate_mmt_si_mpt_asset_descriptors4 =
            cfg["validate-mmt-si-mpt-asset-descriptors4"].as<bool>();
        const bool validate_mmt_si_mpt_asset_id8 =
            cfg["validate-mmt-si-mpt-asset-id8"].as<bool>();
        const bool validate_mmt_si_mpt_asset_id16 =
            cfg["validate-mmt-si-mpt-asset-id16"].as<bool>();
        const bool validate_mmt_si_mpt_asset_location0 =
            cfg["validate-mmt-si-mpt-asset-location0"].as<bool>();
        const bool validate_mmt_si_mpt_asset_location_ipv4 =
            cfg["validate-mmt-si-mpt-asset-location-ipv4"].as<bool>();
        const bool validate_mmt_si_mpt_asset_location_ipv4_nz =
            cfg["validate-mmt-si-mpt-asset-location-ipv4-nz"].as<bool>();
        const bool validate_mmt_si_mpt_asset_location_ipv6 =
            cfg["validate-mmt-si-mpt-asset-location-ipv6"].as<bool>();
        const bool validate_mmt_si_mpt_asset_location_ipv6_nz =
            cfg["validate-mmt-si-mpt-asset-location-ipv6-nz"].as<bool>();
        const bool validate_mmt_si_mpt_asset_id8_location_ipv4 =
            cfg["validate-mmt-si-mpt-asset-id8-location-ipv4"].as<bool>();
        const bool validate_mmt_si_mpt_asset_id8_location_ipv4_nz =
            cfg["validate-mmt-si-mpt-asset-id8-location-ipv4-nz"].as<bool>();
        const bool validate_mmt_si_mpt_asset_id8_location_ipv6 =
            cfg["validate-mmt-si-mpt-asset-id8-location-ipv6"].as<bool>();
        const bool validate_mmt_si_mpt_asset_id8_location_ipv6_nz =
            cfg["validate-mmt-si-mpt-asset-id8-location-ipv6-nz"].as<bool>();
        const bool validate_mmt_si_mpt_asset_id16_location_ipv4 =
            cfg["validate-mmt-si-mpt-asset-id16-location-ipv4"].as<bool>();
        const bool validate_mmt_si_mpt_asset_id16_location_ipv4_nz =
            cfg["validate-mmt-si-mpt-asset-id16-location-ipv4-nz"].as<bool>();
        const bool validate_mmt_si_mpt_asset_id16_location_ipv6 =
            cfg["validate-mmt-si-mpt-asset-id16-location-ipv6"].as<bool>();
        const bool validate_mmt_si_mpt_asset_id16_location_ipv6_nz =
            cfg["validate-mmt-si-mpt-asset-id16-location-ipv6-nz"].as<bool>();
        const bool validate_mmt_si_mpt_asset_id16_descriptors4 =
            cfg["validate-mmt-si-mpt-asset-id16-descriptors4"].as<bool>();
        const bool validate_mmt_si_mpt_asset_id8_descriptors4 =
            cfg["validate-mmt-si-mpt-asset-id8-descriptors4"].as<bool>();
        const bool validate_mmt_si_plt_body_prefix =
            cfg["validate-mmt-si-plt-table-body-prefix"].as<bool>();
        const bool validate_mmt_si_plt_delivery =
            cfg["validate-mmt-si-plt-delivery-info"].as<bool>();
        const bool validate_mmt_si_plt_delivery_ipv4 =
            cfg["validate-mmt-si-plt-delivery-info-ipv4"].as<bool>();
        const bool validate_mmt_si_plt_delivery_ipv6 =
            cfg["validate-mmt-si-plt-delivery-info-ipv6"].as<bool>();
        const bool validate_mmt_si_plt_delivery_url =
            cfg["validate-mmt-si-plt-delivery-info-url"].as<bool>();
        const bool validate_mmt_si_plt_delivery_url_3 =
            cfg["validate-mmt-si-plt-delivery-info-url-3"].as<bool>();
        const bool validate_mmt_si_plt_delivery_url_4 =
            cfg["validate-mmt-si-plt-delivery-info-url-4"].as<bool>();
        const bool validate_mmt_si_plt_delivery_ipv4_nz =
            cfg["validate-mmt-si-plt-delivery-info-ipv4-nz"].as<bool>();
        const bool validate_mmt_si_plt_package_entry =
            cfg["validate-mmt-si-plt-package-entry"].as<bool>();
        const bool validate_mmt_si_plt_package_entry_id8 =
            cfg["validate-mmt-si-plt-package-entry-id8"].as<bool>();
        const bool validate_mmt_si_plt_package_entry_ipv4 =
            cfg["validate-mmt-si-plt-package-entry-ipv4"].as<bool>();
        const bool validate_mmt_si_plt_package_entry_ipv4_nz =
            cfg["validate-mmt-si-plt-package-entry-ipv4-nz"].as<bool>();
        const bool validate_mmt_si_plt_package_entry_id8_location_ipv4 =
            cfg["validate-mmt-si-plt-package-entry-id8-location-ipv4"].as<bool>();
        const bool validate_mmt_si_plt_package_entry_id8_location_ipv4_nz =
            cfg["validate-mmt-si-plt-package-entry-id8-location-ipv4-nz"].as<bool>();
        const bool validate_mmt_si_plt_package_entry_ipv6 =
            cfg["validate-mmt-si-plt-package-entry-ipv6"].as<bool>();
        const bool validate_mmt_si_plt_package_entry_ipv6_nz =
            cfg["validate-mmt-si-plt-package-entry-ipv6-nz"].as<bool>();
        const bool validate_mmt_si_plt_package_entry_id8_location_ipv6 =
            cfg["validate-mmt-si-plt-package-entry-id8-location-ipv6"].as<bool>();
        const bool validate_mmt_si_plt_package_entry_id8_location_ipv6_nz =
            cfg["validate-mmt-si-plt-package-entry-id8-location-ipv6-nz"].as<bool>();
        const unsigned mmtp_si_msg_id_in =
            cfg["mmtp-si-message-id"].as<unsigned>();
        const unsigned mmtp_si_msg_ver_in =
            cfg["mmtp-si-message-version"].as<unsigned>();
        if (!prepend_lct && cp_in != 0u) {
            mlog.error("--lct-codepoint is only meaningful with --prepend-lct-word0");
            co_return 2;
        }
        if (!prepend_lct && lct_include_tsi) {
            mlog.error("--lct-include-tsi requires --prepend-lct-word0");
            co_return 2;
        }
        if (!prepend_lct && lct_include_toi) {
            mlog.error("--lct-include-toi requires --prepend-lct-word0");
            co_return 2;
        }
        if (prepend_mmtp && mmtp_pt_in > 63u) {
            mlog.error("--mmtp-payload-type must be <= 63");
            co_return 2;
        }
        if (prepend_mmtp_isobmff && prepend_mmtp && mmtp_pt_in != 0u) {
            mlog.error(
                "--prepend-mmtp-isobmff-prefix requires --mmtp-payload-type 0 "
                "(ISOBMFF mode)");
            co_return 2;
        }
        if (prepend_mmtp_gfd && prepend_mmtp && mmtp_pt_in != 1u) {
            mlog.error(
                "--prepend-mmtp-gfd-header requires --mmtp-payload-type 1 "
                "(GFD mode)");
            co_return 2;
        }
        if (prepend_mmtp && mmtp_pid_in > 65535u) {
            mlog.error("--mmtp-packet-id must be <= 65535");
            co_return 2;
        }
        if (prepend_mmtp_ts_psn && !prepend_mmtp) {
            mlog.error("--prepend-mmtp-ts-psn requires --prepend-mmtp-word0");
            co_return 2;
        }
        if (prepend_mmtp_pkt_ctr && !prepend_mmtp_ts_psn) {
            mlog.error(
                "--prepend-mmtp-packet-counter requires --prepend-mmtp-ts-psn");
            co_return 2;
        }
        if (prepend_mmtp_pkt_ctr && !prepend_mmtp) {
            mlog.error(
                "--prepend-mmtp-packet-counter requires --prepend-mmtp-word0");
            co_return 2;
        }
        if (prepend_mmtp_ext && !prepend_mmtp) {
            mlog.error("--prepend-mmtp-extension requires --prepend-mmtp-word0");
            co_return 2;
        }
        if (prepend_mmtp_ext && mmtp_ext_type_in > 65535u) {
            mlog.error("--mmtp-extension-type must be <= 65535");
            co_return 2;
        }
        if (cfg.count("mmtp-extension") != 0 && !prepend_mmtp_ext) {
            mlog.error("--mmtp-extension requires --prepend-mmtp-extension");
            co_return 2;
        }
        if (prepend_mmtp_sig && !prepend_mmtp) {
            mlog.error(
                "--prepend-mmtp-signalling-prefix requires --prepend-mmtp-word0");
            co_return 2;
        }
        if (prepend_mmtp_sig && mmtp_sig_fi > 3u) {
            mlog.error("--mmtp-signalling-fragmentation must be <= 3");
            co_return 2;
        }
        if (prepend_mmtp_sig && mmtp_sig_res > 15u) {
            mlog.error("--mmtp-signalling-reserved must be <= 15");
            co_return 2;
        }
        if (prepend_mmtp_sig && mmtp_sig_frag_ctr > 255u) {
            mlog.error("--mmtp-signalling-fragment-counter must be <= 255");
            co_return 2;
        }
        if (prepend_mmtp_isobmff && !prepend_mmtp) {
            mlog.error(
                "--prepend-mmtp-isobmff-prefix requires --prepend-mmtp-word0");
            co_return 2;
        }
        if (prepend_mmtp_isobmff && prepend_mmtp_sig) {
            mlog.error(
                "--prepend-mmtp-isobmff-prefix cannot be combined with "
                "--prepend-mmtp-signalling-prefix");
            co_return 2;
        }
        if (prepend_mmtp_gfd && !prepend_mmtp) {
            mlog.error(
                "--prepend-mmtp-gfd-header requires --prepend-mmtp-word0");
            co_return 2;
        }
        if (prepend_mmtp_gfd && prepend_mmtp_sig) {
            mlog.error(
                "--prepend-mmtp-gfd-header cannot be combined with "
                "--prepend-mmtp-signalling-prefix");
            co_return 2;
        }
        if (prepend_mmtp_gfd && prepend_mmtp_isobmff) {
            mlog.error(
                "--prepend-mmtp-gfd-header cannot be combined with "
                "--prepend-mmtp-isobmff-prefix");
            co_return 2;
        }
        if (prepend_mmtp_gfd && mmtp_gfd_code_point > 255u) {
            mlog.error("--mmtp-gfd-code-point must be <= 255");
            co_return 2;
        }
        if (prepend_mmtp_gfd && mmtp_gfd_reserved > 31u) {
            mlog.error("--mmtp-gfd-reserved must be <= 31");
            co_return 2;
        }
        if (prepend_mmtp_isobmff && mmtp_iso_ft > 15u) {
            mlog.error("--mmtp-isobmff-fragment-type must be <= 15");
            co_return 2;
        }
        if (prepend_mmtp_isobmff && mmtp_iso_fi > 3u) {
            mlog.error("--mmtp-isobmff-fragmentation must be <= 3");
            co_return 2;
        }
        if (prepend_mmtp_isobmff && mmtp_iso_frag_ctr > 255u) {
            mlog.error("--mmtp-isobmff-fragment-counter must be <= 255");
            co_return 2;
        }
        if (cfg.count("mmtp-isobmff-aggregate-hex") != 0 && !prepend_mmtp_isobmff) {
            mlog.error(
                "--mmtp-isobmff-aggregate-hex requires --prepend-mmtp-isobmff-prefix");
            co_return 2;
        }
        if (cfg.count("mmtp-isobmff-aggregate-hex") != 0 && !mmtp_iso_agg) {
            mlog.error(
                "--mmtp-isobmff-aggregate-hex requires --mmtp-isobmff-aggregation");
            co_return 2;
        }
        if (prepend_mmtp_isobmff && mmtp_iso_agg &&
            cfg.count("mmtp-isobmff-aggregate-hex") == 0) {
            mlog.error(
                "--mmtp-isobmff-aggregation requires --mmtp-isobmff-aggregate-hex "
                "(at least one DU)");
            co_return 2;
        }
        if (prepend_mmtp_isobmff_du_hdr && !prepend_mmtp_isobmff) {
            mlog.error(
                "--prepend-mmtp-isobmff-du-header requires "
                "--prepend-mmtp-isobmff-prefix");
            co_return 2;
        }
        if (prepend_mmtp_isobmff_du_hdr && mmtp_iso_ft != 2u) {
            mlog.error(
                "--prepend-mmtp-isobmff-du-header requires "
                "--mmtp-isobmff-fragment-type 2 (data unit)");
            co_return 2;
        }
        if (prepend_mmtp_isobmff_du_hdr && mmtp_iso_du_priority > 255u) {
            mlog.error("--mmtp-isobmff-du-priority must be <= 255");
            co_return 2;
        }
        if (prepend_mmtp_isobmff_du_hdr && mmtp_iso_du_dep_counter > 255u) {
            mlog.error("--mmtp-isobmff-du-dep-counter must be <= 255");
            co_return 2;
        }
        if (prepend_mmtp_sig && !prepend_mmtp) {
            mlog.error(
                "--prepend-mmtp-signalling-prefix requires --prepend-mmtp-word0");
            co_return 2;
        }
        if (cfg.count("mmtp-signalling-aggregate-hex") != 0 && !prepend_mmtp_sig) {
            mlog.error(
                "--mmtp-signalling-aggregate-hex requires "
                "--prepend-mmtp-signalling-prefix");
            co_return 2;
        }
        if (cfg.count("mmtp-signalling-aggregate-hex") != 0 && !mmtp_sig_agg) {
            mlog.error(
                "--mmtp-signalling-aggregate-hex requires "
                "--mmtp-signalling-aggregation");
            co_return 2;
        }
        if (prepend_mmt_si_len32 && !prepend_mmtp_sig) {
            mlog.error(
                "--prepend-mmt-si-length32-envelope requires "
                "--prepend-mmtp-signalling-prefix");
            co_return 2;
        }
        if (prepend_mmt_si_len32 && !prepend_mmtp) {
            mlog.error(
                "--prepend-mmt-si-length32-envelope requires --prepend-mmtp-word0");
            co_return 2;
        }
        if (prepend_mmt_si_len32 && prepend_mmtp && mmtp_pt_in != 2u) {
            mlog.error(
                "--prepend-mmt-si-length32-envelope requires --mmtp-payload-type 2 "
                "(signalling)");
            co_return 2;
        }
        if (prepend_mmt_si_len32 && mmtp_sig_agg) {
            mlog.error(
                "--prepend-mmt-si-length32-envelope requires "
                "--mmtp-signalling-aggregation off (no §9.3.4 aggregate bodies)");
            co_return 2;
        }
        if (prepend_mmt_si_desc_u32 && !prepend_mmtp_sig) {
            mlog.error(
                "--prepend-mmt-si-descriptor-loop-u32 requires "
                "--prepend-mmtp-signalling-prefix");
            co_return 2;
        }
        if (prepend_mmt_si_desc_u32 && !prepend_mmtp) {
            mlog.error(
                "--prepend-mmt-si-descriptor-loop-u32 requires --prepend-mmtp-word0");
            co_return 2;
        }
        if (prepend_mmt_si_desc_u32 && prepend_mmtp && mmtp_pt_in != 2u) {
            mlog.error(
                "--prepend-mmt-si-descriptor-loop-u32 requires --mmtp-payload-type 2 "
                "(signalling)");
            co_return 2;
        }
        if (prepend_mmt_si_desc_u32 && mmtp_sig_agg) {
            mlog.error(
                "--prepend-mmt-si-descriptor-loop-u32 requires "
                "--mmtp-signalling-aggregation off (no §9.3.4 aggregate bodies)");
            co_return 2;
        }
        if (prepend_mmt_si_msg_hdr && !prepend_mmtp_sig) {
            mlog.error(
                "--prepend-mmt-si-message-header-len32 requires "
                "--prepend-mmtp-signalling-prefix");
            co_return 2;
        }
        if (prepend_mmt_si_msg_hdr && !prepend_mmtp) {
            mlog.error(
                "--prepend-mmt-si-message-header-len32 requires --prepend-mmtp-word0");
            co_return 2;
        }
        if (prepend_mmt_si_msg_hdr && prepend_mmtp && mmtp_pt_in != 2u) {
            mlog.error(
                "--prepend-mmt-si-message-header-len32 requires --mmtp-payload-type 2 "
                "(signalling)");
            co_return 2;
        }
        if (prepend_mmt_si_msg_hdr && mmtp_sig_agg) {
            mlog.error(
                "--prepend-mmt-si-message-header-len32 requires "
                "--mmtp-signalling-aggregation off (no §9.3.4 aggregate bodies)");
            co_return 2;
        }
        if (mmtp_si_msg_id_in > 65535u) {
            mlog.error("--mmtp-si-message-id must be <= 65535");
            co_return 2;
        }
        if (mmtp_si_msg_ver_in > 255u) {
            mlog.error("--mmtp-si-message-version must be <= 255");
            co_return 2;
        }
        if (cfg.count("mmtp-si-pa-table-row") != 0 && !prepend_mmt_si_pa_hdr) {
            mlog.error(
                "--mmtp-si-pa-table-row requires --prepend-mmt-si-pa-table-headers");
            co_return 2;
        }
        if (prepend_mmt_si_pa_hdr && !prepend_mmt_si_msg_hdr) {
            mlog.error(
                "--prepend-mmt-si-pa-table-headers requires "
                "--prepend-mmt-si-message-header-len32");
            co_return 2;
        }
        if (prepend_mmt_si_pa_hdr && mmtp_si_msg_id_in != 0u) {
            mlog.error(
                "--prepend-mmt-si-pa-table-headers requires --mmtp-si-message-id 0 "
                "(PA message lab)");
            co_return 2;
        }
        if (prepend_mmt_si_pa_hdr && !prepend_mmtp_sig) {
            mlog.error(
                "--prepend-mmt-si-pa-table-headers requires "
                "--prepend-mmtp-signalling-prefix");
            co_return 2;
        }
        if (prepend_mmt_si_pa_hdr && !prepend_mmtp) {
            mlog.error(
                "--prepend-mmt-si-pa-table-headers requires --prepend-mmtp-word0");
            co_return 2;
        }
        if (prepend_mmt_si_pa_hdr && prepend_mmtp && mmtp_pt_in != 2u) {
            mlog.error(
                "--prepend-mmt-si-pa-table-headers requires --mmtp-payload-type 2 "
                "(signalling)");
            co_return 2;
        }
        if (prepend_mmt_si_pa_hdr && mmtp_sig_agg) {
            mlog.error(
                "--prepend-mmt-si-pa-table-headers requires "
                "--mmtp-signalling-aggregation off (no §9.3.4 aggregate bodies)");
            co_return 2;
        }
        if (validate_mmt_si_mpt_body && validate_mmt_si_plt_body) {
            mlog.error(
                "--validate-mmt-si-mpt-table-body and "
                "--validate-mmt-si-plt-table-body are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_body && !prepend_mmtp_sig) {
            mlog.error(
                "--validate-mmt-si-mpt-table-body requires "
                "--prepend-mmtp-signalling-prefix");
            co_return 2;
        }
        if (validate_mmt_si_plt_body && !prepend_mmtp_sig) {
            mlog.error(
                "--validate-mmt-si-plt-table-body requires "
                "--prepend-mmtp-signalling-prefix");
            co_return 2;
        }
        if (validate_mmt_si_mpt_body_prefix && !validate_mmt_si_mpt_body) {
            mlog.error(
                "--validate-mmt-si-mpt-table-body-prefix requires "
                "--validate-mmt-si-mpt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset && !validate_mmt_si_mpt_body) {
            mlog.error(
                "--validate-mmt-si-mpt-asset requires "
                "--validate-mmt-si-mpt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset && validate_mmt_si_mpt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-mpt-asset and "
                "--validate-mmt-si-mpt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8 && !validate_mmt_si_mpt_body) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8 requires "
                "--validate-mmt-si-mpt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8 && validate_mmt_si_mpt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8 and "
                "--validate-mmt-si-mpt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset && validate_mmt_si_mpt_asset_id8) {
            mlog.error(
                "--validate-mmt-si-mpt-asset and "
                "--validate-mmt-si-mpt-asset-id8 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location0 && !validate_mmt_si_mpt_body) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location0 requires "
                "--validate-mmt-si-mpt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location0 && validate_mmt_si_mpt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location0 and "
                "--validate-mmt-si-mpt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset && validate_mmt_si_mpt_asset_location0) {
            mlog.error(
                "--validate-mmt-si-mpt-asset and "
                "--validate-mmt-si-mpt-asset-location0 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8 && validate_mmt_si_mpt_asset_location0) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8 and "
                "--validate-mmt-si-mpt-asset-location0 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8 && validate_mmt_si_mpt_asset_id16) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8 and "
                "--validate-mmt-si-mpt-asset-id16 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16 && !validate_mmt_si_mpt_body) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16 requires "
                "--validate-mmt-si-mpt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16 && validate_mmt_si_mpt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16 and "
                "--validate-mmt-si-mpt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset && validate_mmt_si_mpt_asset_id16) {
            mlog.error(
                "--validate-mmt-si-mpt-asset and "
                "--validate-mmt-si-mpt-asset-id16 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16 && validate_mmt_si_mpt_asset_location0) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16 and "
                "--validate-mmt-si-mpt-asset-location0 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location_ipv4 && !validate_mmt_si_mpt_body) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location-ipv4 requires "
                "--validate-mmt-si-mpt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location_ipv4 && validate_mmt_si_mpt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location-ipv4 and "
                "--validate-mmt-si-mpt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset && validate_mmt_si_mpt_asset_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset and "
                "--validate-mmt-si-mpt-asset-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8 && validate_mmt_si_mpt_asset_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8 and "
                "--validate-mmt-si-mpt-asset-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location0 && validate_mmt_si_mpt_asset_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location0 and "
                "--validate-mmt-si-mpt-asset-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location_ipv4 &&
            validate_mmt_si_mpt_asset_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location-ipv4 and "
                "--validate-mmt-si-mpt-asset-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location_ipv4_nz && !validate_mmt_si_mpt_body) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location-ipv4-nz requires "
                "--validate-mmt-si-mpt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location_ipv4_nz && validate_mmt_si_mpt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location-ipv4-nz and "
                "--validate-mmt-si-mpt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset && validate_mmt_si_mpt_asset_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset and "
                "--validate-mmt-si-mpt-asset-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8 && validate_mmt_si_mpt_asset_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8 and "
                "--validate-mmt-si-mpt-asset-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location0 && validate_mmt_si_mpt_asset_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location0 and "
                "--validate-mmt-si-mpt-asset-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_location_ipv4 &&
            validate_mmt_si_mpt_asset_id8_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-location-ipv4 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location_ipv4_nz &&
            validate_mmt_si_mpt_asset_id8_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location-ipv4-nz and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_location_ipv4_nz && !validate_mmt_si_mpt_body) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-location-ipv4-nz requires "
                "--validate-mmt-si-mpt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_location_ipv4_nz && validate_mmt_si_mpt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-location-ipv4-nz and "
                "--validate-mmt-si-mpt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset && validate_mmt_si_mpt_asset_id8_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8 && validate_mmt_si_mpt_asset_id8_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location0 && validate_mmt_si_mpt_asset_id8_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location0 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location_ipv4 && validate_mmt_si_mpt_asset_id8_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location-ipv4 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_location_ipv4 && !validate_mmt_si_mpt_body) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-location-ipv4 requires "
                "--validate-mmt-si-mpt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_location_ipv4 && validate_mmt_si_mpt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-location-ipv4 and "
                "--validate-mmt-si-mpt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset && validate_mmt_si_mpt_asset_id8_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8 && validate_mmt_si_mpt_asset_id8_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location0 && validate_mmt_si_mpt_asset_id8_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location0 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location_ipv4 && validate_mmt_si_mpt_asset_id8_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location-ipv4 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location_ipv6 && !validate_mmt_si_mpt_body) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location-ipv6 requires "
                "--validate-mmt-si-mpt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location_ipv6 && validate_mmt_si_mpt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location-ipv6 and "
                "--validate-mmt-si-mpt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset && validate_mmt_si_mpt_asset_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset and "
                "--validate-mmt-si-mpt-asset-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8 && validate_mmt_si_mpt_asset_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8 and "
                "--validate-mmt-si-mpt-asset-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location0 && validate_mmt_si_mpt_asset_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location0 and "
                "--validate-mmt-si-mpt-asset-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location_ipv4 && validate_mmt_si_mpt_asset_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location-ipv4 and "
                "--validate-mmt-si-mpt-asset-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location_ipv6 && validate_mmt_si_mpt_asset_id8_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location-ipv6 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location_ipv6 &&
            validate_mmt_si_mpt_asset_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location-ipv6 and "
                "--validate-mmt-si-mpt-asset-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location_ipv6_nz && !validate_mmt_si_mpt_body) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location-ipv6-nz requires "
                "--validate-mmt-si-mpt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location_ipv6_nz && validate_mmt_si_mpt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location-ipv6-nz and "
                "--validate-mmt-si-mpt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset && validate_mmt_si_mpt_asset_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset and "
                "--validate-mmt-si-mpt-asset-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8 && validate_mmt_si_mpt_asset_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8 and "
                "--validate-mmt-si-mpt-asset-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location0 && validate_mmt_si_mpt_asset_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location0 and "
                "--validate-mmt-si-mpt-asset-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location_ipv4_nz &&
            validate_mmt_si_mpt_asset_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location-ipv4-nz and "
                "--validate-mmt-si-mpt-asset-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_location_ipv4_nz &&
            validate_mmt_si_mpt_asset_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-location-ipv4-nz and "
                "--validate-mmt-si-mpt-asset-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location_ipv6 &&
            validate_mmt_si_mpt_asset_id8_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location-ipv6 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_location_ipv4_nz &&
            validate_mmt_si_mpt_asset_id8_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-location-ipv4-nz and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_location_ipv6_nz &&
            validate_mmt_si_mpt_asset_id8_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-location-ipv6-nz and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location_ipv6_nz &&
            validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location-ipv6-nz and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_location_ipv4_nz &&
            validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-location-ipv4-nz and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_location_ipv6_nz && !validate_mmt_si_mpt_body) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-location-ipv6-nz requires "
                "--validate-mmt-si-mpt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_location_ipv6_nz && validate_mmt_si_mpt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-location-ipv6-nz and "
                "--validate-mmt-si-mpt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset && validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8 && validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location0 && validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location0 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location_ipv4 && validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location-ipv4 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location_ipv6 && validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location-ipv6 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16 && validate_mmt_si_mpt_asset_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16 and "
                "--validate-mmt-si-mpt-asset-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_location_ipv6 && !validate_mmt_si_mpt_body) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-location-ipv6 requires "
                "--validate-mmt-si-mpt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_location_ipv6 && validate_mmt_si_mpt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-location-ipv6 and "
                "--validate-mmt-si-mpt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset && validate_mmt_si_mpt_asset_id8_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8 && validate_mmt_si_mpt_asset_id8_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location0 && validate_mmt_si_mpt_asset_id8_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location0 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location_ipv4 && validate_mmt_si_mpt_asset_id8_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location-ipv4 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location_ipv6 && validate_mmt_si_mpt_asset_id8_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location-ipv6 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_location_ipv4 && validate_mmt_si_mpt_asset_id8_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-location-ipv4 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_descriptors4 && !validate_mmt_si_mpt_body) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-descriptors4 requires "
                "--validate-mmt-si-mpt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_descriptors4 && validate_mmt_si_mpt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-descriptors4 and "
                "--validate-mmt-si-mpt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset && validate_mmt_si_mpt_asset_descriptors4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset and "
                "--validate-mmt-si-mpt-asset-descriptors4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8 && validate_mmt_si_mpt_asset_descriptors4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8 and "
                "--validate-mmt-si-mpt-asset-descriptors4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location0 && validate_mmt_si_mpt_asset_descriptors4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location0 and "
                "--validate-mmt-si-mpt-asset-descriptors4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location_ipv4 && validate_mmt_si_mpt_asset_descriptors4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location-ipv4 and "
                "--validate-mmt-si-mpt-asset-descriptors4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_location_ipv6 && validate_mmt_si_mpt_asset_descriptors4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-location-ipv6 and "
                "--validate-mmt-si-mpt-asset-descriptors4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_location_ipv4 && validate_mmt_si_mpt_asset_descriptors4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-location-ipv4 and "
                "--validate-mmt-si-mpt-asset-descriptors4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_location_ipv6_nz &&
            validate_mmt_si_mpt_asset_descriptors4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-location-ipv6-nz and "
                "--validate-mmt-si-mpt-asset-descriptors4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_location_ipv6 && validate_mmt_si_mpt_asset_descriptors4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-location-ipv6 and "
                "--validate-mmt-si-mpt-asset-descriptors4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4 && !validate_mmt_si_mpt_body) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4 requires "
                "--validate-mmt-si-mpt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4 && validate_mmt_si_mpt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4 and "
                "--validate-mmt-si-mpt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4_nz && !validate_mmt_si_mpt_body) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4-nz requires "
                "--validate-mmt-si-mpt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4_nz && validate_mmt_si_mpt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4-nz and "
                "--validate-mmt-si-mpt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6 && !validate_mmt_si_mpt_body) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6 requires "
                "--validate-mmt-si-mpt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6 && validate_mmt_si_mpt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6 and "
                "--validate-mmt-si-mpt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6_nz && !validate_mmt_si_mpt_body) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6-nz requires "
                "--validate-mmt-si-mpt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6_nz && validate_mmt_si_mpt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6-nz and "
                "--validate-mmt-si-mpt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_descriptors4 && !validate_mmt_si_mpt_body) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-descriptors4 requires "
                "--validate-mmt-si-mpt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_descriptors4 && validate_mmt_si_mpt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-descriptors4 and "
                "--validate-mmt-si-mpt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_descriptors4 && !validate_mmt_si_mpt_body) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-descriptors4 requires "
                "--validate-mmt-si-mpt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_descriptors4 && validate_mmt_si_mpt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-descriptors4 and "
                "--validate-mmt-si-mpt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4 && validate_mmt_si_mpt_asset) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4 and "
                "--validate-mmt-si-mpt-asset are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4 && validate_mmt_si_mpt_asset_descriptors4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4 and "
                "--validate-mmt-si-mpt-asset-descriptors4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4 && validate_mmt_si_mpt_asset_id8) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4 and "
                "--validate-mmt-si-mpt-asset-id8 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4 && validate_mmt_si_mpt_asset_id16) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4 and "
                "--validate-mmt-si-mpt-asset-id16 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4 && validate_mmt_si_mpt_asset_location0) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4 and "
                "--validate-mmt-si-mpt-asset-location0 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4 && validate_mmt_si_mpt_asset_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4 and "
                "--validate-mmt-si-mpt-asset-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4 && validate_mmt_si_mpt_asset_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4 and "
                "--validate-mmt-si-mpt-asset-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4 && validate_mmt_si_mpt_asset_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4 and "
                "--validate-mmt-si-mpt-asset-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4 && validate_mmt_si_mpt_asset_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4 and "
                "--validate-mmt-si-mpt-asset-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4 && validate_mmt_si_mpt_asset_id8_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4 && validate_mmt_si_mpt_asset_id8_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4 && validate_mmt_si_mpt_asset_id8_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4 && validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4 && validate_mmt_si_mpt_asset_id16_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4 and "
                "--validate-mmt-si-mpt-asset-id16-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4 && validate_mmt_si_mpt_asset_id16_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4 and "
                "--validate-mmt-si-mpt-asset-id16-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4 && validate_mmt_si_mpt_asset_id16_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4 and "
                "--validate-mmt-si-mpt-asset-id16-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4 && validate_mmt_si_mpt_asset_id16_descriptors4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4 and "
                "--validate-mmt-si-mpt-asset-id16-descriptors4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4 && validate_mmt_si_mpt_asset_id8_descriptors4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4 and "
                "--validate-mmt-si-mpt-asset-id8-descriptors4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4_nz && validate_mmt_si_mpt_asset) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4-nz and "
                "--validate-mmt-si-mpt-asset are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4_nz && validate_mmt_si_mpt_asset_descriptors4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4-nz and "
                "--validate-mmt-si-mpt-asset-descriptors4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4_nz && validate_mmt_si_mpt_asset_id8) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4-nz and "
                "--validate-mmt-si-mpt-asset-id8 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4_nz && validate_mmt_si_mpt_asset_id16) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4-nz and "
                "--validate-mmt-si-mpt-asset-id16 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4_nz && validate_mmt_si_mpt_asset_location0) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4-nz and "
                "--validate-mmt-si-mpt-asset-location0 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4_nz && validate_mmt_si_mpt_asset_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4-nz and "
                "--validate-mmt-si-mpt-asset-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4_nz && validate_mmt_si_mpt_asset_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4-nz and "
                "--validate-mmt-si-mpt-asset-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4_nz && validate_mmt_si_mpt_asset_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4-nz and "
                "--validate-mmt-si-mpt-asset-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4_nz && validate_mmt_si_mpt_asset_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4-nz and "
                "--validate-mmt-si-mpt-asset-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4_nz && validate_mmt_si_mpt_asset_id8_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4-nz and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4_nz && validate_mmt_si_mpt_asset_id8_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4-nz and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4_nz && validate_mmt_si_mpt_asset_id8_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4-nz and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4_nz && validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4-nz and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4_nz && validate_mmt_si_mpt_asset_id16_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4-nz and "
                "--validate-mmt-si-mpt-asset-id16-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4_nz && validate_mmt_si_mpt_asset_id16_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4-nz and "
                "--validate-mmt-si-mpt-asset-id16-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4_nz && validate_mmt_si_mpt_asset_id16_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4-nz and "
                "--validate-mmt-si-mpt-asset-id16-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4_nz && validate_mmt_si_mpt_asset_id16_descriptors4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4-nz and "
                "--validate-mmt-si-mpt-asset-id16-descriptors4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv4_nz && validate_mmt_si_mpt_asset_id8_descriptors4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv4-nz and "
                "--validate-mmt-si-mpt-asset-id8-descriptors4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6 && validate_mmt_si_mpt_asset) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6 and "
                "--validate-mmt-si-mpt-asset are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6 && validate_mmt_si_mpt_asset_descriptors4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6 and "
                "--validate-mmt-si-mpt-asset-descriptors4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6 && validate_mmt_si_mpt_asset_id8) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6 and "
                "--validate-mmt-si-mpt-asset-id8 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6 && validate_mmt_si_mpt_asset_id16) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6 and "
                "--validate-mmt-si-mpt-asset-id16 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6 && validate_mmt_si_mpt_asset_location0) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6 and "
                "--validate-mmt-si-mpt-asset-location0 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6 && validate_mmt_si_mpt_asset_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6 and "
                "--validate-mmt-si-mpt-asset-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6 && validate_mmt_si_mpt_asset_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6 and "
                "--validate-mmt-si-mpt-asset-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6 && validate_mmt_si_mpt_asset_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6 and "
                "--validate-mmt-si-mpt-asset-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6 && validate_mmt_si_mpt_asset_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6 and "
                "--validate-mmt-si-mpt-asset-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6 && validate_mmt_si_mpt_asset_id8_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6 && validate_mmt_si_mpt_asset_id8_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6 && validate_mmt_si_mpt_asset_id8_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6 && validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6 && validate_mmt_si_mpt_asset_id16_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6 and "
                "--validate-mmt-si-mpt-asset-id16-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6 && validate_mmt_si_mpt_asset_id16_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6 and "
                "--validate-mmt-si-mpt-asset-id16-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6 && validate_mmt_si_mpt_asset_id16_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6 and "
                "--validate-mmt-si-mpt-asset-id16-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6 && validate_mmt_si_mpt_asset_id16_descriptors4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6 and "
                "--validate-mmt-si-mpt-asset-id16-descriptors4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6 && validate_mmt_si_mpt_asset_id8_descriptors4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6 and "
                "--validate-mmt-si-mpt-asset-id8-descriptors4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6_nz && validate_mmt_si_mpt_asset) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6-nz and "
                "--validate-mmt-si-mpt-asset are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6_nz && validate_mmt_si_mpt_asset_descriptors4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6-nz and "
                "--validate-mmt-si-mpt-asset-descriptors4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6_nz && validate_mmt_si_mpt_asset_id8) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6-nz and "
                "--validate-mmt-si-mpt-asset-id8 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6_nz && validate_mmt_si_mpt_asset_id16) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6-nz and "
                "--validate-mmt-si-mpt-asset-id16 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6_nz && validate_mmt_si_mpt_asset_location0) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6-nz and "
                "--validate-mmt-si-mpt-asset-location0 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6_nz && validate_mmt_si_mpt_asset_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6-nz and "
                "--validate-mmt-si-mpt-asset-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6_nz && validate_mmt_si_mpt_asset_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6-nz and "
                "--validate-mmt-si-mpt-asset-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6_nz && validate_mmt_si_mpt_asset_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6-nz and "
                "--validate-mmt-si-mpt-asset-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6_nz && validate_mmt_si_mpt_asset_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6-nz and "
                "--validate-mmt-si-mpt-asset-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6_nz && validate_mmt_si_mpt_asset_id8_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6-nz and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6_nz && validate_mmt_si_mpt_asset_id8_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6-nz and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6_nz && validate_mmt_si_mpt_asset_id8_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6-nz and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6_nz && validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6-nz and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6_nz && validate_mmt_si_mpt_asset_id16_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6-nz and "
                "--validate-mmt-si-mpt-asset-id16-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6_nz && validate_mmt_si_mpt_asset_id16_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6-nz and "
                "--validate-mmt-si-mpt-asset-id16-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6_nz && validate_mmt_si_mpt_asset_id16_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6-nz and "
                "--validate-mmt-si-mpt-asset-id16-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6_nz && validate_mmt_si_mpt_asset_id16_descriptors4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6-nz and "
                "--validate-mmt-si-mpt-asset-id16-descriptors4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_location_ipv6_nz && validate_mmt_si_mpt_asset_id8_descriptors4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-location-ipv6-nz and "
                "--validate-mmt-si-mpt-asset-id8-descriptors4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_descriptors4 && validate_mmt_si_mpt_asset) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-descriptors4 and "
                "--validate-mmt-si-mpt-asset are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_descriptors4 && validate_mmt_si_mpt_asset_descriptors4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-descriptors4 and "
                "--validate-mmt-si-mpt-asset-descriptors4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_descriptors4 && validate_mmt_si_mpt_asset_id8) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-descriptors4 and "
                "--validate-mmt-si-mpt-asset-id8 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_descriptors4 && validate_mmt_si_mpt_asset_id16) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-descriptors4 and "
                "--validate-mmt-si-mpt-asset-id16 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_descriptors4 && validate_mmt_si_mpt_asset_location0) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-descriptors4 and "
                "--validate-mmt-si-mpt-asset-location0 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_descriptors4 && validate_mmt_si_mpt_asset_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-descriptors4 and "
                "--validate-mmt-si-mpt-asset-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_descriptors4 && validate_mmt_si_mpt_asset_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-descriptors4 and "
                "--validate-mmt-si-mpt-asset-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_descriptors4 && validate_mmt_si_mpt_asset_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-descriptors4 and "
                "--validate-mmt-si-mpt-asset-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_descriptors4 && validate_mmt_si_mpt_asset_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-descriptors4 and "
                "--validate-mmt-si-mpt-asset-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_descriptors4 && validate_mmt_si_mpt_asset_id8_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-descriptors4 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_descriptors4 && validate_mmt_si_mpt_asset_id8_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-descriptors4 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_descriptors4 && validate_mmt_si_mpt_asset_id8_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-descriptors4 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_descriptors4 && validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-descriptors4 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_descriptors4 && validate_mmt_si_mpt_asset_id16_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-descriptors4 and "
                "--validate-mmt-si-mpt-asset-id16-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_descriptors4 && validate_mmt_si_mpt_asset_id16_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-descriptors4 and "
                "--validate-mmt-si-mpt-asset-id16-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_descriptors4 && validate_mmt_si_mpt_asset_id16_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-descriptors4 and "
                "--validate-mmt-si-mpt-asset-id16-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_descriptors4 && validate_mmt_si_mpt_asset_id16_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-descriptors4 and "
                "--validate-mmt-si-mpt-asset-id16-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id16_descriptors4 && validate_mmt_si_mpt_asset_id8_descriptors4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id16-descriptors4 and "
                "--validate-mmt-si-mpt-asset-id8-descriptors4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_descriptors4 && validate_mmt_si_mpt_asset) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-descriptors4 and "
                "--validate-mmt-si-mpt-asset are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_descriptors4 && validate_mmt_si_mpt_asset_descriptors4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-descriptors4 and "
                "--validate-mmt-si-mpt-asset-descriptors4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_descriptors4 && validate_mmt_si_mpt_asset_id8) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-descriptors4 and "
                "--validate-mmt-si-mpt-asset-id8 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_descriptors4 && validate_mmt_si_mpt_asset_id16) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-descriptors4 and "
                "--validate-mmt-si-mpt-asset-id16 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_descriptors4 && validate_mmt_si_mpt_asset_location0) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-descriptors4 and "
                "--validate-mmt-si-mpt-asset-location0 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_descriptors4 && validate_mmt_si_mpt_asset_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-descriptors4 and "
                "--validate-mmt-si-mpt-asset-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_descriptors4 && validate_mmt_si_mpt_asset_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-descriptors4 and "
                "--validate-mmt-si-mpt-asset-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_descriptors4 && validate_mmt_si_mpt_asset_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-descriptors4 and "
                "--validate-mmt-si-mpt-asset-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_descriptors4 && validate_mmt_si_mpt_asset_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-descriptors4 and "
                "--validate-mmt-si-mpt-asset-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_descriptors4 && validate_mmt_si_mpt_asset_id8_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-descriptors4 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_descriptors4 && validate_mmt_si_mpt_asset_id8_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-descriptors4 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_descriptors4 && validate_mmt_si_mpt_asset_id8_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-descriptors4 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_descriptors4 && validate_mmt_si_mpt_asset_id8_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-descriptors4 and "
                "--validate-mmt-si-mpt-asset-id8-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_descriptors4 && validate_mmt_si_mpt_asset_id16_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-descriptors4 and "
                "--validate-mmt-si-mpt-asset-id16-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_descriptors4 && validate_mmt_si_mpt_asset_id16_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-descriptors4 and "
                "--validate-mmt-si-mpt-asset-id16-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_descriptors4 && validate_mmt_si_mpt_asset_id16_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-descriptors4 and "
                "--validate-mmt-si-mpt-asset-id16-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_descriptors4 && validate_mmt_si_mpt_asset_id16_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-descriptors4 and "
                "--validate-mmt-si-mpt-asset-id16-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_mpt_asset_id8_descriptors4 && validate_mmt_si_mpt_asset_id16_descriptors4) {
            mlog.error(
                "--validate-mmt-si-mpt-asset-id8-descriptors4 and "
                "--validate-mmt-si-mpt-asset-id16-descriptors4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_body_prefix && !validate_mmt_si_plt_body) {
            mlog.error(
                "--validate-mmt-si-plt-table-body-prefix requires "
                "--validate-mmt-si-plt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery && !validate_mmt_si_plt_body) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info requires "
                "--validate-mmt-si-plt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery && validate_mmt_si_plt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info and "
                "--validate-mmt-si-plt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv4 && !validate_mmt_si_plt_body) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv4 requires "
                "--validate-mmt-si-plt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv4 && validate_mmt_si_plt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv4 and "
                "--validate-mmt-si-plt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery && validate_mmt_si_plt_delivery_ipv4) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info and "
                "--validate-mmt-si-plt-delivery-info-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv6 && !validate_mmt_si_plt_body) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv6 requires "
                "--validate-mmt-si-plt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv6 && validate_mmt_si_plt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv6 and "
                "--validate-mmt-si-plt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery && validate_mmt_si_plt_delivery_ipv6) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info and "
                "--validate-mmt-si-plt-delivery-info-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv4 && validate_mmt_si_plt_delivery_ipv6) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv4 and "
                "--validate-mmt-si-plt-delivery-info-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv4 && validate_mmt_si_plt_delivery_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv4 and "
                "--validate-mmt-si-plt-delivery-info-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv4_nz && !validate_mmt_si_plt_body) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv4-nz requires "
                "--validate-mmt-si-plt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv4_nz && validate_mmt_si_plt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv4-nz and "
                "--validate-mmt-si-plt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery && validate_mmt_si_plt_delivery_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info and "
                "--validate-mmt-si-plt-delivery-info-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv6 && validate_mmt_si_plt_delivery_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv6 and "
                "--validate-mmt-si-plt-delivery-info-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url && !validate_mmt_si_plt_body) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url requires "
                "--validate-mmt-si-plt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url && validate_mmt_si_plt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url and "
                "--validate-mmt-si-plt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery && validate_mmt_si_plt_delivery_url) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info and "
                "--validate-mmt-si-plt-delivery-info-url are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv4 && validate_mmt_si_plt_delivery_url) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv4 and "
                "--validate-mmt-si-plt-delivery-info-url are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv6 && validate_mmt_si_plt_delivery_url) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv6 and "
                "--validate-mmt-si-plt-delivery-info-url are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry && !validate_mmt_si_plt_body) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry requires "
                "--validate-mmt-si-plt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry && validate_mmt_si_plt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry and "
                "--validate-mmt-si-plt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery && validate_mmt_si_plt_package_entry) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info and "
                "--validate-mmt-si-plt-package-entry are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv4 && validate_mmt_si_plt_package_entry) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv4 and "
                "--validate-mmt-si-plt-package-entry are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv6 && validate_mmt_si_plt_package_entry) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv6 and "
                "--validate-mmt-si-plt-package-entry are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url && validate_mmt_si_plt_package_entry) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url and "
                "--validate-mmt-si-plt-package-entry are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url_3 && !validate_mmt_si_plt_body) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url-3 requires "
                "--validate-mmt-si-plt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url_3 && validate_mmt_si_plt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url-3 and "
                "--validate-mmt-si-plt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery && validate_mmt_si_plt_delivery_url_3) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info and "
                "--validate-mmt-si-plt-delivery-info-url-3 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv4 && validate_mmt_si_plt_delivery_url_3) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv4 and "
                "--validate-mmt-si-plt-delivery-info-url-3 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv6 && validate_mmt_si_plt_delivery_url_3) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv6 and "
                "--validate-mmt-si-plt-delivery-info-url-3 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url && validate_mmt_si_plt_delivery_url_3) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url and "
                "--validate-mmt-si-plt-delivery-info-url-3 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url_3 && validate_mmt_si_plt_package_entry) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url-3 and "
                "--validate-mmt-si-plt-package-entry are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url_4 && !validate_mmt_si_plt_body) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url-4 requires "
                "--validate-mmt-si-plt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url_4 && validate_mmt_si_plt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url-4 and "
                "--validate-mmt-si-plt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery && validate_mmt_si_plt_delivery_url_4) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info and "
                "--validate-mmt-si-plt-delivery-info-url-4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv4 && validate_mmt_si_plt_delivery_url_4) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv4 and "
                "--validate-mmt-si-plt-delivery-info-url-4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv6 && validate_mmt_si_plt_delivery_url_4) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv6 and "
                "--validate-mmt-si-plt-delivery-info-url-4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url && validate_mmt_si_plt_delivery_url_4) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url and "
                "--validate-mmt-si-plt-delivery-info-url-4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url_3 && validate_mmt_si_plt_delivery_url_4) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url-3 and "
                "--validate-mmt-si-plt-delivery-info-url-4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url_4 && validate_mmt_si_plt_package_entry) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url-4 and "
                "--validate-mmt-si-plt-package-entry are mutually exclusive");
            co_return 2;
        }

        if (validate_mmt_si_plt_delivery_ipv4_nz && validate_mmt_si_plt_delivery_url) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv4-nz and "
                "--validate-mmt-si-plt-delivery-info-url are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv4_nz && validate_mmt_si_plt_delivery_url_3) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv4-nz and "
                "--validate-mmt-si-plt-delivery-info-url-3 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv4_nz && validate_mmt_si_plt_delivery_url_4) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv4-nz and "
                "--validate-mmt-si-plt-delivery-info-url-4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv4_nz && validate_mmt_si_plt_package_entry) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv4-nz and "
                "--validate-mmt-si-plt-package-entry are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv4_nz && validate_mmt_si_plt_package_entry_id8) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv4-nz and "
                "--validate-mmt-si-plt-package-entry-id8 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv4_nz && validate_mmt_si_plt_package_entry_ipv4) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv4-nz and "
                "--validate-mmt-si-plt-package-entry-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv4_nz &&
            validate_mmt_si_plt_package_entry_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv4-nz and "
                "--validate-mmt-si-plt-package-entry-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_ipv4_nz && !validate_mmt_si_plt_body) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-ipv4-nz requires "
                "--validate-mmt-si-plt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_ipv4_nz && validate_mmt_si_plt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-ipv4-nz and "
                "--validate-mmt-si-plt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery && validate_mmt_si_plt_package_entry_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info and "
                "--validate-mmt-si-plt-package-entry-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv4 && validate_mmt_si_plt_package_entry_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv4 and "
                "--validate-mmt-si-plt-package-entry-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv6 && validate_mmt_si_plt_package_entry_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv6 and "
                "--validate-mmt-si-plt-package-entry-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url && validate_mmt_si_plt_package_entry_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url and "
                "--validate-mmt-si-plt-package-entry-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url_3 && validate_mmt_si_plt_package_entry_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url-3 and "
                "--validate-mmt-si-plt-package-entry-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry && validate_mmt_si_plt_package_entry_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry and "
                "--validate-mmt-si-plt-package-entry-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8 && validate_mmt_si_plt_package_entry_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8 and "
                "--validate-mmt-si-plt-package-entry-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_ipv4 && validate_mmt_si_plt_package_entry_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-ipv4 and "
                "--validate-mmt-si-plt-package-entry-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8 && !validate_mmt_si_plt_body) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8 requires "
                "--validate-mmt-si-plt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8 && validate_mmt_si_plt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8 and "
                "--validate-mmt-si-plt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery && validate_mmt_si_plt_package_entry_id8) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info and "
                "--validate-mmt-si-plt-package-entry-id8 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv4 && validate_mmt_si_plt_package_entry_id8) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv4 and "
                "--validate-mmt-si-plt-package-entry-id8 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv6 && validate_mmt_si_plt_package_entry_id8) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv6 and "
                "--validate-mmt-si-plt-package-entry-id8 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url && validate_mmt_si_plt_package_entry_id8) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url and "
                "--validate-mmt-si-plt-package-entry-id8 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url_3 && validate_mmt_si_plt_package_entry_id8) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url-3 and "
                "--validate-mmt-si-plt-package-entry-id8 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url_4 && validate_mmt_si_plt_package_entry_id8) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url-4 and "
                "--validate-mmt-si-plt-package-entry-id8 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry && validate_mmt_si_plt_package_entry_id8) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry and "
                "--validate-mmt-si-plt-package-entry-id8 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_ipv4 && !validate_mmt_si_plt_body) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-ipv4 requires "
                "--validate-mmt-si-plt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_ipv4 && validate_mmt_si_plt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-ipv4 and "
                "--validate-mmt-si-plt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery && validate_mmt_si_plt_package_entry_ipv4) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info and "
                "--validate-mmt-si-plt-package-entry-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv4 && validate_mmt_si_plt_package_entry_ipv4) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv4 and "
                "--validate-mmt-si-plt-package-entry-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv6 && validate_mmt_si_plt_package_entry_ipv4) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv6 and "
                "--validate-mmt-si-plt-package-entry-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url && validate_mmt_si_plt_package_entry_ipv4) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url and "
                "--validate-mmt-si-plt-package-entry-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url_3 && validate_mmt_si_plt_package_entry_ipv4) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url-3 and "
                "--validate-mmt-si-plt-package-entry-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry && validate_mmt_si_plt_package_entry_ipv4) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry and "
                "--validate-mmt-si-plt-package-entry-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8 && validate_mmt_si_plt_package_entry_ipv4) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8 and "
                "--validate-mmt-si-plt-package-entry-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8_location_ipv4 &&
            !validate_mmt_si_plt_body) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4 requires "
                "--validate-mmt-si-plt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8_location_ipv4 &&
            validate_mmt_si_plt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4 and "
                "--validate-mmt-si-plt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery && validate_mmt_si_plt_package_entry_id8_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv4 &&
            validate_mmt_si_plt_package_entry_id8_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv4 and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv6 &&
            validate_mmt_si_plt_package_entry_id8_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv6 and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url &&
            validate_mmt_si_plt_package_entry_id8_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url_3 &&
            validate_mmt_si_plt_package_entry_id8_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url-3 and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry &&
            validate_mmt_si_plt_package_entry_id8_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8 &&
            validate_mmt_si_plt_package_entry_id8_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8 and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_ipv4 &&
            validate_mmt_si_plt_package_entry_id8_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-ipv4 and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_ipv4_nz &&
            validate_mmt_si_plt_package_entry_id8_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-ipv4-nz and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8_location_ipv4 &&
            validate_mmt_si_plt_package_entry_id8_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4 and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_ipv4_nz &&
            validate_mmt_si_plt_package_entry_id8_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-ipv4-nz and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8_location_ipv4_nz &&
            !validate_mmt_si_plt_body) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4-nz requires "
                "--validate-mmt-si-plt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8_location_ipv4_nz &&
            validate_mmt_si_plt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4-nz and "
                "--validate-mmt-si-plt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery &&
            validate_mmt_si_plt_package_entry_id8_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv4 &&
            validate_mmt_si_plt_package_entry_id8_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv4 and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv6 &&
            validate_mmt_si_plt_package_entry_id8_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv6 and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url &&
            validate_mmt_si_plt_package_entry_id8_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url_3 &&
            validate_mmt_si_plt_package_entry_id8_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url-3 and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry &&
            validate_mmt_si_plt_package_entry_id8_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8 &&
            validate_mmt_si_plt_package_entry_id8_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8 and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_ipv4 &&
            validate_mmt_si_plt_package_entry_id8_location_ipv4_nz) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-ipv4 and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_ipv6 &&
            validate_mmt_si_plt_package_entry_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-ipv6 and "
                "--validate-mmt-si-plt-package-entry-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_ipv6_nz && !validate_mmt_si_plt_body) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-ipv6-nz requires "
                "--validate-mmt-si-plt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_ipv6_nz && validate_mmt_si_plt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-ipv6-nz and "
                "--validate-mmt-si-plt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery && validate_mmt_si_plt_package_entry_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info and "
                "--validate-mmt-si-plt-package-entry-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv4 && validate_mmt_si_plt_package_entry_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv4 and "
                "--validate-mmt-si-plt-package-entry-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv6 && validate_mmt_si_plt_package_entry_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv6 and "
                "--validate-mmt-si-plt-package-entry-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url && validate_mmt_si_plt_package_entry_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url and "
                "--validate-mmt-si-plt-package-entry-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url_3 && validate_mmt_si_plt_package_entry_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url-3 and "
                "--validate-mmt-si-plt-package-entry-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry && validate_mmt_si_plt_package_entry_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry and "
                "--validate-mmt-si-plt-package-entry-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8 && validate_mmt_si_plt_package_entry_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8 and "
                "--validate-mmt-si-plt-package-entry-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_ipv4 && validate_mmt_si_plt_package_entry_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-ipv4 and "
                "--validate-mmt-si-plt-package-entry-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_ipv4_nz &&
            validate_mmt_si_plt_package_entry_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-ipv4-nz and "
                "--validate-mmt-si-plt-package-entry-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8_location_ipv4_nz &&
            validate_mmt_si_plt_package_entry_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4-nz and "
                "--validate-mmt-si-plt-package-entry-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8_location_ipv6 &&
            validate_mmt_si_plt_package_entry_id8_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6 and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8_location_ipv6_nz &&
            !validate_mmt_si_plt_body) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6-nz requires "
                "--validate-mmt-si-plt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8_location_ipv6_nz &&
            validate_mmt_si_plt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6-nz and "
                "--validate-mmt-si-plt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery &&
            validate_mmt_si_plt_package_entry_id8_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv4 &&
            validate_mmt_si_plt_package_entry_id8_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv4 and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv6 &&
            validate_mmt_si_plt_package_entry_id8_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv6 and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url &&
            validate_mmt_si_plt_package_entry_id8_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url_3 &&
            validate_mmt_si_plt_package_entry_id8_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url-3 and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry &&
            validate_mmt_si_plt_package_entry_id8_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8 &&
            validate_mmt_si_plt_package_entry_id8_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8 and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_ipv4 &&
            validate_mmt_si_plt_package_entry_id8_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-ipv4 and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_ipv4_nz &&
            validate_mmt_si_plt_package_entry_id8_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-ipv4-nz and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8_location_ipv4 &&
            validate_mmt_si_plt_package_entry_id8_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4 and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8_location_ipv4_nz &&
            validate_mmt_si_plt_package_entry_id8_location_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4-nz and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8_location_ipv6_nz &&
            validate_mmt_si_plt_package_entry_ipv6_nz) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6-nz and "
                "--validate-mmt-si-plt-package-entry-ipv6-nz are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_ipv6 && !validate_mmt_si_plt_body) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-ipv6 requires "
                "--validate-mmt-si-plt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_ipv6 && validate_mmt_si_plt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-ipv6 and "
                "--validate-mmt-si-plt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery && validate_mmt_si_plt_package_entry_ipv6) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info and "
                "--validate-mmt-si-plt-package-entry-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv4 && validate_mmt_si_plt_package_entry_ipv6) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv4 and "
                "--validate-mmt-si-plt-package-entry-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv6 && validate_mmt_si_plt_package_entry_ipv6) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv6 and "
                "--validate-mmt-si-plt-package-entry-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url && validate_mmt_si_plt_package_entry_ipv6) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url and "
                "--validate-mmt-si-plt-package-entry-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url_3 && validate_mmt_si_plt_package_entry_ipv6) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url-3 and "
                "--validate-mmt-si-plt-package-entry-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry && validate_mmt_si_plt_package_entry_ipv6) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry and "
                "--validate-mmt-si-plt-package-entry-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8 && validate_mmt_si_plt_package_entry_ipv6) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8 and "
                "--validate-mmt-si-plt-package-entry-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_ipv4 && validate_mmt_si_plt_package_entry_ipv6) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-ipv4 and "
                "--validate-mmt-si-plt-package-entry-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8_location_ipv4 &&
            validate_mmt_si_plt_package_entry_ipv6) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4 and "
                "--validate-mmt-si-plt-package-entry-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8_location_ipv4_nz &&
            validate_mmt_si_plt_package_entry_ipv6) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4-nz and "
                "--validate-mmt-si-plt-package-entry-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8_location_ipv6_nz &&
            validate_mmt_si_plt_package_entry_ipv6) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6-nz and "
                "--validate-mmt-si-plt-package-entry-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8_location_ipv6 &&
            !validate_mmt_si_plt_body) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6 requires "
                "--validate-mmt-si-plt-table-body");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8_location_ipv6 &&
            validate_mmt_si_plt_body_prefix) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6 and "
                "--validate-mmt-si-plt-table-body-prefix are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery &&
            validate_mmt_si_plt_package_entry_id8_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv4 &&
            validate_mmt_si_plt_package_entry_id8_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv4 and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_ipv6 &&
            validate_mmt_si_plt_package_entry_id8_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-ipv6 and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url &&
            validate_mmt_si_plt_package_entry_id8_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url_3 &&
            validate_mmt_si_plt_package_entry_id8_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url-3 and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url_4 &&
            validate_mmt_si_plt_package_entry_ipv4) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url-4 and "
                "--validate-mmt-si-plt-package-entry-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url_4 &&
            validate_mmt_si_plt_package_entry_id8_location_ipv4) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url-4 and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url_4 &&
            validate_mmt_si_plt_package_entry_ipv6) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url-4 and "
                "--validate-mmt-si-plt-package-entry-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_delivery_url_4 &&
            validate_mmt_si_plt_package_entry_id8_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-plt-delivery-info-url-4 and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry &&
            validate_mmt_si_plt_package_entry_id8_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8 &&
            validate_mmt_si_plt_package_entry_id8_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8 and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_ipv4 &&
            validate_mmt_si_plt_package_entry_id8_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-ipv4 and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8_location_ipv4 &&
            validate_mmt_si_plt_package_entry_id8_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4 and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8_location_ipv4_nz &&
            validate_mmt_si_plt_package_entry_id8_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8-location-ipv4-nz and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_id8_location_ipv6_nz &&
            validate_mmt_si_plt_package_entry_id8_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6-nz and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        if (validate_mmt_si_plt_package_entry_ipv6 &&
            validate_mmt_si_plt_package_entry_id8_location_ipv6) {
            mlog.error(
                "--validate-mmt-si-plt-package-entry-ipv6 and "
                "--validate-mmt-si-plt-package-entry-id8-location-ipv6 are mutually exclusive");
            co_return 2;
        }
        std::vector<atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row>
            pa_hdr_rows;
        if (prepend_mmt_si_pa_hdr && cfg.count("mmtp-si-pa-table-row") != 0) {
            for (const auto& tok :
                 cfg["mmtp-si-pa-table-row"].as<std::vector<std::string>>()) {
                atsc3::gw::encoder_pipeline::config::mmt_si_pa_table_header_row row{};
                if (!parse_mmtp_si_pa_table_row(tok, &row)) {
                    mlog.error(
                        "invalid --mmtp-si-pa-table-row (want ID:VERSION:LENGTH per token)");
                    co_return 2;
                }
                pa_hdr_rows.push_back(row);
            }
        }
        std::vector<std::vector<std::byte>> mmtp_sig_agg_bodies;
        std::vector<std::vector<std::byte>> mmtp_iso_agg_bodies;
        std::vector<std::byte> mmtp_ext_value_legacy;
        if (prepend_mmtp_ext && cfg.count("mmtp-extension") == 0) {
            if (!parse_even_hex_bytes(mmtp_ext_hex, &mmtp_ext_value_legacy)) {
                mlog.error(
                    "--mmtp-extension-hex must be even-length hex (optional 0x "
                    "prefix)");
                co_return 2;
            }
        }
        if (prepend_mmtp_sig && cfg.count("mmtp-signalling-aggregate-hex") != 0) {
            for (const auto& hx :
                 cfg["mmtp-signalling-aggregate-hex"].as<std::vector<std::string>>()) {
                std::vector<std::byte> seg;
                if (!parse_even_hex_bytes(hx, &seg)) {
                    mlog.error(
                        "--mmtp-signalling-aggregate-hex entries must be "
                        "even-length hex (optional 0x prefix)");
                    co_return 2;
                }
                mmtp_sig_agg_bodies.push_back(std::move(seg));
            }
        }
        if (prepend_mmtp_isobmff && cfg.count("mmtp-isobmff-aggregate-hex") != 0) {
            for (const auto& hx :
                 cfg["mmtp-isobmff-aggregate-hex"].as<std::vector<std::string>>()) {
                std::vector<std::byte> seg;
                if (!parse_even_hex_bytes(hx, &seg)) {
                    mlog.error(
                        "--mmtp-isobmff-aggregate-hex entries must be "
                        "even-length hex (optional 0x prefix)");
                    co_return 2;
                }
                mmtp_iso_agg_bodies.push_back(std::move(seg));
            }
        }
        if (cp_in > std::numeric_limits<std::uint8_t>::max()) {
            mlog.error("--lct-codepoint must be <= 255");
            co_return 2;
        }
        atsc3::gw::encoder_pipeline::config enc_cfg{};
        if (prepend_lct) {
            if (lct_include_tsi && lct_include_toi) {
                enc_cfg = atsc3::gw::with_prepended_lab_lct_word0_tsi_toi(
                    static_cast<std::uint8_t>(cp_in), lct_tsi, lct_toi);
            } else if (lct_include_tsi) {
                enc_cfg = atsc3::gw::with_prepended_lab_lct_word0_tsi(
                    static_cast<std::uint8_t>(cp_in), lct_tsi);
            } else if (lct_include_toi) {
                enc_cfg = atsc3::gw::with_prepended_lab_lct_word0_toi(
                    static_cast<std::uint8_t>(cp_in), lct_toi);
            } else {
                enc_cfg = atsc3::gw::with_prepended_lab_lct_word0(
                    static_cast<std::uint8_t>(cp_in));
            }
        }
        if (prepend_mmtp) {
            enc_cfg = atsc3::gw::with_prepended_lab_mmtp_word0(
                static_cast<std::uint8_t>(mmtp_pt_in),
                static_cast<std::uint16_t>(mmtp_pid_in), std::move(enc_cfg));
            if (prepend_mmtp_ts_psn) {
                enc_cfg = atsc3::gw::with_prepended_lab_mmtp_ts_psn(
                    mmtp_ts, mmtp_psn, std::move(enc_cfg));
            }
            if (prepend_mmtp_pkt_ctr) {
                enc_cfg = atsc3::gw::with_prepended_lab_mmtp_packet_counter(
                    mmtp_pkt_ctr, std::move(enc_cfg));
            }
            if (prepend_mmtp_ext) {
                std::vector<atsc3::gw::mmtp_extension_tlv> tlvs;
                if (cfg.count("mmtp-extension") != 0) {
                    for (const auto& spec :
                         cfg["mmtp-extension"].as<std::vector<std::string>>()) {
                        std::uint16_t et = 0;
                        std::vector<std::byte> ev;
                        if (!parse_mmtp_extension_spec(spec, &et, &ev)) {
                            mlog.error(
                                "invalid --mmtp-extension (want TYPE:HEX per TLV, "
                                "hex even-length or empty)");
                            co_return 2;
                        }
                        tlvs.push_back(
                            atsc3::gw::mmtp_extension_tlv{et, std::move(ev)});
                    }
                } else {
                    tlvs.push_back(atsc3::gw::mmtp_extension_tlv{
                        static_cast<std::uint16_t>(mmtp_ext_type_in),
                        std::move(mmtp_ext_value_legacy)});
                }
                enc_cfg.mmtp_extensions = std::move(tlvs);
            }
            if (prepend_mmtp_sig) {
                atsc3::mmtp_payload_signalling_prefix::decoded_t mmtp_sig_dec{};
                mmtp_sig_dec.fragmentation_indicator =
                    static_cast<std::uint8_t>(mmtp_sig_fi);
                mmtp_sig_dec.reserved = static_cast<std::uint8_t>(mmtp_sig_res);
                mmtp_sig_dec.length_extension_flag = mmtp_sig_len_ext;
                mmtp_sig_dec.aggregation_flag      = mmtp_sig_agg;
                mmtp_sig_dec.fragment_counter =
                    static_cast<std::uint8_t>(mmtp_sig_frag_ctr);
                enc_cfg = atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
                    mmtp_sig_dec, std::move(enc_cfg));
                enc_cfg.mmtp_signalling_aggregate_bodies =
                    std::move(mmtp_sig_agg_bodies);
                enc_cfg.prepend_mmt_si_length32_envelope = prepend_mmt_si_len32;
                enc_cfg.prepend_mmt_si_descriptor_loop_u32 = prepend_mmt_si_desc_u32;
                enc_cfg.prepend_mmt_si_message_header_len32 = prepend_mmt_si_msg_hdr;
                enc_cfg.mmt_si_message_id =
                    static_cast<std::uint16_t>(mmtp_si_msg_id_in);
                enc_cfg.mmt_si_message_version =
                    static_cast<std::uint8_t>(mmtp_si_msg_ver_in);
                enc_cfg.prepend_mmt_si_pa_table_headers = prepend_mmt_si_pa_hdr;
                enc_cfg.mmt_si_pa_table_header_rows   = std::move(pa_hdr_rows);
                enc_cfg.validate_mmt_si_mpt_table_body = validate_mmt_si_mpt_body;
                enc_cfg.validate_mmt_si_plt_table_body = validate_mmt_si_plt_body;
                enc_cfg.validate_mmt_si_mpt_table_body_prefix =
                    validate_mmt_si_mpt_body_prefix;
                enc_cfg.validate_mmt_si_mpt_asset = validate_mmt_si_mpt_asset;
                enc_cfg.validate_mmt_si_mpt_asset_descriptors4 =
                    validate_mmt_si_mpt_asset_descriptors4;
                enc_cfg.validate_mmt_si_mpt_asset_id8 = validate_mmt_si_mpt_asset_id8;
                enc_cfg.validate_mmt_si_mpt_asset_id16 = validate_mmt_si_mpt_asset_id16;
                enc_cfg.validate_mmt_si_mpt_asset_location0 =
                    validate_mmt_si_mpt_asset_location0;
                enc_cfg.validate_mmt_si_mpt_asset_location_ipv4 =
                    validate_mmt_si_mpt_asset_location_ipv4;
                enc_cfg.validate_mmt_si_mpt_asset_location_ipv4_nz =
                    validate_mmt_si_mpt_asset_location_ipv4_nz;
                enc_cfg.validate_mmt_si_mpt_asset_location_ipv6 =
                    validate_mmt_si_mpt_asset_location_ipv6;
                enc_cfg.validate_mmt_si_mpt_asset_location_ipv6_nz =
                    validate_mmt_si_mpt_asset_location_ipv6_nz;
                enc_cfg.validate_mmt_si_mpt_asset_id8_location_ipv4 =
                    validate_mmt_si_mpt_asset_id8_location_ipv4;
                enc_cfg.validate_mmt_si_mpt_asset_id8_location_ipv4_nz =
                    validate_mmt_si_mpt_asset_id8_location_ipv4_nz;
                enc_cfg.validate_mmt_si_mpt_asset_id8_location_ipv6 =
                    validate_mmt_si_mpt_asset_id8_location_ipv6;
                enc_cfg.validate_mmt_si_mpt_asset_id8_location_ipv6_nz =
                    validate_mmt_si_mpt_asset_id8_location_ipv6_nz;
                enc_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4 =
                    validate_mmt_si_mpt_asset_id16_location_ipv4;
                enc_cfg.validate_mmt_si_mpt_asset_id16_location_ipv4_nz =
                    validate_mmt_si_mpt_asset_id16_location_ipv4_nz;
                enc_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6 =
                    validate_mmt_si_mpt_asset_id16_location_ipv6;
                enc_cfg.validate_mmt_si_mpt_asset_id16_location_ipv6_nz =
                    validate_mmt_si_mpt_asset_id16_location_ipv6_nz;
                enc_cfg.validate_mmt_si_mpt_asset_id16_descriptors4 =
                    validate_mmt_si_mpt_asset_id16_descriptors4;
                enc_cfg.validate_mmt_si_mpt_asset_id8_descriptors4 =
                    validate_mmt_si_mpt_asset_id8_descriptors4;
                enc_cfg.validate_mmt_si_plt_table_body_prefix =
                    validate_mmt_si_plt_body_prefix;
                enc_cfg.validate_mmt_si_plt_delivery_info =
                    validate_mmt_si_plt_delivery;
                enc_cfg.validate_mmt_si_plt_delivery_info_ipv4 =
                    validate_mmt_si_plt_delivery_ipv4;
                enc_cfg.validate_mmt_si_plt_delivery_info_ipv6 =
                    validate_mmt_si_plt_delivery_ipv6;
                enc_cfg.validate_mmt_si_plt_delivery_info_url =
                    validate_mmt_si_plt_delivery_url;
                enc_cfg.validate_mmt_si_plt_delivery_info_url_3 =
                    validate_mmt_si_plt_delivery_url_3;
                enc_cfg.validate_mmt_si_plt_delivery_info_url_4 =
                    validate_mmt_si_plt_delivery_url_4;
                enc_cfg.validate_mmt_si_plt_delivery_info_ipv4_nz =
                    validate_mmt_si_plt_delivery_ipv4_nz;
                enc_cfg.validate_mmt_si_plt_package_entry =
                    validate_mmt_si_plt_package_entry;
                enc_cfg.validate_mmt_si_plt_package_entry_id8 =
                    validate_mmt_si_plt_package_entry_id8;
                enc_cfg.validate_mmt_si_plt_package_entry_ipv4 =
                    validate_mmt_si_plt_package_entry_ipv4;
                enc_cfg.validate_mmt_si_plt_package_entry_ipv4_nz =
                    validate_mmt_si_plt_package_entry_ipv4_nz;
                enc_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4 =
                    validate_mmt_si_plt_package_entry_id8_location_ipv4;
                enc_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv4_nz =
                    validate_mmt_si_plt_package_entry_id8_location_ipv4_nz;
                enc_cfg.validate_mmt_si_plt_package_entry_ipv6 =
                    validate_mmt_si_plt_package_entry_ipv6;
                enc_cfg.validate_mmt_si_plt_package_entry_ipv6_nz =
                    validate_mmt_si_plt_package_entry_ipv6_nz;
                enc_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6 =
                    validate_mmt_si_plt_package_entry_id8_location_ipv6;
                enc_cfg.validate_mmt_si_plt_package_entry_id8_location_ipv6_nz =
                    validate_mmt_si_plt_package_entry_id8_location_ipv6_nz;
            } else if (prepend_mmtp_isobmff) {
                atsc3::mmtp_payload_isobmff_prefix::decoded_t iso_dec{};
                iso_dec.fragment_type = static_cast<std::uint8_t>(mmtp_iso_ft);
                iso_dec.timed_flag      = mmtp_iso_timed;
                iso_dec.fragmentation_indicator =
                    static_cast<std::uint8_t>(mmtp_iso_fi);
                iso_dec.aggregation_flag = mmtp_iso_agg;
                iso_dec.fragment_counter =
                    static_cast<std::uint8_t>(mmtp_iso_frag_ctr);
                iso_dec.sequence_number = mmtp_iso_seq;
                enc_cfg = atsc3::gw::with_prepended_lab_mmtp_isobmff_prefix(
                    iso_dec, std::move(enc_cfg));
                enc_cfg.mmtp_isobmff_aggregate_bodies =
                    std::move(mmtp_iso_agg_bodies);
                enc_cfg.prepend_mmtp_isobmff_du_header =
                    prepend_mmtp_isobmff_du_hdr;
                enc_cfg.mmtp_isobmff_du_header_non_timed.item_id =
                    mmtp_iso_du_item_id;
                enc_cfg.mmtp_isobmff_du_header_timed.movie_fragment_sequence_number =
                    mmtp_iso_du_mf_seq;
                enc_cfg.mmtp_isobmff_du_header_timed.sample_number =
                    mmtp_iso_du_sample;
                enc_cfg.mmtp_isobmff_du_header_timed.offset = mmtp_iso_du_offset;
                enc_cfg.mmtp_isobmff_du_header_timed.subsample_priority =
                    static_cast<std::uint8_t>(mmtp_iso_du_priority);
                enc_cfg.mmtp_isobmff_du_header_timed.dependency_counter =
                    static_cast<std::uint8_t>(mmtp_iso_du_dep_counter);
            } else if (prepend_mmtp_gfd) {
                atsc3::mmtp_payload_gfd_header::decoded_t gfd_dec{};
                gfd_dec.session_last_packet_flag  = mmtp_gfd_session_last;
                gfd_dec.object_last_packet_flag   = mmtp_gfd_obj_last_pkt;
                gfd_dec.object_last_byte_flag     = mmtp_gfd_obj_last_byte;
                gfd_dec.code_point =
                    static_cast<std::uint8_t>(mmtp_gfd_code_point);
                gfd_dec.reserved =
                    static_cast<std::uint8_t>(mmtp_gfd_reserved);
                gfd_dec.transport_object_identifier = mmtp_gfd_toi;
                gfd_dec.start_offset                = mmtp_gfd_start_offset;
                enc_cfg = atsc3::gw::with_prepended_lab_mmtp_gfd_header(
                    gfd_dec, std::move(enc_cfg));
            }
        }
        enc_cfg.alp_payload_config = alp_pc;
        enc_cfg.alp_header_mode    = alp_hm;

        atsc3::gw::gw_config gcfg{
            .ingress_addr = seastar::ipv4_addr(cfg["ingress"].as<std::string>()),
            .sink_uri     = cfg["sink"].as<std::string>(),
            .services_state_file =
                services_state.empty() ? std::nullopt
                                       : std::make_optional(services_state),
            .encoder = enc_cfg,
        };

        auto server = std::make_unique<seastar::sharded<atsc3::gw::gw_server>>();

        co_await server->start(gcfg);
        co_await server->invoke_on_all(&atsc3::gw::gw_server::start);

        std::optional<seastar::httpd::http_server_control> admin_ctl;
        if (!admin_bind.empty()) {
            atsc3::gw::admin_listen_options admin_opts{};
            const std::string bearer = cfg["admin-bearer-token"].as<std::string>();
            if (!bearer.empty()) {
                admin_opts.bearer_token = bearer;
            }
            const std::string tls_cert = cfg["admin-tls-cert"].as<std::string>();
            const std::string tls_key = cfg["admin-tls-key"].as<std::string>();
            if (!tls_cert.empty() || !tls_key.empty()) {
                if (tls_cert.empty() || tls_key.empty()) {
                    mlog.error(
                        "admin HTTPS requires both --admin-tls-cert and --admin-tls-key");
                    co_await server->stop();
                    co_return 2;
                }
                seastar::tls::credentials_builder cb;
                co_await cb.set_x509_key_file(
                    tls_cert, tls_key, seastar::tls::x509_crt_format::PEM);
                try {
                    admin_opts.tls_credentials = cb.build_server_credentials();
                } catch (const std::exception& ex) {
                    mlog.error("admin TLS credential build failed: {}", ex.what());
                } catch (...) {
                    mlog.error("admin TLS credential build failed (unknown)");
                }
                if (!admin_opts.tls_credentials) {
                    mlog.error("admin TLS: build_server_credentials failed or returned null");
                    co_await server->stop();
                    co_return 2;
                }
            }

            admin_ctl.emplace();
            co_await admin_ctl->start("atsc3-admin");
            seastar::ipv4_addr aa(admin_bind);
            co_await atsc3::gw::admin_http_listen(*admin_ctl, *server,
                                                  seastar::socket_address(aa),
                                                  std::move(admin_opts));
        }

        mlog.info(
            "atsc3_gw ready: ingress={} sink={} alp_payload_config={} "
            "alp_header_mode={} prepend_mmtp_word0={} "
            "mmtp_payload_type={} mmtp_packet_id={} prepend_mmtp_ts_psn={} "
            "mmtp_timestamp={} mmtp_psn={} prepend_mmtp_packet_counter={} "
            "mmtp_packet_counter={} mmtp_extension_tlvs={} "
            "mmtp_extension_first_type={} mmtp_extension_value_octets_first={} "
            "prepend_mmtp_signalling_prefix={} mmtp_sig_fi={} mmtp_sig_res={} "
            "mmtp_sig_len_ext={} mmtp_sig_agg={} mmtp_sig_frag_ctr={} "
            "mmtp_signalling_aggregate_segments={} "
            "prepend_mmtp_isobmff_prefix={} mmtp_iso_ft={} mmtp_iso_timed={} "
            "mmtp_iso_fi={} mmtp_iso_agg={} mmtp_iso_frag_ctr={} mmtp_iso_seq={} "
            "prepend_mmtp_isobmff_du_header={} mmtp_iso_du_item_id={} "
            "mmtp_iso_du_mf_seq={} mmtp_iso_du_sample={} mmtp_iso_du_offset={} "
            "mmtp_iso_du_priority={} mmtp_iso_du_dep_counter={} "
            "mmtp_isobmff_aggregate_segments={} "
            "prepend_mmtp_gfd_header={} mmtp_gfd_c={} mmtp_gfd_l={} mmtp_gfd_b={} "
            "mmtp_gfd_code_point={} mmtp_gfd_reserved={} mmtp_gfd_toi={} "
            "mmtp_gfd_start_offset={} "
            "prepend_lct_word0={} "
            "lct_codepoint={} lct_include_tsi={} lct_tsi={} lct_include_toi={} "
            "lct_toi={} admin_http={} services_state={} smp={}",
            gcfg.ingress_addr,
            gcfg.sink_uri,
            gcfg.encoder.alp_payload_config ? "yes" : "no",
            gcfg.encoder.alp_header_mode ? "yes" : "no",
            prepend_mmtp ? "yes" : "no",
            static_cast<unsigned>(gcfg.encoder.mmtp_word0.payload_type),
            static_cast<unsigned>(gcfg.encoder.mmtp_word0.packet_id),
            gcfg.encoder.prepend_mmtp_ts_psn ? "yes" : "no",
            gcfg.encoder.mmtp_ts_psn.timestamp,
            gcfg.encoder.mmtp_ts_psn.packet_sequence_number,
            gcfg.encoder.prepend_mmtp_packet_counter ? "yes" : "no",
            gcfg.encoder.mmtp_packet_counter,
            static_cast<unsigned>(gcfg.encoder.mmtp_extensions.size()),
            gcfg.encoder.mmtp_extensions.empty()
                ? 0u
                : static_cast<unsigned>(
                      gcfg.encoder.mmtp_extensions.front().extension_type),
            static_cast<unsigned>(
                gcfg.encoder.mmtp_extensions.empty()
                    ? 0u
                    : gcfg.encoder.mmtp_extensions.front().value.size()),
            gcfg.encoder.prepend_mmtp_signalling_prefix ? "yes" : "no",
            static_cast<unsigned>(
                gcfg.encoder.mmtp_signalling_prefix.fragmentation_indicator),
            static_cast<unsigned>(gcfg.encoder.mmtp_signalling_prefix.reserved),
            gcfg.encoder.mmtp_signalling_prefix.length_extension_flag ? "yes"
                                                                        : "no",
            gcfg.encoder.mmtp_signalling_prefix.aggregation_flag ? "yes" : "no",
            static_cast<unsigned>(
                gcfg.encoder.mmtp_signalling_prefix.fragment_counter),
            static_cast<unsigned>(
                gcfg.encoder.mmtp_signalling_aggregate_bodies.size()),
            gcfg.encoder.prepend_mmtp_isobmff_prefix ? "yes" : "no",
            static_cast<unsigned>(gcfg.encoder.mmtp_isobmff_prefix.fragment_type),
            gcfg.encoder.mmtp_isobmff_prefix.timed_flag ? "yes" : "no",
            static_cast<unsigned>(
                gcfg.encoder.mmtp_isobmff_prefix.fragmentation_indicator),
            gcfg.encoder.mmtp_isobmff_prefix.aggregation_flag ? "yes" : "no",
            static_cast<unsigned>(
                gcfg.encoder.mmtp_isobmff_prefix.fragment_counter),
            gcfg.encoder.mmtp_isobmff_prefix.sequence_number,
            gcfg.encoder.prepend_mmtp_isobmff_du_header ? "yes" : "no",
            gcfg.encoder.mmtp_isobmff_du_header_non_timed.item_id,
            gcfg.encoder.mmtp_isobmff_du_header_timed
                .movie_fragment_sequence_number,
            gcfg.encoder.mmtp_isobmff_du_header_timed.sample_number,
            gcfg.encoder.mmtp_isobmff_du_header_timed.offset,
            static_cast<unsigned>(
                gcfg.encoder.mmtp_isobmff_du_header_timed.subsample_priority),
            static_cast<unsigned>(
                gcfg.encoder.mmtp_isobmff_du_header_timed.dependency_counter),
            static_cast<unsigned>(
                gcfg.encoder.mmtp_isobmff_aggregate_bodies.size()),
            gcfg.encoder.prepend_mmtp_gfd_header ? "yes" : "no",
            gcfg.encoder.mmtp_gfd_header.session_last_packet_flag ? "yes" : "no",
            gcfg.encoder.mmtp_gfd_header.object_last_packet_flag ? "yes" : "no",
            gcfg.encoder.mmtp_gfd_header.object_last_byte_flag ? "yes" : "no",
            static_cast<unsigned>(gcfg.encoder.mmtp_gfd_header.code_point),
            static_cast<unsigned>(gcfg.encoder.mmtp_gfd_header.reserved),
            gcfg.encoder.mmtp_gfd_header.transport_object_identifier,
            gcfg.encoder.mmtp_gfd_header.start_offset,
            prepend_lct ? "yes" : "no",
            static_cast<unsigned>(gcfg.encoder.lct_word0.codepoint),
            prepend_lct && gcfg.encoder.lct_word0.tsi_flag ? "yes" : "no",
            gcfg.encoder.lct_transport_session_identifier,
            prepend_lct && gcfg.encoder.lct_word0.toi_flag == 1 &&
                    !gcfg.encoder.lct_word0.half_word_flag
                ? "yes"
                : "no",
            gcfg.encoder.lct_transport_object_identifier,
            admin_bind.empty() ? std::string("(disabled)") : admin_bind,
            gcfg.services_state_file.has_value() ? *gcfg.services_state_file
                                                 : std::string("(none)"),
            seastar::smp::count);

        // Wait for SIGINT/SIGTERM. The promise is satisfied from the signal
        // handler; the future blocks the coro until then.
        seastar::promise<> stopped;
        seastar::handle_signal(SIGINT, [&stopped] {
            try { stopped.set_value(); } catch (...) {}
        });
        seastar::handle_signal(SIGTERM, [&stopped] {
            try { stopped.set_value(); } catch (...) {}
        });
        co_await stopped.get_future();

        if (admin_ctl) {
            co_await admin_ctl->stop();
        }

        // Aggregate stats across shards before tearing down for a final log.
        atsc3::gw::gw_server::stats_t total{};
        co_await server->invoke_on_all(
            [&total](atsc3::gw::gw_server& s)
                -> seastar::future<> {
                auto st = co_await s.get_stats();
                total.bytes_in       += st.bytes_in;
                total.bytes_out      += st.bytes_out;
                total.payloads       += st.payloads;
                total.encode_errors  += st.encode_errors;
                total.connections    += st.connections;
                co_return;
            });
        mlog.info(
            "totals: payloads={} bytes_in={} bytes_out={} encode_errors={} "
            "connections={}",
            total.payloads, total.bytes_in, total.bytes_out,
            total.encode_errors, total.connections);

        co_await server->stop();
        co_return 0;
    });
}

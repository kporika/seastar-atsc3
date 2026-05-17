// SPDX-License-Identifier: Apache-2.0
//
// Two-stage encoder pipeline used by the gateway:
//
//   raw payload bytes
//       │  optional M8: prepend ISO/IEC 23008-1 MMTP packet header word‑0
//       │  (see prepend_mmtp_header_word0), optional **mmtp_header_ts_psn** (64b),
//       │  optional **mmtp_header_counter32** (32b when **C**=**1**),
//       │  optional **mmtp_header_extension** chain (zero or more X TLVs: 32b + value each),
//       │  optional **mmtp_payload_isobmff_prefix** (64b Figure 3 when **payload_type**=**0x00**)
//       │  and optional **mmtp_payload_isobmff_du_header_*** (Figures 4–5 when **FT**=**2** lab)
//       │  or optional **mmtp_payload_gfd_header** (96b Figure 6 when **payload_type**=**0x01**)
//       │  or optional **mmtp_payload_signalling_prefix** (16b §9.3.4 when **payload_type**=**0x02**)
//       │  and optional **`mmt_si_message_header_len32`** (**§10.3** consumption **message_id** +
//       │  **message_version** + **BE32** **message_byte_length** + body; signalling only; **outermost**
//       │  lab layer vs **descriptor loop** / **§10.2** envelope) and/or optional **`mmt_si_descriptor_loop_u32`**
//       │  (**BE32** descriptor-region length +
//       │  **`mmtp_desc`** concatenation; signalling only) and/or optional **`mmt_si_length32_envelope`**
//       │  (**BE32** body length + body; signalling only; may wrap the descriptor loop)
//       │  (**ISOBMFF**, **GFD**, and **signalling** payload prefixes are mutually exclusive);
//       │  signalling may add **aggregated** length+body pairs when **A**=**1**;
//       │  ISOBMFF may add **DU_length** (16b BE) + (**optional** **DU_header**) + media per
//       │  **`mmtp_isobmff_aggregate_bodies`** when **aggregation_flag**=**1**,
//       │  then optional RFC 5651 LCT word‑0
//       ▼
//   ┌─────────────────────┐
//   │  ALP encode         │  packet_type = PACKET_TYPE_EXTENSION (default);
//   │  (A/330 §5.2)       │  optional **payload_configuration** / **header_mode** bits (**pc**/**hm**)
//   │                     │  payload_length = N
//   └─────────────────────┘
//       │  ALP packet bytes
//       ▼
//   ┌─────────────────────┐
//   │  TLV-mux encode     │  packet_type = SIGNALING (default)
//   │  (A/330 Annex A)    │  packet_length = M
//   └─────────────────────┘
//       │
//       ▼
//   wire bytes (handed to sink)
//
// Limits:
//   * Without any prepend: opaque payload ≤ 2047 bytes (ALP 11-bit length).
//   * With prepend_mmtp_header_word0: ALP opaque = MMTP word‑0 (32b) ∪ optional
//     **`mmtp_header_ts_psn`** (64b) ∪ optional **`mmtp_header_counter32`** (32b
//     when **C**=**1**; requires **ts_psn** on this lab path) ∪ optional
//     **mmtp_header_extension** TLVs (each 4+N B) ∪ optional **ISOBMFF payload prefix** (8 B)
//     ∪ optional **signalling payload prefix** (2 B; not with ISOBMFF) ∪ user. Prefix order:
//     **MMTP word‑0**, optional **ts_psn**, optional **packet_counter**,
//     optional **extension** chain, optional **ISOBMFF**, **GFD**, or **signalling** payload prefix,
//     optional **`mmt_si_message_header_len32`** (**7** B + body) and/or optional
//     **`mmt_si_descriptor_loop_u32`** (**4** B + **A/331**-shaped descriptor octets) and/or
//     optional **`mmt_si_length32_envelope`** (**4** B + body when signalling **§9.3.4** **A**=**0**),
//     optional **ISOBMFF DU_header** (timed/non-timed), optional **ISOBMFF DU_length+body** repeats when **A**=**1**,
//     then **LCT** + optional TSI/TOI.
//   * With prepend_rfc5651_lct_word0: ALP opaque = word‑0 (32b) ∪ optional RFC
//     reorder fields ∪ user ≤ 2047 total (**CCI omitted** lab stitch).
//     · word‑0 only (`header_length_words == 1`): ≤ 2043 user.
//     · + 32‑bit **TSI** (`header_length_words == 2`, **S**=**1**, **O**=**0**):
//       ≤ 2039 user.
//     · + 32‑bit **TOI**, **O**=**1** (`header_length_words == 2`, **S**=**0**):
//       ≤ 2039 user.
//     · + **TSI** then **TOI** (**S**=**1**, **O**=**1**, `header_length_words == 3`):
//       ≤ 2035 user.

//   * TLV-mux packet_length is 16 bits → ALP packet must be ≤ 65535 bytes.
//
// Both upper bounds are checked; oversize input returns an error result
// rather than truncating.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "alp_types.h"
#include "lct_rfc5651_word0_decoder.h"
#include "mmt_si_length32_envelope_decoder.h"
#include "mmt_si_message_header_len32_decoder.h"
#include "mmtp_header_ts_psn_decoder.h"
#include "mmtp_header_word0_decoder.h"
#include "mmtp_payload_gfd_header_decoder.h"
#include "mmtp_payload_isobmff_du_header_non_timed_decoder.h"
#include "mmtp_payload_isobmff_du_header_timed_decoder.h"
#include "mmtp_payload_isobmff_prefix_decoder.h"
#include "mmtp_payload_signalling_prefix_decoder.h"
#include "tlv_mux_types.h"

namespace atsc3::gw {

/// One **mmtp_header_extension** unit (type + length + opaque value octets).
struct mmtp_extension_tlv {
    std::uint16_t extension_type = 0;
    std::vector<std::byte> value{};
};

class encoder_pipeline {
public:
    struct config {
        atsc3::alp::packet_type alp_type =
            atsc3::alp::packet_type::PACKET_TYPE_EXTENSION;
        atsc3::tlv_mux::packet_type tlv_type =
            atsc3::tlv_mux::packet_type::SIGNALING;
        /// **A/330** §5.2 base header **payload_configuration** (**pc**). **Lab:** codegen **ALP**
        /// still emits **only** the 16-bit base header + opaque body (no segmentation/concatenation
        /// additional-header octets yet).
        bool alp_payload_config = false;
        /// **A/330** §5.2 base header **header_mode** (**hm**). **Lab:** same single-header wire as **pc**.
        bool alp_header_mode = false;

        /// M8 lab: prepend MMTP packet header **word‑0** (32b, `protocol/mmtp_header_word0.yaml`)
        /// before ingress inside the ALP opaque body. Encoded with codegen
        /// **`mmtp_header_word0::encode`**; may precede the LCT lab prefix when both
        /// flags are set.
        bool prepend_mmtp_header_word0 = false;
        atsc3::mmtp_header_word0::decoded_t mmtp_word0{};
        /// When true (requires **prepend_mmtp_header_word0**), append
        /// **`mmtp_header_ts_psn`** (64b BE) immediately after MMTP word‑0.
        bool prepend_mmtp_ts_psn = false;
        atsc3::mmtp_header_ts_psn::decoded_t mmtp_ts_psn{};
        /// When true (requires **prepend_mmtp_header_word0** and
        /// **prepend_mmtp_ts_psn**), append **`mmtp_header_counter32`** (32b BE)
        /// after **ts_psn** per ISO/IEC 23008-1. Sets **packet_counter_flag** (**C**)
        /// on the encoded MMTP word‑0.
        bool prepend_mmtp_packet_counter = false;
        std::uint32_t mmtp_packet_counter = 0;
        /// Non-empty ⇒ append that many **`mmtp_header_extension`** TLVs (in order)
        /// after optional **ts_psn** and optional **packet_counter**. Sets **extension_flag** (**X**)
        /// on the encoded MMTP word‑0 when non-empty.
        std::vector<mmtp_extension_tlv> mmtp_extensions{};
        /// When true (requires **prepend_mmtp_header_word0**), append
        /// **`mmtp_payload_signalling_prefix`** (16b, **ISO/IEC 23008-1** **9.3.4**)
        /// after optional **ts_psn**, **packet_counter**, and **extension** chain.
        bool prepend_mmtp_signalling_prefix = false;
        atsc3::mmtp_payload_signalling_prefix::decoded_t mmtp_signalling_prefix{};
        /// When **`mmtp_signalling_prefix.aggregation_flag`** is **true**, append each
        /// entry as **BE length** (**16** or **32** bits per **`length_extension_flag`**)
        /// then body octets (**length** = body size on this lab path). Must be empty when
        /// **aggregation_flag** is **false**.
        std::vector<std::vector<std::byte>> mmtp_signalling_aggregate_bodies{};
        /// When true (requires **prepend_mmtp_signalling_prefix**; **payload_type** **2**;
        /// **aggregation_flag** **false**; **mmtp_signalling_aggregate_bodies** empty),
        /// prepend **`mmt_si_descriptor_loop_u32`** (**`protocol/mmt_si_descriptor_loop_u32.yaml`**):
        /// **BE32**(**ingress size**) **+** ingress octets (ingress must concatenate valid **`mmtp_desc`**
        /// wire units whose total size equals the length field).
        bool prepend_mmt_si_descriptor_loop_u32 = false;
        /// When true (requires **prepend_mmtp_signalling_prefix**; **payload_type** **2**;
        /// **aggregation_flag** **false**; **mmtp_signalling_aggregate_bodies** empty),
        /// wrap the SI tail (**descriptor loop** if enabled, else raw ingress) in **`mmt_si_length32_envelope`**.
        bool prepend_mmt_si_length32_envelope = false;
        /// When true (requires **prepend_mmtp_signalling_prefix**; **payload_type** **2**;
        /// **aggregation_flag** **false**; **mmtp_signalling_aggregate_bodies** empty), prepend
        /// **`mmt_si_message_header_len32`** (**`protocol/mmt_si_message_header_len32.yaml`**) **around**
        /// the SI tail built from optional **descriptor loop** / **§10.2** envelope over ingress
        /// (**message_byte_length** = that tail’s octet length).
        bool prepend_mmt_si_message_header_len32 = false;
        /// **message_id** / **message_version** for **`prepend_mmt_si_message_header_len32`** (PA/MPI/MPT lab).
        std::uint16_t mmt_si_message_id = 0;
        std::uint8_t mmt_si_message_version = 0;

        /// One **PA** / **MMT-SI** **§10.3** table header row (**4** B) for
        /// **`prepend_mmt_si_pa_table_headers`** (**`mmt_si_table_header_word32`** wire).
        struct mmt_si_pa_table_header_row {
            std::uint8_t table_id = 0;
            std::uint8_t table_version = 0;
            std::uint16_t table_length = 0;
        };
        /// When true (requires **`prepend_mmt_si_message_header_len32`**, **PA** **message_id** **0**,
        /// same signalling constraints as other **MMT-SI** lab flags), prepend **`mmt_si_pa_table_headers`**
        /// (**`protocol/mmt_si_pa_table_headers.yaml`**) **before** optional **descriptor loop** /
        /// **§10.2** envelope over ingress. Wire order inside the message body:
        /// **PA index** **||** (**table bodies** when **`table_length` > 0**) **||** SI tail.
        /// **ZC** lab: one row with **`table_length` == 0** — ingress is SI tail after the index.
        /// **ZD** lab: one row with **`table_length` == ingress.size()** — ingress is that table body.
        /// **ZE** lab: multiple rows, each **`table_length` > 0** — ingress is bodies concatenated in
        /// row order (**sum(table_length) == ingress.size()**).
        /// **ZF** lab: multiple rows with mixed **`table_length` == 0** and **> 0** — ingress is
        /// concatenated table bodies in row order, then optional SI tail (**sum(non-zero lengths) ≤
        /// ingress.size()**).
        /// **ZG** / **ZH**: **`validate_mmt_si_mpt_table_body`** / **`validate_mmt_si_plt_table_body`**
        /// require ingress to decode as **`mmt_si_mpt_table`** / **`mmt_si_plt_table`**.
        bool prepend_mmt_si_pa_table_headers = false;
        std::vector<mmt_si_pa_table_header_row> mmt_si_pa_table_header_rows{};

        /// When true, ingress must decode as **`mmt_si_mpt_table`** (**table_id** **0x20**).
        /// With **PA** table rows, a **0x20** row **table_length** must equal ingress size when non-zero.
        bool validate_mmt_si_mpt_table_body = false;
        /// When true (requires **`validate_mmt_si_mpt_table_body`**), the MPT **`table_length`**
        /// region must decode as **`mmt_si_mpt_table_body_prefix`** (**ZI** minimal lab:
        /// **table_length** **5**).
        bool validate_mmt_si_mpt_table_body_prefix = false;
        /// When true (requires **`validate_mmt_si_mpt_table_body`**), the MPT body must decode as
        /// **`mmt_si_mpt_table_body_prefix`** + one **`mmt_si_mpt_asset`** (**ZK** lab:
        /// **table_length** **19**, **number_of_assets** **1**, **asset_id_length** **0**).
        bool validate_mmt_si_mpt_asset = false;
        /// When true (requires **`validate_mmt_si_mpt_table_body`**), the MPT body must decode as
        /// **`mmt_si_mpt_table_body_prefix`** + one **`mmt_si_mpt_asset_descriptors4`** (**AAC** lab:
        /// **table_length** **23**, **asset_descriptors_length** **4**).
        bool validate_mmt_si_mpt_asset_descriptors4 = false;
        /// When true (requires **`validate_mmt_si_mpt_table_body`**), the MPT body must decode as
        /// **`mmt_si_mpt_table_body_prefix`** + one **`mmt_si_mpt_asset_id8`** (**ZS** lab:
        /// **table_length** **20**, **number_of_assets** **1**, **asset_id_length** **1**,
        /// **asset_id** **0x01**).
        bool validate_mmt_si_mpt_asset_id8 = false;
        /// When true (requires **`validate_mmt_si_mpt_table_body`**), the MPT body must decode as
        /// **`mmt_si_mpt_table_body_prefix`** + one **`mmt_si_mpt_asset_id16`** (**AAG** lab:
        /// **table_length** **21**, **asset_id_length** **2**, **asset_id** **0x01** **0x02**).
        bool validate_mmt_si_mpt_asset_id16 = false;
        /// When true (requires **`validate_mmt_si_mpt_table_body`**), the MPT body must decode as
        /// **`mmt_si_mpt_table_body_prefix`** + one **`mmt_si_mpt_asset_location0`** (**ZT** lab:
        /// **table_length** **22**, **asset_id_length** **0**, **location_count** **1**,
        /// **location_type** **0**).
        bool validate_mmt_si_mpt_asset_location0 = false;
        /// When true (requires **`validate_mmt_si_mpt_table_body`**), the MPT body must decode as
        /// **`mmt_si_mpt_table_body_prefix`** + one **`mmt_si_mpt_asset_location_ipv4`** (**ZV** lab:
        /// **table_length** **30**, **asset_id_length** **0**, **location_count** **1**,
        /// **location_type** **1**).
        bool validate_mmt_si_mpt_asset_location_ipv4 = false;
        /// When true (requires **`validate_mmt_si_mpt_table_body`**), the MPT body must decode as
        /// **`mmt_si_mpt_table_body_prefix`** + one **`mmt_si_mpt_asset_location_ipv4_nz`** (**AAF** lab:
        /// **table_length** **30**, **src** **10.0.0.1**, **dst** **224.0.0.1**, **dst_port** **5000**).
        bool validate_mmt_si_mpt_asset_location_ipv4_nz = false;
        /// When true (requires **`validate_mmt_si_mpt_table_body`**), the MPT body must decode as
        /// **`mmt_si_mpt_table_body_prefix`** + one **`mmt_si_mpt_asset_location_ipv6`** (**ZY** lab:
        /// **table_length** **54**, **asset_id_length** **0**, **location_count** **1**,
        /// **location_type** **2**).
        bool validate_mmt_si_mpt_asset_location_ipv6 = false;
        /// When true (requires **`validate_mmt_si_mpt_table_body`**), the MPT body must decode as
        /// **`mmt_si_mpt_table_body_prefix`** + one **`mmt_si_mpt_asset_location_ipv6_nz`** (**AAH** lab:
        /// **table_length** **54**, **::ffff:10.0.0.1** → **::ffff:224.0.0.1**, **dst_port** **5000**).
        bool validate_mmt_si_mpt_asset_location_ipv6_nz = false;
        /// When true (requires **`validate_mmt_si_mpt_table_body`**), the MPT body must decode as
        /// **`mmt_si_mpt_table_body_prefix`** + one **`mmt_si_mpt_asset_id8_location_ipv4`** (**ZW** lab:
        /// **table_length** **31**, **asset_id_length** **1**, **asset_id** **0x01**, **location_type** **1**).
        bool validate_mmt_si_mpt_asset_id8_location_ipv4 = false;
        /// When true (requires **`validate_mmt_si_mpt_table_body`**), the MPT body must decode as
        /// **`mmt_si_mpt_table_body_prefix`** + one **`mmt_si_mpt_asset_id8_location_ipv4_nz`** (**AAM** lab:
        /// **table_length** **31**, **asset_id** **0x01**, **10.0.0.1** → **224.0.0.1:5000**).
        bool validate_mmt_si_mpt_asset_id8_location_ipv4_nz = false;
        /// When true (requires **`validate_mmt_si_mpt_table_body`**), the MPT body must decode as
        /// **`mmt_si_mpt_table_body_prefix`** + one **`mmt_si_mpt_asset_id8_location_ipv6_nz`** (**AAN** lab:
        /// **table_length** **55**, **asset_id** **0x01**, **::ffff:10.0.0.1** → **::ffff:224.0.0.1:5000**).
        bool validate_mmt_si_mpt_asset_id8_location_ipv6_nz = false;
        /// When true (requires **`validate_mmt_si_mpt_table_body`**), the MPT body must decode as
        /// **`mmt_si_mpt_table_body_prefix`** + one **`mmt_si_mpt_asset_id16_location_ipv4`** (**AAO** lab:
        /// **table_length** **32**, **asset_id** **0x01** **0x02**, zero IPv4 addrs).
        bool validate_mmt_si_mpt_asset_id16_location_ipv4 = false;
        /// When true (requires **`validate_mmt_si_mpt_table_body`**), the MPT body must decode as
        /// **`mmt_si_mpt_table_body_prefix`** + one **`mmt_si_mpt_asset_id16_location_ipv4_nz`** (**AAP** lab:
        /// **table_length** **32**, **asset_id** **0x01** **0x02**, **10.0.0.1** → **224.0.0.1:5000**).
        bool validate_mmt_si_mpt_asset_id16_location_ipv4_nz = false;
        /// When true (requires **`validate_mmt_si_mpt_table_body`**), the MPT body must decode as
        /// **`mmt_si_mpt_table_body_prefix`** + one **`mmt_si_mpt_asset_id16_location_ipv6`** (**AAQ** lab:
        /// **table_length** **55**, **asset_id** **0x01** **0x02**, zero IPv6 addrs).
        bool validate_mmt_si_mpt_asset_id16_location_ipv6 = false;
        /// When true (requires **`validate_mmt_si_mpt_table_body`**), the MPT body must decode as
        /// **`mmt_si_mpt_table_body_prefix`** + one **`mmt_si_mpt_asset_id16_location_ipv6_nz`** (**AAR** lab:
        /// **table_length** **56**, **asset_id** **0x01** **0x02**, **::ffff:10.0.0.1** → **::ffff:224.0.0.1:5000**).
        bool validate_mmt_si_mpt_asset_id16_location_ipv6_nz = false;
        /// When true (requires **`validate_mmt_si_mpt_table_body`**), the MPT body must decode as
        /// **`mmt_si_mpt_table_body_prefix`** + one **`mmt_si_mpt_asset_id16_descriptors4`** (**AAS** lab:
        /// **table_length** **25**, **asset_id** **0x01** **0x02**, descriptor **DEADBEEF**).
        bool validate_mmt_si_mpt_asset_id16_descriptors4 = false;
        /// When true (requires **`validate_mmt_si_mpt_table_body`**), the MPT body must decode as
        /// **`mmt_si_mpt_table_body_prefix`** + one **`mmt_si_mpt_asset_id8_descriptors4`** (**AAT** lab:
        /// **table_length** **24**, **asset_id** **0x01**, descriptor **DEADBEEF**).
        bool validate_mmt_si_mpt_asset_id8_descriptors4 = false;
        /// When true (requires **`validate_mmt_si_mpt_table_body`**), the MPT body must decode as
        /// **`mmt_si_mpt_table_body_prefix`** + one **`mmt_si_mpt_asset_id8_location_ipv6`** (**AAA** lab:
        /// **table_length** **55**, **asset_id_length** **1**, **asset_id** **0x01**, **location_type** **2**).
        bool validate_mmt_si_mpt_asset_id8_location_ipv6 = false;
        /// When true, ingress must decode as **`mmt_si_plt_table`** (**table_id** **0x80**).
        bool validate_mmt_si_plt_table_body = false;
        /// When true (requires **`validate_mmt_si_plt_table_body`**), the PLT **`table_length`**
        /// region must decode as **`mmt_si_plt_table_body_prefix`** (**ZJ** minimal lab:
        /// **table_length** **2**).
        bool validate_mmt_si_plt_table_body_prefix = false;
        /// When true (requires **`validate_mmt_si_plt_table_body`**), the PLT body must decode as
        /// **`mmt_si_plt_table_body_prefix`** + one **`mmt_si_plt_delivery_info`** (**ZL** lab:
        /// **table_length** **9**, **num_of_ip_delivery** **1**, **location_type** **0**).
        bool validate_mmt_si_plt_delivery_info = false;
        /// When true (requires **`validate_mmt_si_plt_table_body`**), the PLT body must decode as
        /// **`mmt_si_plt_table_body_prefix`** + one **`mmt_si_plt_delivery_info_ipv4`** (**ZM** lab:
        /// **table_length** **19**, **num_of_ip_delivery** **1**, **location_type** **1**).
        bool validate_mmt_si_plt_delivery_info_ipv4 = false;
        /// When true (requires **`validate_mmt_si_plt_table_body`**), the PLT body must decode as
        /// **`mmt_si_plt_table_body_prefix`** + one **`mmt_si_plt_delivery_info_ipv6`** (**ZN** lab:
        /// **table_length** **43**, **num_of_ip_delivery** **1**, **location_type** **2**).
        bool validate_mmt_si_plt_delivery_info_ipv6 = false;
        /// When true (requires **`validate_mmt_si_plt_table_body`**), the PLT body must decode as
        /// **`mmt_si_plt_table_body_prefix`** + one **`mmt_si_plt_delivery_info_url`** (**ZO** lab:
        /// **table_length** **10**, **num_of_ip_delivery** **1**, **location_type** **5**,
        /// **url_length** **0**).
        bool validate_mmt_si_plt_delivery_info_url = false;
        /// When true (requires **`validate_mmt_si_plt_table_body`**), the PLT body must decode as
        /// **`mmt_si_plt_table_body_prefix`** + one **`mmt_si_plt_delivery_info_url_3`** (**ZQ** lab:
        /// **table_length** **13**, **num_of_ip_delivery** **1**, **url_length** **3**, URL **lab**).
        bool validate_mmt_si_plt_delivery_info_url_3 = false;
        /// When true (requires **`validate_mmt_si_plt_table_body`**), the PLT body must decode as
        /// **`mmt_si_plt_table_body_prefix`** + one **`mmt_si_plt_delivery_info_url_4`** (**AAD** lab:
        /// **table_length** **14**, **num_of_ip_delivery** **1**, **url_length** **4**, URL **http**).
        bool validate_mmt_si_plt_delivery_info_url_4 = false;
        /// When true (requires **`validate_mmt_si_plt_table_body`**), the PLT body must decode as
        /// **`mmt_si_plt_table_body_prefix`** + one **`mmt_si_plt_delivery_info_ipv4_nz`** (**AAE** lab:
        /// **table_length** **19**, **src** **10.0.0.1**, **dst** **224.0.0.1**, **dst_port** **5000**).
        bool validate_mmt_si_plt_delivery_info_ipv4_nz = false;
        /// When true (requires **`validate_mmt_si_plt_table_body`**), the PLT body must decode as
        /// **`mmt_si_plt_table_body_prefix`** + one **`mmt_si_plt_package_entry`** (**ZP** lab:
        /// **table_length** **6**, **num_of_packages** **1**, **MMT_package_id_length** **0**,
        /// **location_type** **0**).
        bool validate_mmt_si_plt_package_entry = false;
        /// When true (requires **`validate_mmt_si_plt_table_body`**), the PLT body must decode as
        /// **`mmt_si_plt_table_body_prefix`** + one **`mmt_si_plt_package_entry_id8`** (**ZR** lab:
        /// **table_length** **7**, **MMT_package_id_length** **1**, **MMT_package_id** **0x01**).
        bool validate_mmt_si_plt_package_entry_id8 = false;
        /// When true (requires **`validate_mmt_si_plt_table_body`**), the PLT body must decode as
        /// **`mmt_si_plt_table_body_prefix`** + one **`mmt_si_plt_package_entry_ipv4`** (**ZU** lab:
        /// **table_length** **14**, **num_of_packages** **1**, **MMT_package_id_length** **0**,
        /// **location_type** **1**).
        bool validate_mmt_si_plt_package_entry_ipv4 = false;
        /// When true (requires **`validate_mmt_si_plt_table_body`**), the PLT body must decode as
        /// **`mmt_si_plt_table_body_prefix`** + one **`mmt_si_plt_package_entry_ipv4_nz`** (**AAI** lab:
        /// **table_length** **14**, **src** **10.0.0.1**, **dst** **224.0.0.1**, **dst_port** **5000**).
        bool validate_mmt_si_plt_package_entry_ipv4_nz = false;
        /// When true (requires **`validate_mmt_si_plt_table_body`**), the PLT body must decode as
        /// **`mmt_si_plt_table_body_prefix`** + one **`mmt_si_plt_package_entry_id8_location_ipv4`**
        /// (**ZX** lab: **table_length** **15**, **MMT_package_id_length** **1**,
        /// **MMT_package_id** **0x01**, **location_type** **1**).
        bool validate_mmt_si_plt_package_entry_id8_location_ipv4 = false;
        /// When true (requires **`validate_mmt_si_plt_table_body`**), the PLT body must decode as
        /// **`mmt_si_plt_table_body_prefix`** + one **`mmt_si_plt_package_entry_id8_location_ipv4_nz`**
        /// (**AAK** lab: **table_length** **15**, **MMT_package_id** **0x01**, **10.0.0.1** → **224.0.0.1:5000**).
        bool validate_mmt_si_plt_package_entry_id8_location_ipv4_nz = false;
        /// When true (requires **`validate_mmt_si_plt_table_body`**), the PLT body must decode as
        /// **`mmt_si_plt_table_body_prefix`** + one **`mmt_si_plt_package_entry_ipv6`** (**ZZ** lab:
        /// **table_length** **38**, **MMT_package_id_length** **0**, **location_type** **2**).
        bool validate_mmt_si_plt_package_entry_ipv6 = false;
        /// When true (requires **`validate_mmt_si_plt_table_body`**), the PLT body must decode as
        /// **`mmt_si_plt_table_body_prefix`** + one **`mmt_si_plt_package_entry_ipv6_nz`** (**AAJ** lab:
        /// **table_length** **38**, **::ffff:10.0.0.1** → **::ffff:224.0.0.1**, **dst_port** **5000**).
        bool validate_mmt_si_plt_package_entry_ipv6_nz = false;
        /// When true (requires **`validate_mmt_si_plt_table_body`**), the PLT body must decode as
        /// **`mmt_si_plt_table_body_prefix`** + one **`mmt_si_plt_package_entry_id8_location_ipv6`**
        /// (**AAB** lab: **table_length** **39**, **MMT_package_id_length** **1**,
        /// **MMT_package_id** **0x01**, **location_type** **2**).
        bool validate_mmt_si_plt_package_entry_id8_location_ipv6 = false;
        /// When true (requires **`validate_mmt_si_plt_table_body`**), the PLT body must decode as
        /// **`mmt_si_plt_table_body_prefix`** + one **`mmt_si_plt_package_entry_id8_location_ipv6_nz`**
        /// (**AAL** lab: **table_length** **39**, **::ffff:10.0.0.1** → **::ffff:224.0.0.1:5000**).
        bool validate_mmt_si_plt_package_entry_id8_location_ipv6_nz = false;

        /// When true (requires **prepend_mmtp_header_word0**), append
        /// **`mmtp_payload_isobmff_prefix`** (64b, **ISO/IEC 23008-1** Figure 3 rows 1–2)
        /// after optional **ts_psn**, **packet_counter**, and **extension** chain.
        /// Mutually exclusive with **prepend_mmtp_signalling_prefix** and **prepend_mmtp_gfd_header**;
        /// requires **mmtp_word0.payload_type** **==** **0** (ISOBMFF mode). **`payload_length_excluding_length_field`**
        /// counts octets after the prefix’s **16-bit length** field: **6** (rest of prefix) **+**
        /// (**A**=**0**: ingress only) **or** (**A**=**1**: Σ (**2** + **`body.size()`**) per entry) **+**
        /// optional RFC 5651 LCT lab octets **+** ingress. When **aggregation_flag** is **true**,
        /// **`mmtp_isobmff_aggregate_bodies`** must be non-empty; each **body** is one DU’s octets
        /// (**DU_Header** + media) and is prefixed on the wire with **16-bit BE** **DU_length** =
        /// **`body.size()`**. When **false**, **`mmtp_isobmff_aggregate_bodies`** must be empty.
        bool prepend_mmtp_isobmff_prefix = false;
        atsc3::mmtp_payload_isobmff_prefix::decoded_t mmtp_isobmff_prefix{};
        /// When **`mmtp_isobmff_prefix.aggregation_flag`** is **true**, append each entry as
        /// **BE DU_length** (**16** bits = **`body.size()`**) then **`body`** octets. Must be empty
        /// when **aggregation_flag** is **false**.
        std::vector<std::vector<std::byte>> mmtp_isobmff_aggregate_bodies{};
        /// When true (requires **prepend_mmtp_isobmff_prefix**), emit **`mmtp_payload_isobmff_du_header_*`**
        /// after the **64b** ISOBMFF prefix (**Figure** **4**/**5**): **14** B timed or **4** B non-timed
        /// per **`mmtp_isobmff_prefix.timed_flag`**, then **A**=**0** ingress or (**A**=**1**) each
        /// aggregate **media** chunk (header repeated per DU). Requires **`fragment_type`** **==** **2**.
        bool prepend_mmtp_isobmff_du_header = false;
        atsc3::mmtp_payload_isobmff_du_header_timed::decoded_t mmtp_isobmff_du_header_timed{};
        atsc3::mmtp_payload_isobmff_du_header_non_timed::decoded_t mmtp_isobmff_du_header_non_timed{};

        /// When true (requires **prepend_mmtp_header_word0**), append **`mmtp_payload_gfd_header`**
        /// (96b, **ISO/IEC 23008-1** Figure 6) after optional **ts_psn**, **packet_counter**, and
        /// **extension** chain. Mutually exclusive with **prepend_mmtp_signalling_prefix** and
        /// **prepend_mmtp_isobmff_prefix**; requires **mmtp_word0.payload_type** **==** **1** (GFD mode).
        bool prepend_mmtp_gfd_header = false;
        atsc3::mmtp_payload_gfd_header::decoded_t mmtp_gfd_header{};

        /// M8 lab: prepend RFC 5651 §5.1 fixed fields before ingress in the ALP
        /// opaque body (**no CCI** extension — `header_length_words` counts trailing
        /// fixed words after word‑0):
        ///   * `header_length_words == 1`, **S**=0 (`tsi_flag`), **O**=0 (`toi_flag`):
        ///     word‑0 only.
        ///   * `header_length_words == 2`, **S**=1, **O**=0,
        ///     `half_word_flag == false`: word‑0 + 32‑bit TSI BE
        ///     (`lct_transport_session_identifier`).
        ///   * `header_length_words == 2`, **S**=1, **O**=0,
        ///     `half_word_flag == false`: word‑0 + 32‑bit TSI BE
        ///     (`lct_transport_session_identifier`).
        ///   * `header_length_words == 2`, **S**=0, **O**=**1** (`toi_flag == 1`),
        ///     `half_word_flag == false`: word‑0 + 32‑bit TOI BE
        ///     (`lct_transport_object_identifier`).
        ///   * `header_length_words == 3`, **S**=**1**, **O**=**1** (`toi_flag == 1`),
        ///     `half_word_flag == false`: word‑0 + 32‑bit TSI BE + 32‑bit TOI BE
        ///     (**RFC Figure 1** order; **CCI** still omitted lab‑only).
        bool prepend_rfc5651_lct_word0 = false;

        atsc3::lct_rfc5651_word0::decoded_t lct_word0{};
        std::uint32_t lct_transport_session_identifier = 0;
        std::uint32_t lct_transport_object_identifier  = 0;
    };

    struct result {
        bool ok = false;
        std::vector<std::byte> bytes;
        std::string error;
    };

    encoder_pipeline() noexcept = default;
    explicit encoder_pipeline(config cfg) noexcept : _cfg(cfg) {}

    [[nodiscard]] const config& encoder_config() const noexcept { return _cfg; }

    // Wrap a single raw payload. Returns the wire bytes ready for the sink.
    result encode(std::span<const std::byte> payload) const;

private:
    config _cfg;
};

/// MMTP word‑0 only (defaults: V=0, C=0, FEC=0, no X/R extensions, **payload_type**
/// and **packet_id** supplied — see `mmtp_header_word0.yaml` fixtures).
[[nodiscard]] inline encoder_pipeline::config with_prepended_lab_mmtp_word0(
    std::uint8_t payload_type,
    std::uint16_t packet_id,
    encoder_pipeline::config base = {}) noexcept {
    base.prepend_mmtp_header_word0 = true;
    auto& m                        = base.mmtp_word0;
    m.mmtp_version                 = 0;
    m.packet_counter_flag          = false;
    m.fec_type                     = 0;
    m.reserved_r                   = 0;
    m.extension_flag               = false;
    m.rap_flag                     = false;
    m.reserved_two                 = 0;
    m.payload_type =
        (payload_type > 63u) ? static_cast<std::uint8_t>(63) : payload_type;
    m.packet_id = packet_id;
    return base;
}

/// Append **`mmtp_header_ts_psn`** after MMTP word‑0 (**requires** that the base
/// config already enables **`prepend_mmtp_header_word0`**).
[[nodiscard]] inline encoder_pipeline::config with_prepended_lab_mmtp_ts_psn(
    std::uint32_t timestamp,
    std::uint32_t packet_sequence_number,
    encoder_pipeline::config base) noexcept {
    base.prepend_mmtp_ts_psn                    = true;
    base.mmtp_ts_psn.timestamp                = timestamp;
    base.mmtp_ts_psn.packet_sequence_number   = packet_sequence_number;
    return base;
}

/// Append **`mmtp_header_counter32`** after **ts_psn** (**requires** that `base`
/// already has **`prepend_mmtp_ts_psn`** and **`prepend_mmtp_header_word0`**).
[[nodiscard]] inline encoder_pipeline::config with_prepended_lab_mmtp_packet_counter(
    std::uint32_t packet_counter,
    encoder_pipeline::config base) noexcept {
    base.prepend_mmtp_packet_counter = true;
    base.mmtp_packet_counter         = packet_counter;
    return base;
}

/// Append one **`mmtp_header_extension`** after optional **ts_psn** and optional
/// **packet_counter** (**requires**
/// **prepend_mmtp_header_word0** on `base`).
[[nodiscard]] inline encoder_pipeline::config with_prepended_lab_mmtp_extension(
    std::uint16_t extension_type,
    std::vector<std::byte> extension_value,
    encoder_pipeline::config base) noexcept {
    base.mmtp_extensions.push_back(
        mmtp_extension_tlv{extension_type, std::move(extension_value)});
    return base;
}

/// Append **`mmtp_payload_signalling_prefix`** after optional MMTP packet header
/// extensions (**requires** **prepend_mmtp_header_word0** on `base`).
[[nodiscard]] inline encoder_pipeline::config with_prepended_lab_mmtp_signalling_prefix(
    atsc3::mmtp_payload_signalling_prefix::decoded_t sig,
    encoder_pipeline::config base) noexcept {
    base.prepend_mmtp_signalling_prefix = true;
    base.mmtp_signalling_prefix        = sig;
    return base;
}

/// Append **`mmtp_payload_isobmff_prefix`** after optional MMTP packet header extensions
/// (**requires** **prepend_mmtp_header_word0** on `base`; **not** with signalling prefix).
[[nodiscard]] inline encoder_pipeline::config with_prepended_lab_mmtp_isobmff_prefix(
    atsc3::mmtp_payload_isobmff_prefix::decoded_t iso,
    encoder_pipeline::config base) noexcept {
    base.prepend_mmtp_isobmff_prefix = true;
    base.mmtp_isobmff_prefix         = iso;
    return base;
}

/// Append **`mmtp_payload_gfd_header`** after optional MMTP packet header extensions (**requires**
/// **prepend_mmtp_header_word0** on `base`; **not** with ISOBMFF or signalling prefix).
[[nodiscard]] inline encoder_pipeline::config with_prepended_lab_mmtp_gfd_header(
    atsc3::mmtp_payload_gfd_header::decoded_t gfd,
    encoder_pipeline::config base) noexcept {
    base.prepend_mmtp_gfd_header = true;
    base.mmtp_gfd_header         = gfd;
    return base;
}

/// Wire pattern follows `minimal_v1_c0` in `protocol/lct_rfc5651_word0.yaml`
/// (`header_length_words = 1` ⇒ word‑0 only).
[[nodiscard]] inline encoder_pipeline::config with_prepended_lab_lct_word0(
    std::uint8_t codepoint,
    encoder_pipeline::config base = {}) noexcept {
    base.prepend_rfc5651_lct_word0 = true;
    auto& w                        = base.lct_word0;
    w.lct_version                  = 1;
    w.congestion_flag_c            = 0;
    w.protocol_specific_indication = 0;
    w.tsi_flag                     = false;
    w.toi_flag                     = 0;
    w.half_word_flag               = false;
    w.reserved_two                 = 0;
    w.close_session                = false;
    w.close_object                 = false;
    w.header_length_words          = 1;
    w.codepoint                    = codepoint;
    return base;
}

/// Like `minimal_v1_c0` but `tsi_flag=true`, appends **`tsi`** BE32 after word‑0
/// (`header_length_words = 2`; no TOI on the wire in this lab path).
[[nodiscard]] inline encoder_pipeline::config with_prepended_lab_lct_word0_tsi(
    std::uint8_t codepoint,
    std::uint32_t tsi,
    encoder_pipeline::config base = {}) noexcept {
    base.prepend_rfc5651_lct_word0               = true;
    base.lct_transport_session_identifier        = tsi;
    auto& w                                      = base.lct_word0;
    w.lct_version                                = 1;
    w.congestion_flag_c                          = 0;
    w.protocol_specific_indication               = 0;
    w.tsi_flag                                   = true;
    w.toi_flag                                   = 0;
    w.half_word_flag                             = false;
    w.reserved_two                               = 0;
    w.close_session                              = false;
    w.close_object                               = false;
    w.header_length_words                        = 2;
    w.codepoint                                  = codepoint;
    return base;
}

/// Word‑0 + 32‑bit **TSI** (**S**=**1**) + 32‑bit **TOI** (**O**=**1** in `toi_flag`).
/// **`header_length_words = 3`**, **CCI** omitted (same lab caveat as sibling helpers).
[[nodiscard]] inline encoder_pipeline::config with_prepended_lab_lct_word0_tsi_toi(
    std::uint8_t codepoint,
    std::uint32_t tsi,
    std::uint32_t toi,
    encoder_pipeline::config base = {}) noexcept {
    base.prepend_rfc5651_lct_word0               = true;
    base.lct_transport_session_identifier        = tsi;
    base.lct_transport_object_identifier         = toi;
    auto& w                                      = base.lct_word0;
    w.lct_version                                = 1;
    w.congestion_flag_c                          = 0;
    w.protocol_specific_indication               = 0;
    w.tsi_flag                                   = true;
    w.toi_flag                                   = 1;
    w.half_word_flag                             = false;
    w.reserved_two                               = 0;
    w.close_session                              = false;
    w.close_object                               = false;
    w.header_length_words                        = 3;
    w.codepoint                                  = codepoint;
    return base;
}

/// Word‑0 + **O**`=1`: one 32-bit TOI (**`header_length_words = 2`**; no **S** /
/// TSI bit; **H**`=0`; `toi_flag` member stores **two-bit O**, value **1**).
[[nodiscard]] inline encoder_pipeline::config with_prepended_lab_lct_word0_toi(
    std::uint8_t codepoint,
    std::uint32_t toi,
    encoder_pipeline::config base = {}) noexcept {
    base.prepend_rfc5651_lct_word0        = true;
    base.lct_transport_object_identifier  = toi;
    auto& w                               = base.lct_word0;
    w.lct_version                         = 1;
    w.congestion_flag_c                   = 0;
    w.protocol_specific_indication        = 0;
    w.tsi_flag                            = false;
    w.toi_flag                            = 1;
    w.half_word_flag                      = false;
    w.reserved_two                        = 0;
    w.close_session                       = false;
    w.close_object                        = false;
    w.header_length_words                 = 2;
    w.codepoint                           = codepoint;
    return base;
}

}  // namespace atsc3::gw

int run_mmtp_signalling_prefix_with_mpt_asset_location0_in_consumption_message(
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


int run_mmtp_signalling_prefix_with_mpt_asset_id8_location_ipv4_in_consumption_message(
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


int run_mmtp_signalling_prefix_with_plt_package_entry_id8_location_ipv4_in_consumption_message(
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


int run_mmtp_signalling_prefix_with_mpt_asset_id8_location_ipv6_in_consumption_message(
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


int run_mmtp_signalling_prefix_with_plt_package_entry_id8_location_ipv6_in_consumption_message(
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


int run_mmtp_signalling_prefix_with_mpt_asset_location_ipv6_nz_in_consumption_message(
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


int run_mmtp_signalling_prefix_with_plt_package_entry_id8_location_ipv4_nz_in_consumption_message(
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


int run_mmtp_signalling_prefix_with_plt_package_entry_id8_location_ipv6_nz_in_consumption_message(
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


int run_mmtp_signalling_prefix_with_mpt_asset_id8_location_ipv4_nz_in_consumption_message(
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


int run_mmtp_signalling_prefix_with_mpt_asset_id8_location_ipv6_nz_in_consumption_message(
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


int run_mmtp_signalling_prefix_with_mpt_asset_id16_location_ipv4_in_consumption_message(
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


int run_mmtp_signalling_prefix_with_mpt_asset_id16_location_ipv4_nz_in_consumption_message(
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


int run_mmtp_signalling_prefix_with_mpt_asset_id16_location_ipv6_in_consumption_message(
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


int run_mmtp_signalling_prefix_with_mpt_asset_id16_location_ipv6_nz_in_consumption_message(
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


int run_mmtp_signalling_prefix_with_mpt_asset_id16_descriptors4_in_consumption_message(
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


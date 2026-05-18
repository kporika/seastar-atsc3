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
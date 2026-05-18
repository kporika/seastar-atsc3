            failures +=
                run_mmtp_signalling_prefix_with_mpt_asset_id8_location_ipv6_in_consumption_message(
                    "mmtp-signalling-si-mpt-asset-id8-location-ipv6-consumption-msg", 2, 0x10u, sig_e, aaa_ingress);
            }
            {
                static const char *aan_hex =
                    "200100370000000001000000000001010000000000010200000000000000000000ffff0a00000100000000000000000000ffffe000000113880000";
                std::vector<std::byte> aan_ingress;
                aan_ingress.reserve(59u);
                for (std::size_t i = 0; aan_hex[i] != '\0'; i += 2) {
                    const auto nyb = [](char c) -> unsigned {
                        if (c >= '0' && c <= '9') {
                            return static_cast<unsigned>(c - '0');
                        }
                        return static_cast<unsigned>(c - 'a' + 10);
                    };
                    aan_ingress.push_back(static_cast<std::byte>(
                        (nyb(aan_hex[i]) << 4) | nyb(aan_hex[i + 1]));

            failures +=
                run_mmtp_signalling_prefix_with_plt_package_entry_id8_location_ipv6_in_consumption_message(
                    "mmtp-signalling-si-plt-package-entry-id8-location-ipv6-consumption-msg", 2, 0x10u, sig_e, aab_ingress);
            }
            {
                atsc3::gw::encoder_pipeline::config cfg =
                    atsc3::gw::with_prepended_lab_mmtp_signalling_prefix(
                        sig_e,
                        atsc3::gw::with_prepended_lab_mmtp_word0(2, 0x10u);

            failures +=
                run_mmtp_signalling_prefix_with_mpt_asset_location_ipv6_nz_in_consumption_message(
                    "mmtp-signalling-si-mpt-asset-location-ipv6-nz-consumption-msg", 2, 0x10u, sig_e, aah_ingress);
            }
            {
                std::vector<std::byte> zy_ingress;
                zy_ingress.reserve(58u);
                for (const unsigned b :
                     {0x20u, 0x01u, 0x00u, 0x36u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u}) {
                    zy_ingress.push_back(static_cast<std::byte>(b);

            failures +=
                run_mmtp_signalling_prefix_with_plt_package_entry_id8_location_ipv6_nz_in_consumption_message(
                    "mmtp-signalling-si-plt-package-entry-id8-location-ipv6-nz-consumption-msg", 2, 0x10u, sig_e, aal_ingress);
            }
            {
                std::vector<std::byte> aab_ingress;
                aab_ingress.reserve(43u);
                for (const unsigned b :
                     {0x80u, 0x00u, 0x00u, 0x27u, 0x01u, 0x00u, 0x01u, 0x01u, 0x02u}) {
                    aab_ingress.push_back(static_cast<std::byte>(b);

            failures +=
                run_mmtp_signalling_prefix_with_mpt_asset_id8_location_ipv6_nz_in_consumption_message(
                    "mmtp-signalling-si-mpt-asset-id8-location-ipv6-nz-consumption-msg", 2, 0x10u, sig_e, aan_ingress);
            }

            {
                const char *hx = "200100200000000001000000000002010200000000000101000000000000000000000000";
                std::vector<std::byte> ingress;
                ingress.reserve(36u);
                for (std::size_t i = 0; hx[i] != '\0'; i += 2) {
                    const auto nyb = [](char c) -> unsigned {
                        if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
                        return static_cast<unsigned>(c - 'a' + 10);
                    };
                    ingress.push_back(static_cast<std::byte>((nyb(hx[i]) << 4) | nyb(hx[i + 1]));

            failures +=
                run_mmtp_signalling_prefix_with_mpt_asset_id16_location_ipv6_in_consumption_message(
                    "mmtp-signalling-si-mpt-asset-id16_location_ipv6-consumption-msg", 2, 0x10u, sig_e, ingress);
            }
            {
                const char *hx = "20010038000000000100000000000201020000000000010200000000000000000000ffff0a00000100000000000000000000ffffe000000113880000";
                std::vector<std::byte> ingress;
                ingress.reserve(60u);
                for (std::size_t i = 0; hx[i] != '\0'; i += 2) {
                    const auto nyb = [](char c) -> unsigned {
                        if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
                        return static_cast<unsigned>(c - 'a' + 10);
                    };
                    ingress.push_back(static_cast<std::byte>((nyb(hx[i]) << 4) | nyb(hx[i + 1]));

            failures +=
                run_mmtp_signalling_prefix_with_mpt_asset_id16_location_ipv6_nz_in_consumption_message(
                    "mmtp-signalling-si-mpt-asset-id16_location_ipv6_nz-consumption-msg", 2, 0x10u, sig_e, ingress);
            }
            {
                const char *hx = "20010019000000000100000000000201020000000000000004deadbeef";
                std::vector<std::byte> ingress;
                ingress.reserve(29u);
                for (std::size_t i = 0; hx[i] != '\0'; i += 2) {
                    const auto nyb = [](char c) -> unsigned {
                        if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
                        return static_cast<unsigned>(c - 'a' + 10);
                    };
                    ingress.push_back(static_cast<std::byte>((nyb(hx[i]) << 4) | nyb(hx[i + 1]));
/*
 * Copyright 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <cstdint>

namespace rootcanal::apcf {

/// Records the filtering parameters for the specified filter_index.
/// The associated advertising filters are added to their respective tables.
struct Filter {
  uint8_t filter_index;
  uint16_t feature_selection;
  uint16_t list_logic_type;
  uint8_t filter_logic_type;
  uint8_t rssi_high_thresh;
  bluetooth::hci::DeliveryMode delivery_mode;
  uint16_t onfound_timeout;
  uint8_t onfound_timeout_cnt;
  uint8_t rssi_low_thresh;
  uint16_t onlost_timeout;
  uint16_t num_of_tracking_entries;
};

/// Filter for matching the advertiser address.
struct BroadcasterAddressFilter {
  uint8_t filter_index;
  bluetooth::hci::Address broadcaster_address;
  bluetooth::hci::ApcfApplicationAddressType application_address_type;
};

/// Generic filter for GAP data information.
/// Used for matching Service UUID, Service Solicitation UUID,
/// Local Name, Manufacturer Data, Service Data.
struct GapDataFilter {
  uint8_t filter_index;
  std::vector<uint8_t> gap_data;
  std::vector<uint8_t> gap_data_mask;
};

/// Filter for matching the AD type.
struct AdTypeFilter {
  uint8_t filter_index;
  uint8_t ad_type;
  std::vector<uint8_t> ad_data;
  std::vector<uint8_t> ad_data_mask;
};

/// State of the APCF scanner.
struct ApcfScanner {
  bool enable{false};
  std::vector<Filter> filters{};
  std::vector<BroadcasterAddressFilter> broadcaster_address_filters{};
  std::vector<GapDataFilter> service_uuid_filters{};
  std::vector<GapDataFilter> service_solicitation_uuid_filters{};
  std::vector<GapDataFilter> local_name_filters{};
  std::vector<GapDataFilter> manufacturer_data_filters{};
  std::vector<GapDataFilter> service_data_filters{};
  std::vector<AdTypeFilter> ad_type_filters{};

  // Return if the APCF filter index is defined in the
  // list of filters.
  bool HasFilterIndex(uint8_t apcf_filter_index) const;

  // Remove the entries associated with the APCF filter index
  // from all tables.
  void ClearFilterIndex(uint8_t apcf_filter_index);

  // Remove all entries in all tables.
  void Clear();

  // Apply the requested modification to the selected
  // filter list.
  template <typename T>
  ErrorCode UpdateFilterList(std::vector<T>& filter_list,
                             size_t max_filter_list_size,
                             bluetooth::hci::ApcfAction action, T filter);
};

}  // namespace rootcanal::apcf

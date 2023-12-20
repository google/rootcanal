/*
 * Copyright 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License") {

 }
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

#include <algorithm>
#include <cstdint>

#include "log.h"
#include "model/controller/link_layer_controller.h"
#include "packets/hci_packets.h"

#pragma GCC diagnostic ignored "-Wunused-parameter"

namespace rootcanal::apcf {

bool ApcfScanner::HasFilterIndex(uint8_t apcf_filter_index) const {
  return std::any_of(std::begin(filters), std::end(filters), [&](auto it) {
    return it.filter_index == apcf_filter_index;
  });
}

void ApcfScanner::ClearFilterIndex(uint8_t apcf_filter_index) {
  broadcaster_address_filters.erase(
      std::remove_if(
          std::begin(broadcaster_address_filters),
          std::end(broadcaster_address_filters),
          [&](auto it) { return it.filter_index == apcf_filter_index; }),
      std::end(broadcaster_address_filters));
  service_uuid_filters.erase(
      std::remove_if(
          std::begin(service_uuid_filters), std::end(service_uuid_filters),
          [&](auto it) { return it.filter_index == apcf_filter_index; }),
      std::end(service_uuid_filters));
  service_solicitation_uuid_filters.erase(
      std::remove_if(
          std::begin(service_solicitation_uuid_filters),
          std::end(service_solicitation_uuid_filters),
          [&](auto it) { return it.filter_index == apcf_filter_index; }),
      std::end(service_solicitation_uuid_filters));
  local_name_filters.erase(
      std::remove_if(
          std::begin(local_name_filters), std::end(local_name_filters),
          [&](auto it) { return it.filter_index == apcf_filter_index; }),
      std::end(local_name_filters));
  manufacturer_data_filters.erase(
      std::remove_if(
          std::begin(manufacturer_data_filters),
          std::end(manufacturer_data_filters),
          [&](auto it) { return it.filter_index == apcf_filter_index; }),
      std::end(manufacturer_data_filters));
  service_data_filters.erase(
      std::remove_if(
          std::begin(service_data_filters), std::end(service_data_filters),
          [&](auto it) { return it.filter_index == apcf_filter_index; }),
      std::end(service_data_filters));
  ad_type_filters.erase(
      std::remove_if(
          std::begin(ad_type_filters), std::end(ad_type_filters),
          [&](auto it) { return it.filter_index == apcf_filter_index; }),
      std::end(ad_type_filters));
}

void ApcfScanner::Clear() {
  filters.clear();
  broadcaster_address_filters.clear();
  service_uuid_filters.clear();
  service_solicitation_uuid_filters.clear();
  local_name_filters.clear();
  manufacturer_data_filters.clear();
  service_data_filters.clear();
  ad_type_filters.clear();
}

template <typename T>
ErrorCode ApcfScanner::UpdateFilterList(std::vector<T>& filter_list,
                                        size_t max_filter_list_size,
                                        bluetooth::hci::ApcfAction action,
                                        T filter) {
  if (!HasFilterIndex(filter.filter_index)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  switch (action) {
    case ApcfAction::ADD: {
      if (filter_list.size() == max_filter_list_size) {
        return ErrorCode::MEMORY_CAPACITY_EXCEEDED;
      }

      filter_list.emplace_back(std::move(filter));
      return ErrorCode::SUCCESS;
    }
    case ApcfAction::DELETE: {
      // Delete will delete the specified data in the specified filter.
      filter_list.erase(
          std::remove_if(std::begin(filter_list), std::end(filter_list),
                         [&](auto it) { return it == filter; }),
          std::end(filter_list));
      return ErrorCode::SUCCESS;
    }
    case ApcfAction::CLEAR: {
      // Clear will clear all data in the specified filter.
      filter_list.erase(
          std::remove_if(
              std::begin(filter_list), std::end(filter_list),
              [&](auto it) { return it.filter_index == filter.filter_index; }),
          std::end(filter_list));
      return ErrorCode::SUCCESS;
    }
    default:
      break;
  }

  return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
}

bool operator==(BroadcasterAddressFilter const& lhs,
                BroadcasterAddressFilter const& rhs) {
  return lhs.filter_index == rhs.filter_index &&
         lhs.broadcaster_address == rhs.broadcaster_address &&
         lhs.application_address_type == rhs.application_address_type;
}

bool operator==(GapDataFilter const& lhs, GapDataFilter const& rhs) {
  return lhs.filter_index == rhs.filter_index && lhs.gap_data == rhs.gap_data &&
         lhs.gap_data_mask == rhs.gap_data_mask;
}

bool operator==(AdTypeFilter const& lhs, AdTypeFilter const& rhs) {
  return lhs.filter_index == rhs.filter_index && lhs.ad_type == rhs.ad_type &&
         lhs.ad_data == rhs.ad_data && lhs.ad_data_mask == rhs.ad_data_mask;
}

}  // namespace rootcanal::apcf

namespace rootcanal {

using bluetooth::hci::ApcfAction;

ErrorCode LinkLayerController::LeApcfEnable(bool apcf_enable) {
  apcf_scanner_.enable = apcf_enable;
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::LeApcfAddFilteringParameters(
    uint8_t apcf_filter_index, uint16_t apcf_feature_selection,
    uint16_t apcf_list_logic_type, uint8_t apcf_filter_logic_type,
    uint8_t rssi_high_thresh, bluetooth::hci::DeliveryMode delivery_mode,
    uint16_t onfound_timeout, uint8_t onfound_timeout_cnt,
    uint8_t rssi_low_thresh, uint16_t onlost_timeout,
    uint16_t num_of_tracking_entries, uint8_t* apcf_available_spaces) {
  *apcf_available_spaces =
      properties_.le_apcf_filter_list_size - apcf_scanner_.filters.size();

      if (apcf_scanner_.HasFilterIndex(apcf_filter_index)) {
        INFO(id_, "apcf filter index {} already configured", apcf_filter_index);
        return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
      }

      if (*apcf_available_spaces == 0) {
        INFO(id_, "reached max number of apcf filters");
        return ErrorCode::MEMORY_CAPACITY_EXCEEDED;
      }

      apcf_scanner_.filters.push_back(rootcanal::apcf::Filter{
          .filter_index = apcf_filter_index,
          .feature_selection = apcf_feature_selection,
          .list_logic_type = apcf_list_logic_type,
          .filter_logic_type = apcf_filter_logic_type,
          .rssi_high_thresh = rssi_high_thresh,
          .delivery_mode = delivery_mode,
          .onfound_timeout = onfound_timeout,
          .onfound_timeout_cnt = onfound_timeout_cnt,
          .rssi_low_thresh = rssi_low_thresh,
          .onlost_timeout = onlost_timeout,
          .num_of_tracking_entries = num_of_tracking_entries,
      });

      *apcf_available_spaces -= 1;
      return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::LeApcfDeleteFilteringParameters(
    uint8_t apcf_filter_index, uint8_t* apcf_available_spaces) {
      *apcf_available_spaces =
          properties_.le_apcf_filter_list_size - apcf_scanner_.filters.size();

      if (!apcf_scanner_.HasFilterIndex(apcf_filter_index)) {
        INFO(id_, "apcf filter index {} is not configured", apcf_filter_index);
        return ErrorCode::UNKNOWN_CONNECTION;
      }

      apcf_scanner_.filters.erase(
          std::remove_if(
              std::begin(apcf_scanner_.filters),
              std::end(apcf_scanner_.filters),
              [&](auto it) { return it.filter_index == apcf_filter_index; }),
          std::end(apcf_scanner_.filters));

      apcf_scanner_.ClearFilterIndex(apcf_filter_index);
      *apcf_available_spaces += 1;
      return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::LeApcfClearFilteringParameters(
    uint8_t* apcf_available_spaces) {
      apcf_scanner_.Clear();
      *apcf_available_spaces = properties_.le_apcf_filter_list_size;
      return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::LeApcfBroadcasterAddress(
    ApcfAction apcf_action, uint8_t apcf_filter_index,
    bluetooth::hci::Address apcf_broadcaster_address,
    bluetooth::hci::ApcfApplicationAddressType apcf_application_address_type,
    uint8_t* apcf_available_spaces) {
  ErrorCode status = apcf_scanner_.UpdateFilterList(
      apcf_scanner_.broadcaster_address_filters,
      properties_.le_apcf_broadcaster_address_filter_list_size, apcf_action,
      rootcanal::apcf::BroadcasterAddressFilter{
          .filter_index = apcf_filter_index,
          .broadcaster_address = apcf_broadcaster_address,
          .application_address_type = apcf_application_address_type,
      });

  *apcf_available_spaces =
      properties_.le_apcf_broadcaster_address_filter_list_size -
      apcf_scanner_.broadcaster_address_filters.size();

  return status;
}

ErrorCode LinkLayerController::LeApcfServiceUuid(
    ApcfAction apcf_action, uint8_t apcf_filter_index,
    std::vector<uint8_t> apcf_uuid_data, uint8_t* apcf_available_spaces) {
  size_t uuid_data_size = apcf_uuid_data.size() / 2;
  std::vector<uint8_t> uuid_data(std::begin(apcf_uuid_data),
                                 std::begin(apcf_uuid_data) + uuid_data_size);
  std::vector<uint8_t> uuid_data_mask(
      std::begin(apcf_uuid_data) + uuid_data_size, std::end(apcf_uuid_data));

  ErrorCode status = apcf_scanner_.UpdateFilterList(
      apcf_scanner_.service_uuid_filters,
      properties_.le_apcf_service_uuid_filter_list_size, apcf_action,
      rootcanal::apcf::GapDataFilter{
          .filter_index = apcf_filter_index,
          .gap_data = uuid_data,
          .gap_data_mask = uuid_data_mask,
      });

  *apcf_available_spaces = properties_.le_apcf_service_uuid_filter_list_size -
                           apcf_scanner_.service_uuid_filters.size();

  return status;
}

ErrorCode LinkLayerController::LeApcfServiceSolicitationUuid(
    ApcfAction apcf_action, uint8_t apcf_filter_index,
    std::vector<uint8_t> apcf_uuid_data, uint8_t* apcf_available_spaces) {
  size_t uuid_data_size = apcf_uuid_data.size() / 2;
  std::vector<uint8_t> uuid_data(std::begin(apcf_uuid_data),
                                 std::begin(apcf_uuid_data) + uuid_data_size);
  std::vector<uint8_t> uuid_data_mask(
      std::begin(apcf_uuid_data) + uuid_data_size, std::end(apcf_uuid_data));

  ErrorCode status = apcf_scanner_.UpdateFilterList(
      apcf_scanner_.service_solicitation_uuid_filters,
      properties_.le_apcf_service_solicitation_uuid_filter_list_size,
      apcf_action,
      rootcanal::apcf::GapDataFilter{
          .filter_index = apcf_filter_index,
          .gap_data = uuid_data,
          .gap_data_mask = uuid_data_mask,
      });

  *apcf_available_spaces =
      properties_.le_apcf_service_solicitation_uuid_filter_list_size -
      apcf_scanner_.service_solicitation_uuid_filters.size();

  return status;
}

ErrorCode LinkLayerController::LeApcfLocalName(
    ApcfAction apcf_action, uint8_t apcf_filter_index,
    std::vector<uint8_t> apcf_local_name, uint8_t* apcf_available_spaces) {
  size_t local_name_size = apcf_local_name.size() / 2;
  std::vector<uint8_t> local_name(
      std::begin(apcf_local_name),
      std::begin(apcf_local_name) + local_name_size);
  std::vector<uint8_t> local_name_mask(
      std::begin(apcf_local_name) + local_name_size, std::end(apcf_local_name));

  ErrorCode status = apcf_scanner_.UpdateFilterList(
      apcf_scanner_.local_name_filters,
      properties_.le_apcf_local_name_filter_list_size, apcf_action,
      rootcanal::apcf::GapDataFilter{
          .filter_index = apcf_filter_index,
          .gap_data = local_name,
          .gap_data_mask = local_name_mask,
      });

  *apcf_available_spaces = properties_.le_apcf_local_name_filter_list_size -
                           apcf_scanner_.local_name_filters.size();

  return status;
}

ErrorCode LinkLayerController::LeApcfManufacturerData(
    ApcfAction apcf_action, uint8_t apcf_filter_index,
    std::vector<uint8_t> apcf_manufacturer_data,
    uint8_t* apcf_available_spaces) {
  size_t manufacturer_data_size = apcf_manufacturer_data.size() / 2;
  std::vector<uint8_t> manufacturer_data(
      std::begin(apcf_manufacturer_data),
      std::begin(apcf_manufacturer_data) + manufacturer_data_size);
  std::vector<uint8_t> manufacturer_data_mask(
      std::begin(apcf_manufacturer_data) + manufacturer_data_size,
      std::end(apcf_manufacturer_data));

  ErrorCode status = apcf_scanner_.UpdateFilterList(
      apcf_scanner_.manufacturer_data_filters,
      properties_.le_apcf_manufacturer_data_filter_list_size, apcf_action,
      rootcanal::apcf::GapDataFilter{
          .filter_index = apcf_filter_index,
          .gap_data = manufacturer_data,
          .gap_data_mask = manufacturer_data_mask,
      });

  *apcf_available_spaces =
      properties_.le_apcf_manufacturer_data_filter_list_size -
      apcf_scanner_.manufacturer_data_filters.size();

  return status;
}

ErrorCode LinkLayerController::LeApcfServiceData(
    ApcfAction apcf_action, uint8_t apcf_filter_index,
    std::vector<uint8_t> apcf_service_data, uint8_t* apcf_available_spaces) {
  size_t service_data_size = apcf_service_data.size() / 2;
  std::vector<uint8_t> service_data(
      std::begin(apcf_service_data),
      std::begin(apcf_service_data) + service_data_size);
  std::vector<uint8_t> service_data_mask(
      std::begin(apcf_service_data) + service_data_size,
      std::end(apcf_service_data));

  ErrorCode status = apcf_scanner_.UpdateFilterList(
      apcf_scanner_.service_data_filters,
      properties_.le_apcf_service_data_filter_list_size, apcf_action,
      rootcanal::apcf::GapDataFilter{
          .filter_index = apcf_filter_index,
          .gap_data = service_data,
          .gap_data_mask = service_data_mask,
      });

  *apcf_available_spaces = properties_.le_apcf_service_data_filter_list_size -
                           apcf_scanner_.service_data_filters.size();

  return status;
}

ErrorCode LinkLayerController::LeApcfAdTypeFilter(
    ApcfAction apcf_action, uint8_t apcf_filter_index, uint8_t apcf_ad_type,
    std::vector<uint8_t> apcf_ad_data, std::vector<uint8_t> apcf_ad_data_mask,
    uint8_t* apcf_available_spaces) {
  ErrorCode status = apcf_scanner_.UpdateFilterList(
      apcf_scanner_.ad_type_filters,
      properties_.le_apcf_ad_type_filter_list_size, apcf_action,
      rootcanal::apcf::AdTypeFilter{
          .filter_index = apcf_filter_index,
          .ad_type = apcf_ad_type,
          .ad_data = std::move(apcf_ad_data),
          .ad_data_mask = std::move(apcf_ad_data_mask),
      });

  *apcf_available_spaces = properties_.le_apcf_ad_type_filter_list_size -
                           apcf_scanner_.ad_type_filters.size();

  return status;
}

}  // namespace rootcanal

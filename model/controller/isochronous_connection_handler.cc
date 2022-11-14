/*
 * Copyright 2020 The Android Open Source Project
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

#include "model/controller/isochronous_connection_handler.h"

#include "hci/address.h"
#include "log.h"

namespace rootcanal {

using bluetooth::hci::ErrorCode;

std::unique_ptr<bluetooth::hci::LeSetCigParametersCompleteBuilder>
IsochronousConnectionHandler::SetCigParameters(
    GroupParameters group_parameters, std::vector<StreamParameters>& streams,
    std::vector<uint16_t> handles) {
  if (groups_.count(group_parameters.id) != 0) {
    if (groups_.at(group_parameters.id).HasStreams()) {
      return bluetooth::hci::LeSetCigParametersCompleteBuilder::Create(
          1, ErrorCode::COMMAND_DISALLOWED, group_parameters.id, {});
    }
    groups_.erase(group_parameters.id);
  }

  // TODO: Limit groups and return ErrorCode::MEMORY_CAPACITY_EXCEEDED
  // TODO: Limit connections return ErrorCode::CONNECTION_LIMIT_EXCEEDED

  std::vector<ConnectedIsochronousStream> created_streams;
  for (size_t i = 0; i < streams.size(); i++) {
    streams[i].handle = handles[i];
    streams[i].group_id = group_parameters.id;
    created_streams.emplace_back(streams[i]);
    cis_to_group_.emplace(handles[i], group_parameters.id);
  }

  groups_.emplace(std::piecewise_construct,
                  std::forward_as_tuple(group_parameters.id),
                  std::forward_as_tuple(group_parameters, created_streams));

  return bluetooth::hci::LeSetCigParametersCompleteBuilder::Create(
      1, ErrorCode::SUCCESS, group_parameters.id, handles);
}

bluetooth::hci::ErrorCode IsochronousConnectionHandler::RemoveCig(
    uint8_t cig_id) {
  if (groups_.count(cig_id) != 0) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }
  if (groups_.at(cig_id).HasConnectedStream()) {
    return ErrorCode::COMMAND_DISALLOWED;
  }
  groups_.erase(cig_id);
  auto copy = cis_to_group_;
  cis_to_group_.clear();
  for (auto pair : cis_to_group_) {
    if (pair.second != cig_id) {
      cis_to_group_.emplace(pair.first, pair.second);
    }
  }
  return ErrorCode::SUCCESS;
}

bool IsochronousConnectionHandler::HasHandle(uint16_t handle) const {
  return cis_to_group_.count(handle) != 0;
}

uint8_t IsochronousConnectionHandler::GetGroupId(uint16_t handle) const {
  return cis_to_group_.at(handle);
}

StreamParameters IsochronousConnectionHandler::GetStreamParameters(
    uint16_t handle) const {
  return groups_.at(cis_to_group_.at(handle)).GetStreamParameters(handle);
}

GroupParameters IsochronousConnectionHandler::GetGroupParameters(
    uint8_t id) const {
  return groups_.at(id).GetParameters();
}

bool IsochronousConnectionHandler::GetStreamIsConnected(uint16_t handle) const {
  return groups_.at(cis_to_group_.at(handle)).StreamIsConnected(handle);
}

}  // namespace rootcanal

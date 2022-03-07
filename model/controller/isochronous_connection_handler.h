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

#pragma once

#include <cstdint>
#include <map>
#include <set>

#include "hci/hci_packets.h"
#include "model/controller/connected_isochronous_group.h"
#include "model/controller/connected_isochronous_stream.h"

namespace rootcanal {

class IsochronousConnectionHandler {
 public:
  IsochronousConnectionHandler() = default;
  virtual ~IsochronousConnectionHandler() = default;

  std::unique_ptr<bluetooth::hci::LeSetCigParametersCompleteBuilder>
  SetCigParameters(GroupParameters parameters,
                   std::vector<StreamParameters>& streams,
                   std::vector<uint16_t> handles);

  bluetooth::hci::ErrorCode RemoveCig(uint8_t cig_id);

  bool HasHandle(uint16_t handle) const;

  uint8_t GetGroupId(uint16_t) const;

  StreamParameters GetStreamParameters(uint16_t handle) const;
  GroupParameters GetGroupParameters(uint8_t id) const;

  bool GetStreamIsConnected(uint16_t handle) const;

  std::vector<uint16_t> GetCigHandles(uint8_t id) const;

 private:
  std::map<uint8_t, ConnectedIsochronousGroup> groups_;
  std::map<uint16_t, uint8_t> cis_to_group_;
};

}  // namespace rootcanal

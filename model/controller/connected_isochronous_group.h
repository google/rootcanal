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

#include <algorithm>
#include <cstdint>

#include "hci/hci_packets.h"
#include "model/controller/connected_isochronous_stream.h"

namespace rootcanal {

class GroupParameters {
 public:
  uint8_t id;
  uint32_t sdu_interval_m_to_s;
  uint32_t sdu_interval_s_to_m;
  bool interleaved;
  bool framed;
  uint16_t max_transport_latency_m_to_s;
  uint16_t max_transport_latency_s_to_m;
};

class ConnectedIsochronousGroup {
 public:
  ConnectedIsochronousGroup(GroupParameters parameters,
                            std::vector<ConnectedIsochronousStream> streams)
      : parameters_(parameters), streams_(std::move(streams)) {}

  virtual ~ConnectedIsochronousGroup() = default;

  bool HasConnectedStream() const {
    return std::any_of(
        streams_.begin(), streams_.end(),
        [&](const ConnectedIsochronousStream& s) { return s.IsConnected(); });
  }

  bool StreamIsConnected(uint16_t handle) const {
    return streams_.at(handle).IsConnected();
  }

  bool HasStreams() const { return !streams_.empty(); }

  GroupParameters GetParameters() const { return parameters_; }

  StreamParameters GetStreamParameters(uint16_t handle) const {
    for (const auto& stream : streams_) {
      if (stream.GetHandle() == handle) {
        return stream.GetConfig();
      }
    }
    return StreamParameters{};
  }

 private:
  GroupParameters parameters_;
  std::vector<ConnectedIsochronousStream> streams_;
};

}  // namespace rootcanal

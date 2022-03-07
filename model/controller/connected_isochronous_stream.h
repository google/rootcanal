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

#include "hci/hci_packets.h"

namespace rootcanal {

class StreamParameters {
 public:
  uint8_t group_id;
  uint8_t stream_id;
  uint16_t max_sdu_m_to_s;
  uint16_t max_sdu_s_to_m;
  uint8_t rtn_m_to_s;
  uint8_t rtn_s_to_m;
  uint16_t handle;
};

class ConnectedIsochronousStream {
 public:
  ConnectedIsochronousStream(StreamParameters& stream_param)
      : config_(stream_param) {}

  virtual ~ConnectedIsochronousStream() = default;

  bool IsConnected() const { return is_connected_; }
  StreamParameters GetConfig() const { return config_; }

  uint16_t GetHandle() const { return config_.handle; }
  void Connect() { is_connected_ = true; }

  void Disconnect() { is_connected_ = false; }

 private:
  bool is_connected_{false};
  StreamParameters config_;
};
}  // namespace rootcanal

/*
 * Copyright 2021 The Android Open Source Project
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
#include <optional>

#include "hci/address.h"
#include "model/setup/async_manager.h"

namespace rootcanal {

using ::bluetooth::hci::Address;

/*
 * Notes about SCO / eSCO connection establishment:
 *
 * - Connections will always be established if possible as eSCO connections.
 * The LMP parameter negotiation is skipped, instead the required parameters
 * are directly sent to the peer.
 *
 * - If an synchronous connection setup fails with eSCO parameter negotiation,
 * it is _not_ retried with SCO parameter negotiation.
 *
 * - If the parameters are compatible with the values returned from
 * HCI Accept Synchronous Connection Request on the peer,
 * the peer selects a valid link configuration which it returns
 * in response.
 */

struct ScoLinkParameters {
  uint8_t transmission_interval;
  uint8_t retransmission_window;
  uint16_t rx_packet_length;
  uint16_t tx_packet_length;
  uint8_t air_mode;
  bool extended;
};

struct ScoConnectionParameters {
  uint32_t transmit_bandwidth;
  uint32_t receive_bandwidth;
  uint16_t max_latency;  // 0-3 reserved, 0xFFFF = don't care
  uint16_t voice_setting;
  uint8_t retransmission_effort;
  uint16_t packet_type;

  // Return true if packet_type enables extended SCO packets.
  bool IsExtended() const;

  // Return the link parameters for these connection parameters, if the
  // parameters are coherent, none otherwise.
  std::optional<ScoLinkParameters> GetLinkParameters() const;
};

enum ScoState {
  SCO_STATE_CLOSED = 0,
  SCO_STATE_PENDING,
  SCO_STATE_SENT_ESCO_CONNECTION_REQUEST,
  SCO_STATE_SENT_SCO_CONNECTION_REQUEST,
  SCO_STATE_OPENED,
};

enum ScoDatapath {
  NORMAL = 0,   // data is provided by the host over HCI
  SPOOFED = 1,  // rootcanal generates data itself
};

class ScoConnection {
 public:
  ScoConnection(Address address, ScoConnectionParameters const& parameters,
                ScoState state, ScoDatapath datapath, bool legacy)
      : address_(address),
        parameters_(parameters),
        link_parameters_(),
        state_(state),
        datapath_(datapath),
        legacy_(legacy) {}

  ~ScoConnection();

  bool IsLegacy() const { return legacy_; }
  Address GetAddress() const { return address_; }
  ScoState GetState() const { return state_; }
  void SetState(ScoState state) { state_ = state; }

  void StartStream(std::function<AsyncTaskId()> startStream);
  void StopStream(std::function<void(AsyncTaskId)> stopStream);

  ScoConnectionParameters GetConnectionParameters() const {
    return parameters_;
  }
  ScoLinkParameters GetLinkParameters() const { return link_parameters_; }
  void SetLinkParameters(ScoLinkParameters const& parameters) {
    link_parameters_ = parameters;
  }

  // Negotiate the connection parameters.
  // Update the local connection parameters with negotiated values.
  // Return true if the negotiation was successful, false otherwise.
  bool NegotiateLinkParameters(ScoConnectionParameters const& peer);

  ScoDatapath GetDatapath() const { return datapath_; }

 private:
  Address address_;
  ScoConnectionParameters parameters_;
  ScoLinkParameters link_parameters_;
  ScoState state_;

  // whether we use HCI, spoof the data, or potential future datapaths
  ScoDatapath datapath_;

  // The handle of the async task managing the SCO stream, used to simulate
  // offloaded input. None if HCI is used for input packets.
  std::optional<AsyncTaskId> stream_handle_{};

  // Mark connections opened with the HCI command Add SCO Connection.
  // The connection status is reported with HCI Connection Complete event
  // rather than HCI Synchronous Connection Complete event.
  bool legacy_;
};

}  // namespace rootcanal

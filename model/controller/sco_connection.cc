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

#include "sco_connection.h"

#include <hci/hci_packets.h>
#include <log.h>

#include <vector>

using namespace rootcanal;
using namespace bluetooth::hci;

ScoConnection::~ScoConnection() { ASSERT(!stream_handle_.has_value()); }

bool ScoConnectionParameters::IsExtended() const {
  uint16_t legacy = (uint16_t)SynchronousPacketTypeBits::HV1_ALLOWED |
                    (uint16_t)SynchronousPacketTypeBits::HV2_ALLOWED |
                    (uint16_t)SynchronousPacketTypeBits::HV3_ALLOWED;
  uint16_t edr = (uint16_t)SynchronousPacketTypeBits::NO_2_EV3_ALLOWED |
                 (uint16_t)SynchronousPacketTypeBits::NO_3_EV3_ALLOWED |
                 (uint16_t)SynchronousPacketTypeBits::NO_2_EV5_ALLOWED |
                 (uint16_t)SynchronousPacketTypeBits::NO_3_EV5_ALLOWED;
  return ((packet_type ^ edr) & ~legacy) != 0;
}

std::optional<ScoLinkParameters> ScoConnectionParameters::GetLinkParameters()
    const {
  // Coding conversion.
  uint8_t air_coding_to_air_mode[] = {
      0x02,  // CVSD
      0x00,  // u-law
      0x01,  // A-law
      0x03,  // transparent data
  };

  // Prioritize eSCO connections.
  // Packets HV1, HV2, HV3 are tested in a second phase.
  struct Packet {
    unsigned length;
    unsigned slots;

    Packet(unsigned length, unsigned slots) : length(length), slots(slots) {}
  };

  std::vector<Packet> accepted_packets;
  accepted_packets.push_back(Packet(0, 1));  // POLL/NULL

  if (packet_type & (uint16_t)SynchronousPacketTypeBits::EV3_ALLOWED) {
    accepted_packets.push_back(Packet(30, 1));
  }
  if (packet_type & (uint16_t)SynchronousPacketTypeBits::EV4_ALLOWED) {
    accepted_packets.push_back(Packet(120, 3));
  }
  if (packet_type & (uint16_t)SynchronousPacketTypeBits::EV5_ALLOWED) {
    accepted_packets.push_back(Packet(180, 3));
  }
  if ((packet_type & (uint16_t)SynchronousPacketTypeBits::NO_2_EV3_ALLOWED) ==
      0) {
    accepted_packets.push_back(Packet(60, 1));
  }
  if ((packet_type & (uint16_t)SynchronousPacketTypeBits::NO_3_EV3_ALLOWED) ==
      0) {
    accepted_packets.push_back(Packet(360, 3));
  }
  if ((packet_type & (uint16_t)SynchronousPacketTypeBits::NO_2_EV5_ALLOWED) ==
      0) {
    accepted_packets.push_back(Packet(90, 1));
  }
  if ((packet_type & (uint16_t)SynchronousPacketTypeBits::NO_3_EV5_ALLOWED) ==
      0) {
    accepted_packets.push_back(Packet(540, 3));
  }
  // Ignore empty bandwidths for now.
  if (transmit_bandwidth == 0 || receive_bandwidth == 0) {
    LOG_WARN("eSCO transmissions with null bandwidths are not supported");
    return {};
  }

  // Bandwidth usage of the optimal selection.
  double best_bandwidth_usage = 1.0;
  std::optional<ScoLinkParameters> best_parameters = {};

  // Explore all packet combinations, select the valid one
  // with smallest actual bandwidth usage.
  for (auto tx : accepted_packets) {
    if (tx.length == 0) {
      continue;
    }

    unsigned tx_max_interval = (1600 * tx.length) / transmit_bandwidth;

    for (auto rx : accepted_packets) {
      if (rx.length == 0) {
        continue;
      }

      LOG_INFO("Testing combination %u/%u : %u/%u", tx.length, tx.slots,
               rx.length, rx.slots);

      unsigned rx_max_interval = (1600 * rx.length) / receive_bandwidth;

      // Choose the best interval satisfying both.
      unsigned transmission_interval =
          std::min(tx_max_interval, rx_max_interval);
      transmission_interval -= transmission_interval % 2;
      transmission_interval = std::min(transmission_interval, 254U);

      LOG_INFO("Transmission interval: %u slots", transmission_interval);

      // Compute retransmission window.
      unsigned retransmission_window =
          retransmission_effort ==
                  (uint8_t)RetransmissionEffort::NO_RETRANSMISSION
              ? 0
          : retransmission_effort ==
                  (uint8_t)RetransmissionEffort::OPTIMIZED_FOR_POWER
              ? rx.slots + tx.slots
          : retransmission_effort ==
                  (uint8_t)RetransmissionEffort::OPTIMIZED_FOR_LINK_QUALITY
              ? 2 * (rx.slots + tx.slots)
              : 0;

      LOG_INFO("Retransmission window: %u slots", retransmission_window);

      // Compute transmission window and validate latency.
      unsigned transmission_window =
          tx.slots + rx.slots + retransmission_window;

      // Validate window.
      if (transmission_window > transmission_interval) {
        // Oops
        continue;
      }

      // Compute and validate latency.
      unsigned latency = (transmission_window * 1250) / 2;

      LOG_INFO("Latency: %u us (max %u us)", latency, max_latency * 1000U);

      if (latency > (1000 * max_latency)) {
        // Oops
        continue;
      }

      // We got a valid configuration.
      // Evaluate the actual bandwidth usage.
      double bandwidth_usage =
          (double)transmission_window / (double)transmission_interval;

      if (bandwidth_usage <= best_bandwidth_usage) {
        LOG_INFO("Valid combination!");

        uint16_t tx_packet_length =
            (transmit_bandwidth * transmission_interval + 1600 - 1) / 1600;
        uint16_t rx_packet_length =
            (receive_bandwidth * transmission_interval + 1600 - 1) / 1600;
        uint8_t air_coding = voice_setting & 0x3;

        best_bandwidth_usage = bandwidth_usage;
        best_parameters = {
            (uint8_t)transmission_interval,
            (uint8_t)retransmission_window,
            rx_packet_length,
            tx_packet_length,
            air_coding_to_air_mode[air_coding],
            true,
        };
      }
    }
  }

  if (best_parameters.has_value()) {
    return best_parameters;
  }

  // Parameter negotiation for SCO connections:
  // Check packet types and validate bandwidth and latency requirements.

  if (retransmission_effort ==
          (uint8_t)RetransmissionEffort::OPTIMIZED_FOR_POWER ||
      retransmission_effort ==
          (uint8_t)RetransmissionEffort::OPTIMIZED_FOR_LINK_QUALITY) {
    LOG_WARN("SCO Retransmission effort must be None or Don't care");
    return {};
  }

  uint8_t transmission_interval;
  uint16_t packet_length;
  uint8_t air_coding = voice_setting & 0x3;

  if (packet_type & (uint16_t)SynchronousPacketTypeBits::HV3_ALLOWED) {
    transmission_interval = 6;
    packet_length = 30;
  } else if (packet_type & (uint16_t)SynchronousPacketTypeBits::HV2_ALLOWED) {
    transmission_interval = 4;
    packet_length = 20;
  } else if (packet_type & (uint16_t)SynchronousPacketTypeBits::HV1_ALLOWED) {
    transmission_interval = 2;
    packet_length = 10;
  } else {
    LOG_WARN("No SCO packet type enabled");
    return {};
  }

  best_parameters = {
      transmission_interval,
      0,
      packet_length,
      packet_length,
      air_coding_to_air_mode[air_coding],
      false,
  };
  return best_parameters;
}

bool ScoConnection::NegotiateLinkParameters(
    ScoConnectionParameters const& peer) {
  if (peer.transmit_bandwidth != 0xffff &&
      peer.transmit_bandwidth != parameters_.receive_bandwidth) {
    LOG_WARN("Transmit bandwidth requirements cannot be met");
    return false;
  }

  if (state_ == SCO_STATE_SENT_ESCO_CONNECTION_REQUEST &&
      peer.receive_bandwidth != 0xffff &&
      peer.receive_bandwidth != parameters_.transmit_bandwidth) {
    LOG_WARN("Receive bandwidth requirements cannot be met");
    return false;
  }

  // mask out the air coding format bits before comparison, as per 5.3 Vol
  // 4E 6.12
  if ((peer.voice_setting & ~0x3) != (parameters_.voice_setting & ~0x3)) {
    LOG_WARN("Voice setting requirements cannot be met");
    LOG_WARN("Remote voice setting: 0x%04x",
             static_cast<unsigned>(parameters_.voice_setting));
    LOG_WARN("Local voice setting: 0x%04x",
             static_cast<unsigned>(peer.voice_setting));
    return false;
  }

  uint16_t packet_type = (peer.packet_type & parameters_.packet_type) & 0x3f;
  packet_type |= (peer.packet_type | parameters_.packet_type) & 0x3c0;

  if (packet_type == 0x3c0) {
    LOG_WARN("Packet type requirements cannot be met");
    LOG_WARN("Remote packet type: 0x%04x",
             static_cast<unsigned>(parameters_.packet_type));
    LOG_WARN("Local packet type: 0x%04x",
             static_cast<unsigned>(peer.packet_type));
    return false;
  }

  uint16_t max_latency =
      peer.max_latency == 0xffff ? parameters_.max_latency
      : parameters_.max_latency == 0xffff
          ? peer.max_latency
          : std::min(peer.max_latency, parameters_.max_latency);

  uint8_t retransmission_effort;
  if (state_ == SCO_STATE_SENT_SCO_CONNECTION_REQUEST) {
    retransmission_effort = (uint8_t)RetransmissionEffort::NO_RETRANSMISSION;
  } else if (peer.retransmission_effort == parameters_.retransmission_effort ||
             peer.retransmission_effort ==
                 (uint8_t)RetransmissionEffort::DO_NOT_CARE) {
    retransmission_effort = parameters_.retransmission_effort;
  } else if (parameters_.retransmission_effort ==
             (uint8_t)RetransmissionEffort::DO_NOT_CARE) {
    retransmission_effort = peer.retransmission_effort;
  } else if (peer.retransmission_effort ==
                 (uint8_t)RetransmissionEffort::NO_RETRANSMISSION ||
             parameters_.retransmission_effort ==
                 (uint8_t)RetransmissionEffort::NO_RETRANSMISSION) {
    LOG_WARN("Retransmission effort requirements cannot be met");
    LOG_WARN("Remote retransmission effort: 0x%02x",
             static_cast<unsigned>(parameters_.retransmission_effort));
    LOG_WARN("Local retransmission effort: 0x%04x",
             static_cast<unsigned>(peer.retransmission_effort));
    return false;
  } else {
    retransmission_effort = (uint8_t)RetransmissionEffort::OPTIMIZED_FOR_POWER;
  }

  ScoConnectionParameters negotiated_parameters = {
      parameters_.transmit_bandwidth,
      parameters_.receive_bandwidth,
      max_latency,
      parameters_.voice_setting,
      retransmission_effort,
      packet_type};

  auto link_parameters = negotiated_parameters.GetLinkParameters();
  if (link_parameters.has_value()) {
    link_parameters_ = link_parameters.value();
    LOG_INFO("Negotiated link parameters for SCO connection:");
    LOG_INFO("  Transmission interval: %u slots",
             static_cast<unsigned>(link_parameters_.transmission_interval));
    LOG_INFO("  Retransmission window: %u slots",
             static_cast<unsigned>(link_parameters_.retransmission_window));
    LOG_INFO("  RX packet length: %u bytes",
             static_cast<unsigned>(link_parameters_.rx_packet_length));
    LOG_INFO("  TX packet length: %u bytes",
             static_cast<unsigned>(link_parameters_.tx_packet_length));
    LOG_INFO("  Air mode: %u",
             static_cast<unsigned>(link_parameters_.air_mode));
  } else {
    LOG_WARN("Failed to derive link parameters");
  }
  return link_parameters.has_value();
}

void ScoConnection::StartStream(std::function<AsyncTaskId()> startStream) {
  ASSERT(!stream_handle_.has_value());
  if (datapath_ == ScoDatapath::SPOOFED) {
    stream_handle_ = startStream();
  }
}

void ScoConnection::StopStream(std::function<void(AsyncTaskId)> stopStream) {
  if (stream_handle_.has_value()) {
    stopStream(*stream_handle_);
  }
  stream_handle_ = std::nullopt;
}

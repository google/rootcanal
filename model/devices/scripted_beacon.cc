/*
 * Copyright 2016 The Android Open Source Project
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

#include "scripted_beacon.h"

#include <unistd.h>

#include <cstdint>
#include <fstream>

#include "log.h"
#include "model/devices/scripted_beacon_ble_payload.pb.h"
#include "model/setup/device_boutique.h"

#ifdef _WIN32
#define F_OK 00
#define R_OK 04
#endif

using std::vector;
using std::chrono::steady_clock;
using std::chrono::system_clock;

namespace rootcanal {
using namespace model::packets;
using namespace std::chrono_literals;

bool ScriptedBeacon::registered_ =
    DeviceBoutique::Register("scripted_beacon", &ScriptedBeacon::Create);

ScriptedBeacon::ScriptedBeacon(const vector<std::string>& args) : Beacon(args) {
  advertising_interval_ = 1280ms;
  advertising_type_ = LegacyAdvertisingType::ADV_SCAN_IND;
  advertising_data_ = {
      0x18 /* Length */,
      0x09 /* TYPE_NAME_CMPL */,
      'g',
      'D',
      'e',
      'v',
      'i',
      'c',
      'e',
      '-',
      's',
      'c',
      'r',
      'i',
      'p',
      't',
      'e',
      'd',
      '-',
      'b',
      'e',
      'a',
      'c',
      'o',
      'n',
      0x02 /* Length */,
      0x01 /* TYPE_FLAG */,
      0x4 /* BREDR_NOT_SPT */ | 0x2 /* GEN_DISC_FLAG */,
  };

  scan_response_data_ = {
      0x05 /* Length */, 0x08 /* TYPE_NAME_SHORT */, 'g', 'b', 'e', 'a'};

  LOG_INFO("Scripted_beacon registered %s", registered_ ? "true" : "false");

  if (args.size() >= 4) {
    config_file_ = args[2];
    events_file_ = args[3];
    set_state(PlaybackEvent::INITIALIZED);
  } else {
    LOG_ERROR(
        "Initialization failed, need playback and playback events file "
        "arguments");
  }
}

bool has_time_elapsed(steady_clock::time_point time_point) {
  return steady_clock::now() > time_point;
}

static void populate_event(PlaybackEvent* event,
                           PlaybackEvent::PlaybackEventType type) {
  LOG_INFO("Adding event: %d", type);
  event->set_type(type);
  event->set_secs_since_epoch(system_clock::now().time_since_epoch().count());
}

// Adds events to events file; we won't be able to post anything to the file
// until we set to permissive mode in tests. No events are posted until then.
void ScriptedBeacon::set_state(PlaybackEvent::PlaybackEventType state) {
  PlaybackEvent event;
  current_state_ = state;
  if (!events_ostream_.is_open()) {
    events_ostream_.open(events_file_,
                         std::ios::out | std::ios::binary | std::ios::trunc);
    if (!events_ostream_.is_open()) {
      LOG_INFO("Events file not opened yet, for event: %d", state);
      return;
    }
  }
  populate_event(&event, state);
  event.SerializeToOstream(&events_ostream_);
  events_ostream_.flush();
}

void ScriptedBeacon::Tick() {
  switch (current_state_) {
    case PlaybackEvent::INITIALIZED:
      Beacon::Tick();
      break;
    case PlaybackEvent::SCANNED_ONCE:
      next_check_time_ =
          steady_clock::now() + steady_clock::duration(std::chrono::seconds(1));
      set_state(PlaybackEvent::WAITING_FOR_FILE);
      break;
    case PlaybackEvent::WAITING_FOR_FILE:
      if (!has_time_elapsed(next_check_time_)) {
        return;
      }
      next_check_time_ =
          steady_clock::now() + steady_clock::duration(std::chrono::seconds(1));
      if (access(config_file_.c_str(), F_OK) == -1) {
        return;
      }
      set_state(PlaybackEvent::WAITING_FOR_FILE_TO_BE_READABLE);
      break;
    case PlaybackEvent::WAITING_FOR_FILE_TO_BE_READABLE:
      if (access(config_file_.c_str(), R_OK) == -1) {
        return;
      }
      set_state(PlaybackEvent::PARSING_FILE);
      break;
    case PlaybackEvent::PARSING_FILE: {
      if (!has_time_elapsed(next_check_time_)) {
        return;
      }
      std::fstream input(config_file_, std::ios::in | std::ios::binary);
      if (!ble_ad_list_.ParseFromIstream(&input)) {
        LOG_ERROR("Cannot parse playback file %s", config_file_.c_str());
        set_state(PlaybackEvent::FILE_PARSING_FAILED);
        return;
      }
      set_state(PlaybackEvent::PLAYBACK_STARTED);
      LOG_INFO("Starting Ble advertisement playback from file: %s",
               config_file_.c_str());
      next_ad_.ad_time = steady_clock::now();
      get_next_advertisement();
      input.close();
      break;
    }
    case PlaybackEvent::PLAYBACK_STARTED: {
      while (has_time_elapsed(next_ad_.ad_time)) {
        auto ad = model::packets::LeLegacyAdvertisingPduBuilder::Create(
            next_ad_.address, Address::kEmpty /* Destination */,
            AddressType::RANDOM, AddressType::PUBLIC,
            LegacyAdvertisingType::ADV_NONCONN_IND, next_ad_.ad);
        SendLinkLayerPacket(std::move(ad), Phy::Type::LOW_ENERGY);
        if (packet_num_ < ble_ad_list_.advertisements().size()) {
          get_next_advertisement();
        } else {
          set_state(PlaybackEvent::PLAYBACK_ENDED);
          if (events_ostream_.is_open()) {
            events_ostream_.close();
          }
          LOG_INFO(
              "Completed Ble advertisement playback from file: %s with %d "
              "packets",
              config_file_.c_str(), packet_num_);
          break;
        }
      }
    } break;
    case PlaybackEvent::FILE_PARSING_FAILED:
    case PlaybackEvent::PLAYBACK_ENDED:
    case PlaybackEvent::UNKNOWN:
      return;
  }
}

void ScriptedBeacon::ReceiveLinkLayerPacket(
    model::packets::LinkLayerPacketView packet, Phy::Type /*type*/,
    int8_t /*rssi*/) {
  if (current_state_ == PlaybackEvent::INITIALIZED) {
    if (packet.GetDestinationAddress() == address_ &&
        packet.GetType() == PacketType::LE_SCAN) {
      set_state(PlaybackEvent::SCANNED_ONCE);
      SendLinkLayerPacket(
          std::move(model::packets::LeScanResponseBuilder::Create(
              address_, packet.GetSourceAddress(), AddressType::PUBLIC,
              std::vector(scan_response_data_.begin(),
                          scan_response_data_.end()))),
          Phy::Type::LOW_ENERGY);
    }
  }
}

void ScriptedBeacon::get_next_advertisement() {
  std::string payload = ble_ad_list_.advertisements(packet_num_).payload();
  std::string mac_address =
      ble_ad_list_.advertisements(packet_num_).mac_address();
  uint32_t delay_before_send_ms =
      ble_ad_list_.advertisements(packet_num_).delay_before_send_ms();
  next_ad_.ad.assign(payload.begin(), payload.end());
  if (Address::IsValidAddress(mac_address)) {
    // formatted string with colons like "12:34:56:78:9a:bc"
    Address::FromString(mac_address, next_ad_.address);
  } else if (mac_address.size() == Address::kLength) {
    // six-byte binary address
    std::vector<uint8_t> mac_vector(mac_address.cbegin(), mac_address.cend());
    next_ad_.address.Address::FromOctets(mac_vector.data());
  } else {
    Address::FromString("BA:D0:AD:BA:D0:AD", next_ad_.address);
  }
  next_ad_.ad_time +=
      steady_clock::duration(std::chrono::milliseconds(delay_before_send_ms));
  packet_num_++;
}
}  // namespace rootcanal

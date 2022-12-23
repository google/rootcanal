/*
 * Copyright 2017 The Android Open Source Project
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

#include <array>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "hci/address.h"

namespace rootcanal {

using ::bluetooth::hci::Address;

enum class PairingType : uint8_t {
  AUTO_CONFIRMATION,
  CONFIRM_Y_N,
  DISPLAY_PIN,
  DISPLAY_AND_CONFIRM,
  INPUT_PIN,
  OUT_OF_BAND,
  PEER_HAS_OUT_OF_BAND,
  INVALID = 0xff,
};

enum class IoCapabilityType : uint8_t {
  DISPLAY_ONLY = 0,
  DISPLAY_YES_NO = 1,
  KEYBOARD_ONLY = 2,
  NO_INPUT_NO_OUTPUT = 3,
  INVALID = 0xff,
};

enum class AuthenticationType : uint8_t {
  NO_BONDING = 0,
  NO_BONDING_MITM = 1,
  DEDICATED_BONDING = 2,
  DEDICATED_BONDING_MITM = 3,
  GENERAL_BONDING = 4,
  GENERAL_BONDING_MITM = 5,
  INVALID = 0xff,
};

// Encapsulate the details of storing and retrieving keys.
class SecurityManager {
 public:
  SecurityManager(uint16_t num_keys) : max_keys_(num_keys) {}
  virtual ~SecurityManager() = default;

  uint16_t DeleteAllKeys();
  uint16_t DeleteKey(const Address& addr);
  uint16_t ReadAllKeys() const;
  uint16_t ReadKey(const Address& addr) const;
  uint16_t WriteKey(const Address& addr, const std::array<uint8_t, 16>& key);
  uint16_t ReadCapacity() const { return max_keys_; };

  const std::array<uint8_t, 16>& GetKey(const Address& addr) const;

  void AuthenticationRequest(const Address& addr, uint16_t handle,
                             bool initiator);
  void AuthenticationRequestFinished();

  bool AuthenticationInProgress();
  bool IsInitiator();
  uint16_t GetAuthenticationHandle();
  Address GetAuthenticationAddress();

  void SetPinRequested(const Address& addr);
  bool GetPinRequested(const Address& addr);
  void SetLocalPin(const Address& peer, const std::vector<uint8_t>& pin);
  void SetRemotePin(const Address& peer, const std::vector<uint8_t>& pin);
  bool GetLocalPinResponseReceived(const Address& peer);
  bool GetRemotePinResponseReceived(const Address& peer);
  bool PinCompare();

  void SetPeerIoCapability(const Address& addr, uint8_t io_capability,
                           uint8_t oob_present_flag,
                           uint8_t authentication_requirements);
  void SetLocalIoCapability(const Address& peer, uint8_t io_capability,
                            uint8_t oob_present_flag,
                            uint8_t authentication_requirements);

  PairingType GetSimplePairingType();

  void InvalidateIoCapabilities();

 private:
  uint16_t max_keys_;
  std::unordered_map<std::string, std::array<uint8_t, 16>> key_store_;

  bool peer_capabilities_valid_{false};
  IoCapabilityType peer_io_capability_{IoCapabilityType::DISPLAY_ONLY};
  uint8_t peer_oob_present_flag_{0};
  AuthenticationType peer_authentication_requirements_{
      AuthenticationType::NO_BONDING};
  bool peer_pin_requested_{false};
  bool peer_pin_received_{false};
  std::vector<uint8_t> peer_pin_;

  bool host_capabilities_valid_{false};
  IoCapabilityType host_io_capability_{IoCapabilityType::DISPLAY_ONLY};
  uint8_t host_oob_present_flag_{0};
  AuthenticationType host_authentication_requirements_{
      AuthenticationType::NO_BONDING};
  std::vector<uint8_t> host_pin_;
  bool host_pin_received_{false};

  bool authenticating_{false};
  uint16_t current_handle_{};
  Address peer_address_{};
  bool initiator_{false};
};

}  // namespace rootcanal

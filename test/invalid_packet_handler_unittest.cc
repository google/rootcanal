/*
 * Copyright 2024 The Android Open Source Project
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

#include <gtest/gtest.h>

#include "log.h"
#include "model/controller/dual_mode_controller.h"

namespace rootcanal {

using namespace bluetooth::hci;

class InvalidPacketHandlerTest : public ::testing::Test {
 public:
  InvalidPacketHandlerTest() = default;
  ~InvalidPacketHandlerTest() override = default;

 protected:
  DualModeController controller_;
};

// Set Event Mask command with missing parameters.
const std::vector<uint8_t> kInvalidCommandPacket = {0x01, 0x0C, 0x03,
                                                    0xff, 0xff, 0xff};

// Hardware Error event with code 0x43.
const std::vector<uint8_t> kHardwareErrorEvent = {0x10, 0x01, 0x43};

TEST_F(InvalidPacketHandlerTest, DefaultHandler) {
  // Validate that the default invalid packet handler causes
  // an abort when an invalid packet is received.
  ASSERT_DEATH(controller_.HandleCommand(std::make_shared<std::vector<uint8_t>>(
                   kInvalidCommandPacket)),
               "");
}

TEST_F(InvalidPacketHandlerTest, RegisteredHandler) {
  static struct {
    uint32_t id;
    InvalidPacketReason reason;
    std::vector<uint8_t> bytes;
  } invalid_packet;

  static std::vector<uint8_t> hci_event;

  // Validate that the registered invalid packet handler is correctly
  // invoked when an invalid packet is received.
  controller_.RegisterInvalidPacketHandler(
      [&](uint32_t id, InvalidPacketReason reason, std::string,
          std::vector<uint8_t> const& bytes) {
        invalid_packet.id = id;
        invalid_packet.reason = reason;
        invalid_packet.bytes = bytes;
      });

  controller_.RegisterEventChannel(
      [&](std::shared_ptr<std::vector<uint8_t>> packet) {
        hci_event = std::vector<uint8_t>(*packet);
      });

  controller_.HandleCommand(
      std::make_shared<std::vector<uint8_t>>(kInvalidCommandPacket));
  ASSERT_EQ(invalid_packet.id, controller_.id_);
  ASSERT_EQ(invalid_packet.reason, InvalidPacketReason::kParseError);
  ASSERT_EQ(invalid_packet.bytes, kInvalidCommandPacket);
  ASSERT_EQ(hci_event, kHardwareErrorEvent);
}

}  // namespace rootcanal

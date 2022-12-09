/*
 * Copyright 2022 The Android Open Source Project
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

#include "model/controller/link_layer_controller.h"

namespace rootcanal {

using namespace bluetooth::hci;

class RpaGenerationTest : public ::testing::Test {
 public:
  RpaGenerationTest() = default;
  ~RpaGenerationTest() override = default;
};

TEST_F(RpaGenerationTest, Test) {
  std::array<uint8_t, rootcanal::LinkLayerController::kIrkSize> irk = {
      0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
      0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
  };

  AddressWithType rpa{rootcanal::LinkLayerController::generate_rpa(irk),
                      AddressType::RANDOM_DEVICE_ADDRESS};

  ASSERT_TRUE(rpa.IsRpa());
  ASSERT_TRUE(rpa.IsRpaThatMatchesIrk(irk));
}

}  // namespace rootcanal

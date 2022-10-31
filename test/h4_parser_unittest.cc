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

#include "model/hci/h4_parser.h"

#include <gtest/gtest.h>

namespace rootcanal {
using PacketData = std::vector<uint8_t>;

class H4ParserTest : public ::testing::Test {
 public:
 protected:
  void SetUp() override {
    packet_.clear();
    parser_.Reset();
  }

  void TearDown() override { parser_.Reset(); }

  void PacketReadCallback(const std::vector<uint8_t>& packet) {
    packet_ = std::move(packet);
  }

 protected:
  H4Parser parser_{
      [&](auto p) {
        type_ = PacketType::COMMAND;
        PacketReadCallback(p);
      },
      [&](auto p) {
        type_ = PacketType::EVENT;
        PacketReadCallback(p);
      },
      [&](auto p) {
        type_ = PacketType::ACL;
        PacketReadCallback(p);
      },
      [&](auto p) {
        type_ = PacketType::SCO;
        PacketReadCallback(p);
      },
      [&](auto p) {
        type_ = PacketType::ISO;
        PacketReadCallback(p);
      },
  };
  PacketData packet_;
  PacketType type_;
};

TEST_F(H4ParserTest, InitiallyExpectOneByte) {
  ASSERT_EQ(1, (int)parser_.BytesRequested());
}

TEST_F(H4ParserTest, SwitchStateAfterType) {
  uint8_t typ = (uint8_t)PacketType::ACL;
  ASSERT_TRUE(parser_.Consume(&typ, 1));
  ASSERT_EQ(parser_.CurrentState(), H4Parser::State::HCI_PREAMBLE);
}

TEST_F(H4ParserTest, RequestedBytesDecreases) {
  // Make sure that the requested bytes is monotonically decreasing
  // for the requested types.
  uint8_t typ = (uint8_t)PacketType::ACL;
  ASSERT_TRUE(parser_.Consume(&typ, 1));
  auto wanted = parser_.BytesRequested();
  while (wanted > 0) {
    ASSERT_EQ(wanted, parser_.BytesRequested());
    ASSERT_TRUE(parser_.Consume(&typ, 1));
    wanted--;
  }

  ASSERT_EQ(parser_.CurrentState(), H4Parser::State::HCI_PAYLOAD);
  wanted = parser_.BytesRequested();
  while (wanted > 0) {
    ASSERT_EQ(wanted, parser_.BytesRequested());
    ASSERT_TRUE(parser_.Consume(&typ, 1));
    wanted--;
  }

  // A callback should have been invoked.
  ASSERT_LT(0, (int)packet_.size());
}

TEST_F(H4ParserTest, RejectNoData) {
  // You need to give us something!
  PacketData bad_bit;
  ASSERT_FALSE(parser_.Consume(bad_bit.data(), bad_bit.size()));
}

TEST_F(H4ParserTest, TooMuchIsDeath) {
  PacketData bad_bit({0xfd});
  ASSERT_DEATH(parser_.Consume(bad_bit.data(), parser_.BytesRequested() + 1),
               "More bytes read .* than expected .*!");
}

TEST_F(H4ParserTest, WrongTypeIsDeath) {
  PacketData bad_bit({0xfd});
  ASSERT_DEATH(parser_.Consume(bad_bit.data(), bad_bit.size()),
               "Unimplemented packet type.*");
}

TEST_F(H4ParserTest, CallsTheRightCallbacks) {
  // Make sure that the proper type of callback is invoked.
  std::vector<PacketType> types({PacketType::ACL, PacketType::SCO,
                                 PacketType::COMMAND, PacketType::EVENT,
                                 PacketType::ISO});
  for (auto packetType : types) {
    // Configure the incoming packet.
    uint8_t typ = (uint8_t)packetType;
    ASSERT_TRUE(parser_.Consume(&typ, 1));

    // Feed data as long as this packet is not complete.
    while (parser_.CurrentState() != H4Parser::State::HCI_TYPE) {
      PacketData data;
      for (uint32_t i = 0; i < parser_.BytesRequested(); i++) {
        data.push_back((uint8_t)i);
      }
      ASSERT_TRUE(parser_.Consume(data.data(), data.size()));
    }

    // The proper callbacks should have been invoked.
    ASSERT_LT(0, (int)packet_.size());
    ASSERT_EQ(packetType, type_);
  }
}

}  // namespace rootcanal

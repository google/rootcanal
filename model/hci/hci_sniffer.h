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
#include <fstream>
#include <memory>
#include <ostream>

#include "model/hci/h4.h"
#include "model/hci/hci_transport.h"

namespace rootcanal {

enum class PacketDirection : uint8_t {
  CONTROLLER_TO_HOST = 0,
  HOST_TO_CONTROLLER = 1,
};

// A Hci Transport that logs all the in and out going
// packets to a stream.
class HciSniffer : public HciTransport {
 public:
  HciSniffer(std::shared_ptr<HciTransport> transport,
             std::shared_ptr<std::ostream> outputStream = nullptr);
  ~HciSniffer() = default;

  static std::shared_ptr<HciTransport> Create(
      std::shared_ptr<HciTransport> transport,
      std::shared_ptr<std::ostream> outputStream = nullptr) {
    return std::make_shared<HciSniffer>(transport, outputStream);
  }

  // Sets and initializes the output stream
  void SetOutputStream(std::shared_ptr<std::ostream> outputStream);

  void SendEvent(const std::vector<uint8_t>& packet) override;

  void SendAcl(const std::vector<uint8_t>& packet) override;

  void SendSco(const std::vector<uint8_t>& packet) override;

  void SendIso(const std::vector<uint8_t>& packet) override;

  void RegisterCallbacks(PacketCallback command_callback,
                         PacketCallback acl_callback,
                         PacketCallback sco_callback,
                         PacketCallback iso_callback,
                         CloseCallback close_callback) override;

  void TimerTick() override;

  void Close() override;

 private:
  void AppendRecord(PacketDirection direction, PacketType type,
                    const std::vector<uint8_t>& packet);

  std::shared_ptr<std::ostream> output_;
  std::shared_ptr<HciTransport> transport_;
};

}  // namespace rootcanal

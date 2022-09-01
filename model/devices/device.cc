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

#include "device.h"

#include <vector>

namespace rootcanal {

std::string Device::ToString() const {
  return GetTypeString() + "@" + address_.ToString();
}

void Device::RegisterPhyLayer(std::shared_ptr<PhyLayer> phy) {
  phy_layers_.push_back(phy);
}

void Device::UnregisterPhyLayers() {
  for (auto phy : phy_layers_) {
    if (phy != nullptr) {
      phy->Unregister();
    }
  }
  phy_layers_.clear();
}

void Device::UnregisterPhyLayer(Phy::Type phy_type, uint32_t factory_id) {
  for (auto& phy : phy_layers_) {
    if (phy != nullptr && phy->IsFactoryId(factory_id) &&
        phy->GetType() == phy_type) {
      phy->Unregister();
      phy.reset();
      return;
    }
  }
}

void Device::SendLinkLayerPacket(
    std::shared_ptr<model::packets::LinkLayerPacketBuilder> to_send,
    Phy::Type phy_type) {
  for (auto phy : phy_layers_) {
    if (phy != nullptr && phy->GetType() == phy_type) {
      phy->Send(to_send);
    }
  }
}

void Device::SendLinkLayerPacket(model::packets::LinkLayerPacketView to_send,
                                 Phy::Type phy_type) {
  for (auto phy : phy_layers_) {
    if (phy != nullptr && phy->GetType() == phy_type) {
      phy->Send(to_send);
    }
  }
}

void Device::Close() {
  if (close_callback_) {
    close_callback_();
  }
}

void Device::RegisterCloseCallback(std::function<void()> close_callback) {
  close_callback_ = close_callback;
}

}  // namespace rootcanal

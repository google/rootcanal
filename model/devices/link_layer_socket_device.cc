/*
 * Copyright 2018 The Android Open Source Project
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

#include "link_layer_socket_device.h"

#include <type_traits>  // for remove_extent_t

#include "log.h"                  // for ASSERT, LOG_INFO, LOG_ERROR, LOG_WARN
#include "packet/bit_inserter.h"  // for BitInserter
#include "packet/iterator.h"      // for Iterator
#include "packet/packet_view.h"   // for PacketView, kLittleEndian
#include "packet/raw_builder.h"   // for RawBuilder
#include "packet/view.h"          // for View
#include "phy.h"                  // for Phy, Phy::Type

using std::vector;

namespace rootcanal {

LinkLayerSocketDevice::LinkLayerSocketDevice(
    std::shared_ptr<AsyncDataChannel> socket_fd, Phy::Type phy_type)
    : socket_(socket_fd),
      phy_type_(phy_type),
      size_bytes_(std::make_shared<std::vector<uint8_t>>(kSizeBytes)) {}

void LinkLayerSocketDevice::Tick() {
  if (receiving_size_) {
    ssize_t bytes_received =
        socket_->Recv(size_bytes_->data() + offset_, kSizeBytes);
    if (bytes_received <= 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // Nothing available yet.
        // LOG_DEBUG("Nothing available yet...");
        return;
      }
      LOG_INFO("Closing socket, received: %zd, %s", bytes_received,
               strerror(errno));
      Close();
      return;
    }
    if ((size_t)bytes_received < bytes_left_) {
      bytes_left_ -= bytes_received;
      offset_ += bytes_received;
      return;
    }
    bluetooth::packet::PacketView<bluetooth::packet::kLittleEndian> size(
        {bluetooth::packet::View(size_bytes_, 0, kSizeBytes)});
    bytes_left_ = size.begin().extract<uint32_t>();
    received_ = std::make_shared<std::vector<uint8_t>>(bytes_left_);
    offset_ = 0;
    receiving_size_ = false;
  }
  ssize_t bytes_received =
      socket_->Recv(received_->data() + offset_, bytes_left_);
  if (bytes_received <= 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      // Nothing available yet.
      // LOG_DEBUG("Nothing available yet...");
      return;
    }
    LOG_INFO("Closing socket, received: %zd, %s", bytes_received,
             strerror(errno));
    Close();
    return;
  }
  if ((size_t)bytes_received < bytes_left_) {
    bytes_left_ -= bytes_received;
    offset_ += bytes_received;
    return;
  }
  bytes_left_ = kSizeBytes;
  offset_ = 0;
  receiving_size_ = true;
  SendLinkLayerPacket(*received_, phy_type_);
}

void LinkLayerSocketDevice::Close() {
  if (socket_) {
    socket_->Close();
  }
  Device::Close();
}

void LinkLayerSocketDevice::ReceiveLinkLayerPacket(
    model::packets::LinkLayerPacketView packet, Phy::Type /*type*/,
    int8_t /*rssi*/) {
  auto size_packet = bluetooth::packet::RawBuilder();
  size_packet.AddOctets4(packet.size());
  std::vector<uint8_t> size_bytes;
  bluetooth::packet::BitInserter bit_inserter(size_bytes);
  size_packet.Serialize(bit_inserter);

  if (socket_->Send(size_bytes.data(), size_bytes.size()) == kSizeBytes) {
    std::vector<uint8_t> payload_bytes{packet.begin(), packet.end()};
    socket_->Send(payload_bytes.data(), payload_bytes.size());
  }
}

}  // namespace rootcanal

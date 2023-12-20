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

#include "model/devices/link_layer_socket_device.h"

#include <packet_runtime.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <memory>
#include <utility>
#include <vector>

#include "log.h"
#include "model/devices/device.h"
#include "packets/link_layer_packets.h"
#include "phy.h"

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
        // DEBUG("Nothing available yet...");
        return;
      }
      INFO("Closing socket, received: {}, {}", bytes_received, strerror(errno));
      Close();
      return;
    }
    if ((size_t)bytes_received < bytes_left_) {
      bytes_left_ -= bytes_received;
      offset_ += bytes_received;
      return;
    }
    pdl::packet::slice size(std::move(size_bytes_));
    bytes_left_ = size.read_le<uint32_t>();
    received_ = std::make_shared<std::vector<uint8_t>>(bytes_left_);
    offset_ = 0;
    receiving_size_ = false;
  }
  ssize_t bytes_received =
      socket_->Recv(received_->data() + offset_, bytes_left_);
  if (bytes_received <= 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      // Nothing available yet.
      // DEBUG("Nothing available yet...");
      return;
    }
    INFO("Closing socket, received: {}, {}", bytes_received, strerror(errno));
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
  std::vector<uint8_t> packet_bytes = packet.bytes().bytes();
  std::vector<uint8_t> size_bytes;
  pdl::packet::Builder::write_le<uint32_t>(size_bytes, packet_bytes.size());

  if (socket_->Send(size_bytes.data(), size_bytes.size()) == kSizeBytes) {
    socket_->Send(packet_bytes.data(), packet_bytes.size());
  }
}

}  // namespace rootcanal

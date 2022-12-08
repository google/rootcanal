/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <algorithm>
#include <array>
#include <cstdint>

namespace rootcanal::crypto {

constexpr int kOctet16Length = 16;
using Octet16 = std::array<uint8_t, kOctet16Length>;

Octet16 aes_128(const Octet16& key, const Octet16& message);

/* This function computes AES_128(key, message). |key| must be 128bit.
 * |message| can be at most 16 bytes long, its length in bytes is given in
 * |length| */
inline Octet16 aes_128(const Octet16& key, const uint8_t* message,
                       const uint8_t length) {
  Octet16 padded_message{0};
  std::copy(message, message + length, padded_message.begin());
  return aes_128(key, padded_message);
}

}  // namespace rootcanal::crypto

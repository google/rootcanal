/*
 * Copyright 2023 The Android Open Source Project
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

#include "crypto/crypto.h"

#include <openssl/aes.h>

#include <algorithm>

namespace rootcanal::crypto {

/* This function computes AES_128(key, message) */
Octet16 aes_128(const Octet16& key, const Octet16& message) {
  Octet16 key_reversed;
  Octet16 message_reversed;
  Octet16 output;

  std::reverse_copy(key.begin(), key.end(), key_reversed.begin());
  std::reverse_copy(message.begin(), message.end(), message_reversed.begin());

  AES_KEY aes_key;
  (void)AES_set_encrypt_key(key_reversed.data(), 128, &aes_key);
  (void)AES_encrypt(message_reversed.data(), output.data(), &aes_key);

  std::reverse(output.begin(), output.end());
  return output;
}

}  // namespace rootcanal::crypto

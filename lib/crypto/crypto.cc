
#include "crypto/crypto.h"

#include <openssl/aes.h>

#include <algorithm>
#include <cstdint>

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

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

#pragma once

#include <fmt/core.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>

#include "crypto/crypto.h"
#include "hci/address.h"
#include "packets/hci_packets.h"

namespace bluetooth::hci {

class AddressWithType final {
 public:
  AddressWithType(Address address, AddressType address_type)
      : address_(std::move(address)), address_type_(address_type) {}

  explicit AddressWithType()
      : address_(Address::kEmpty),
        address_type_(AddressType::PUBLIC_DEVICE_ADDRESS) {}

  inline Address GetAddress() const { return address_; }

  inline AddressType GetAddressType() const { return address_type_; }

  /* Is this an Resolvable Private Address ? */
  inline bool IsRpa() const {
    return address_type_ == hci::AddressType::RANDOM_DEVICE_ADDRESS &&
           ((address_.data())[5] & 0xc0) == 0x40;
  }

  /* Is this an Resolvable Private Address, that was generated from given irk ?
   */
  bool IsRpaThatMatchesIrk(const rootcanal::crypto::Octet16& irk) const {
    if (!IsRpa()) {
      return false;
    }

    /* use the 3 MSB of bd address as prand */
    uint8_t prand[3];
    prand[0] = address_.address[3];
    prand[1] = address_.address[4];
    prand[2] = address_.address[5];
    /* generate X = E irk(R0, R1, R2) and R is random address 3 LSO */
    rootcanal::crypto::Octet16 computed_hash =
        rootcanal::crypto::aes_128(irk, &prand[0], 3);
    uint8_t hash[3];
    hash[0] = address_.address[0];
    hash[1] = address_.address[1];
    hash[2] = address_.address[2];
    return memcmp(computed_hash.data(), &hash[0], 3) == 0;
  }

  bool operator<(const AddressWithType& rhs) const {
    return (address_ != rhs.address_) ? address_ < rhs.address_
                                      : address_type_ < rhs.address_type_;
  }
  bool operator==(const AddressWithType& rhs) const {
    return address_ == rhs.address_ && address_type_ == rhs.address_type_;
  }
  bool operator>(const AddressWithType& rhs) const { return (rhs < *this); }
  bool operator<=(const AddressWithType& rhs) const { return !(*this > rhs); }
  bool operator>=(const AddressWithType& rhs) const { return !(*this < rhs); }
  bool operator!=(const AddressWithType& rhs) const { return !(*this == rhs); }

  FilterAcceptListAddressType ToFilterAcceptListAddressType() const {
    switch (address_type_) {
      case AddressType::PUBLIC_DEVICE_ADDRESS:
      case AddressType::PUBLIC_IDENTITY_ADDRESS:
        return FilterAcceptListAddressType::PUBLIC;
      case AddressType::RANDOM_DEVICE_ADDRESS:
      case AddressType::RANDOM_IDENTITY_ADDRESS:
        return FilterAcceptListAddressType::RANDOM;
    }
  }

  PeerAddressType ToPeerAddressType() const {
    switch (address_type_) {
      case AddressType::PUBLIC_DEVICE_ADDRESS:
      case AddressType::PUBLIC_IDENTITY_ADDRESS:
        return PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS;
      case AddressType::RANDOM_DEVICE_ADDRESS:
      case AddressType::RANDOM_IDENTITY_ADDRESS:
        return PeerAddressType::RANDOM_DEVICE_OR_IDENTITY_ADDRESS;
    }
  }

  std::string ToString() const {
    std::stringstream ss;
    ss << address_ << "[" << AddressTypeText(address_type_) << "]";
    return ss.str();
  }

 private:
  Address address_;
  AddressType address_type_;
};

inline std::ostream& operator<<(std::ostream& os, const AddressWithType& a) {
  os << a.ToString();
  return os;
}

}  // namespace bluetooth::hci

namespace std {
template <>
struct hash<bluetooth::hci::AddressWithType> {
  std::size_t operator()(const bluetooth::hci::AddressWithType& address) const {
    uint64_t address_int = static_cast<uint64_t>(address.GetAddressType());
    for (auto b : address.GetAddress().address) {
      address_int <<= 8;
      address_int |= b;
    }
    return std::hash<uint64_t>{}(address_int);
  }
};
}  // namespace std

template <>
struct fmt::formatter<bluetooth::hci::AddressWithType> {
  // Presentation format: 'x' - lowercase, 'X' - uppercase.
  char presentation = 'x';

  // Parses format specifications of the form ['x' | 'X'].
  constexpr auto parse(format_parse_context& ctx)
      -> format_parse_context::iterator {
    // Parse the presentation format and store it in the formatter:
    auto it = ctx.begin();
    auto end = ctx.end();
    if (it != end && (*it == 'x' || *it == 'X')) {
      presentation = *it++;
    }

    // Check if reached the end of the range:
    if (it != end && *it != '}') {
      throw_format_error("invalid format");
    }

    // Return an iterator past the end of the parsed range:
    return it;
  }

  // Formats the address a using the parsed format specification (presentation)
  // stored in this formatter.
  auto format(const bluetooth::hci::AddressWithType& a,
              format_context& ctx) const -> format_context::iterator {
    auto out = presentation == 'x'
                   ? fmt::format_to(ctx.out(), "{:x}", a.GetAddress())
                   : fmt::format_to(ctx.out(), "{:X}", a.GetAddress());
    return fmt::format_to(out, "[{}]", AddressTypeText(a.GetAddressType()));
  }
};

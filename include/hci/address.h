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

#pragma once

#include <fmt/core.h>
#include <packet_runtime.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <initializer_list>
#include <optional>
#include <ostream>
#include <string>
#include <vector>

namespace bluetooth::hci {

class Address final : public pdl::packet::Builder {
 public:
  static constexpr size_t kLength = 6;

  // Bluetooth MAC address bytes saved in little endian format.
  // The address MSB is address[5], the address LSB is address[0].
  // Note that the textual representation follows the big endian format,
  // ie. Address{0, 1, 2, 3, 4, 5} is represented as 05:04:03:02:01:00.
  std::array<uint8_t, kLength> address = {};

  constexpr Address() = default;
  constexpr Address(std::array<uint8_t, kLength> const& address);
  Address(const uint8_t (&address)[kLength]);
  Address(std::initializer_list<uint8_t> l);

  // storage::Serializable methods
  std::string ToString() const;
  static std::optional<Address> FromString(const std::string& from);

  bool operator<(const Address& rhs) const { return address < rhs.address; }
  bool operator==(const Address& rhs) const { return address == rhs.address; }
  bool operator>(const Address& rhs) const { return (rhs < *this); }
  bool operator<=(const Address& rhs) const { return !(*this > rhs); }
  bool operator>=(const Address& rhs) const { return !(*this < rhs); }
  bool operator!=(const Address& rhs) const { return !(*this == rhs); }

  bool IsEmpty() const { return *this == kEmpty; }
  uint8_t* data() { return address.data(); }
  uint8_t const* data() const { return address.data(); }

  // Packet parser interface.
  static bool Parse(pdl::packet::slice& input, Address* output);

  // Packet builder interface.
  size_t GetSize() const override { return kLength; }
  void Serialize(std::vector<uint8_t>& output) const override {
    output.insert(output.end(), address.begin(), address.end());
  }

  // Converts |string| to Address and places it in |to|. If |from| does
  // not represent a Bluetooth address, |to| is not modified and this function
  // returns false. Otherwise, it returns true.
  static bool FromString(const std::string& from, Address& to);

  // Copies |from| raw Bluetooth address octets to the local object.
  // Returns the number of copied octets - should be always Address::kLength
  size_t FromOctets(const uint8_t* from);

  static bool IsValidAddress(const std::string& address);

  static const Address kEmpty;  // 00:00:00:00:00:00
  static const Address kAny;    // FF:FF:FF:FF:FF:FF
};

inline std::ostream& operator<<(std::ostream& os, const Address& a) {
  os << a.ToString();
  return os;
}

}  // namespace bluetooth::hci

namespace std {
template <>
struct hash<bluetooth::hci::Address> {
  std::size_t operator()(const bluetooth::hci::Address& address) const {
    uint64_t address_int = 0;
    for (auto b : address.address) {
      address_int <<= 8;
      address_int |= b;
    }
    return std::hash<uint64_t>{}(address_int);
  }
};
}  // namespace std

template <>
struct fmt::formatter<bluetooth::hci::Address> {
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
  auto format(const bluetooth::hci::Address& a, format_context& ctx) const
      -> format_context::iterator {
    return presentation == 'x'
               ? fmt::format_to(ctx.out(),
                                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                a.address[5], a.address[4], a.address[3],
                                a.address[2], a.address[1], a.address[0])
               : fmt::format_to(ctx.out(),
                                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                                a.address[5], a.address[4], a.address[3],
                                a.address[2], a.address[1], a.address[0]);
  }
};

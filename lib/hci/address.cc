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

#include "hci/address.h"

#include <fmt/core.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <iomanip>
#include <sstream>

#include "hci/address_with_type.h"

namespace bluetooth {
namespace hci {

const Address Address::kAny{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const Address Address::kEmpty{0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// Address cannot initialize member variables as it is a POD type
// NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init)
constexpr Address::Address(std::array<uint8_t, kLength> const& address)
    : address(address) {}

Address::Address(const uint8_t (&address)[kLength]) {
  std::copy(address, address + kLength, this->address.begin());
}

Address::Address(std::initializer_list<uint8_t> l) {
  std::copy(l.begin(), std::min(l.begin() + kLength, l.end()), data());
}

bool Address::Parse(pdl::packet::slice& input, Address* output) {
  if (input.size() < kLength) {
    return false;
  }

  std::array<uint8_t, kLength> address{
      input.read_le<uint8_t>(), input.read_le<uint8_t>(),
      input.read_le<uint8_t>(), input.read_le<uint8_t>(),
      input.read_le<uint8_t>(), input.read_le<uint8_t>(),
  };
  *output = Address(address);
  return true;
}

std::string Address::ToString() const {
  std::stringstream ss;
  for (auto it = address.rbegin(); it != address.rend(); it++) {
    ss << std::nouppercase << std::hex << std::setw(2) << std::setfill('0')
       << +*it;
    if (std::next(it) != address.rend()) {
      ss << ':';
    }
  }
  return ss.str();
}

std::optional<Address> Address::FromString(const std::string& from) {
  if (from.length() != 17) {
    return std::nullopt;
  }

  Address addr{};
  std::istringstream stream(from);
  std::string token;
  int index = 0;
  while (getline(stream, token, ':')) {
    if (index >= 6) {
      return std::nullopt;
    }

    if (token.length() != 2) {
      return std::nullopt;
    }

    char* temp = nullptr;
    addr.address.at(5 - index) = std::strtol(token.c_str(), &temp, 16);
    if (temp == token.c_str()) {
      // string token is empty or has wrong format
      return std::nullopt;
    }
    if (temp != (token.c_str() + token.size())) {
      // cannot parse whole string
      return std::nullopt;
    }

    index++;
  }

  if (index != 6) {
    return std::nullopt;
  }

  return addr;
}

bool Address::FromString(const std::string& from, Address& to) {
  auto addr = FromString(from);
  if (!addr) {
    to = {};
    return false;
  }
  to = std::move(*addr);
  return true;
}

size_t Address::FromOctets(const uint8_t* from) {
  std::copy(from, from + kLength, data());
  return kLength;
};

bool Address::IsValidAddress(const std::string& address) {
  return Address::FromString(address).has_value();
}

}  // namespace hci
}  // namespace bluetooth

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
      ctx.on_error("invalid format");
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
      ctx.on_error("invalid format");
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

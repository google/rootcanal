/******************************************************************************
 *
 *  Copyright 2022 The Android Open Source Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#pragma once

#include <array>
#include <optional>
#include <string>

#include "packet/custom_field_fixed_size_interface.h"

namespace bluetooth {
namespace hci {

class ClassOfDevice final
    : public packet::CustomFieldFixedSizeInterface<ClassOfDevice> {
 public:
  static constexpr size_t kLength = 3;

  std::array<uint8_t, kLength> cod = {};

  ClassOfDevice() = default;
  ClassOfDevice(const uint8_t (&class_of_device)[kLength]);

  // packet::CustomFieldFixedSizeInterface methods
  inline uint8_t* data() override { return cod.data(); }
  inline const uint8_t* data() const override { return cod.data(); }

  uint32_t ToUint32() const;
  std::string ToString() const;
  static std::optional<ClassOfDevice> FromString(const std::string& str);

  bool operator<(const ClassOfDevice& rhs) const { return cod < rhs.cod; }
  bool operator==(const ClassOfDevice& rhs) const { return cod == rhs.cod; }
  bool operator>(const ClassOfDevice& rhs) const { return (rhs < *this); }
  bool operator<=(const ClassOfDevice& rhs) const { return !(*this > rhs); }
  bool operator>=(const ClassOfDevice& rhs) const { return !(*this < rhs); }
  bool operator!=(const ClassOfDevice& rhs) const { return !(*this == rhs); }

  // Converts |string| to ClassOfDevice and places it in |to|. If |from| does
  // not represent a Class of Device, |to| is not modified and this function
  // returns false. Otherwise, it returns true.
  static bool FromString(const std::string& from, ClassOfDevice& to);

  // Copies |from| raw Class of Device octets to the local object.
  // Returns the number of copied octets (always ClassOfDevice::kLength)
  size_t FromOctets(const uint8_t* from);

  static bool IsValid(const std::string& class_of_device);
};

inline std::ostream& operator<<(std::ostream& os, const ClassOfDevice& c) {
  os << c.ToString();
  return os;
}

}  // namespace hci
}  // namespace bluetooth

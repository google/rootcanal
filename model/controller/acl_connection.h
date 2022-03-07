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

#include <cstdint>

#include "hci/address_with_type.h"
#include "phy.h"

namespace rootcanal {

using ::bluetooth::hci::AddressWithType;

// Model the connection of a device to the controller.
class AclConnection {
 public:
  AclConnection(AddressWithType addr, AddressWithType own_addr,
                Phy::Type phy_type);

  virtual ~AclConnection() = default;

  void Encrypt();

  bool IsEncrypted() const;

  AddressWithType GetAddress() const;

  void SetAddress(AddressWithType address);

  AddressWithType GetOwnAddress() const;

  void SetOwnAddress(AddressWithType own_addr);

  Phy::Type GetPhyType() const;

 private:
  AddressWithType address_;
  AddressWithType own_address_;
  Phy::Type type_{Phy::Type::BR_EDR};

  // State variables
  bool encrypted_{false};
};

}  // namespace rootcanal

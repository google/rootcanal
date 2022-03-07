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

#include "acl_connection.h"

namespace rootcanal {
AclConnection::AclConnection(AddressWithType addr, AddressWithType own_addr,
                             Phy::Type phy_type)
    : address_(addr), own_address_(own_addr), type_(phy_type) {}

void AclConnection::Encrypt() { encrypted_ = true; };

bool AclConnection::IsEncrypted() const { return encrypted_; };

AddressWithType AclConnection::GetAddress() const { return address_; }

void AclConnection::SetAddress(AddressWithType address) { address_ = address; }

AddressWithType AclConnection::GetOwnAddress() const { return own_address_; }

void AclConnection::SetOwnAddress(AddressWithType own_addr) {
  own_address_ = own_addr;
}

Phy::Type AclConnection::GetPhyType() const { return type_; }

}  // namespace rootcanal

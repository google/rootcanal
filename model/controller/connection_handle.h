/*
 * Copyright (C) 2025 The Android Open Source Project
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

namespace rootcanal {

/// Core Specification Volume 4 Part E § 5.3.1. Controller handles
///
/// Connection_Handles, Sync_Handles, Advertising_Handles, and BIG_Handles are Controller Handles
/// used to identify logical channels between the Host and the Controller.
///
/// Connection_Handles are assigned by the Controller when a new logical transport is created or
/// reserved and reported to the Host in one of the following events:
///     - Connection Complete,
///     - Synchronous Connection Complete,
///     - LE Connection Complete,
///     - LE Enhanced Connection Complete,
///     - LE CIS Request,
///     - LE Create BIG Complete,
///     - LE BIG Sync Established, or Command Complete events following the LE Set CIG Parameters
///       command.
/// All connection handles that are assigned by the Controller shall be derived from the same
/// number space.

enum ConnectionHandle : uint16_t {
  kAclRangeStart = 0x000,
  kAclRangeEnd = 0x0FF,
  kScoRangeStart = 0x100,
  kScoRangeEnd = 0x1FF,
  kLeAclRangeStart = 0x200,
  kLeAclRangeEnd = 0x2FF,
  kCisRangeStart = 0xE00,
  kCisRangeEnd = 0xEFF,
};

[[maybe_unused]]
static bool IsAclConnectionHandle(uint16_t connection_handle) {
  return connection_handle >= ConnectionHandle::kAclRangeStart &&
         connection_handle <= ConnectionHandle::kAclRangeEnd;
}

[[maybe_unused]]
static bool IsScoConnectionHandle(uint16_t connection_handle) {
  return connection_handle >= ConnectionHandle::kScoRangeStart &&
         connection_handle <= ConnectionHandle::kScoRangeEnd;
}

[[maybe_unused]]
static bool IsLeAclConnectionHandle(uint16_t connection_handle) {
  return connection_handle >= ConnectionHandle::kLeAclRangeStart &&
         connection_handle <= ConnectionHandle::kLeAclRangeEnd;
}

[[maybe_unused]]
static bool IsCisConnectionHandle(uint16_t connection_handle) {
  return connection_handle >= ConnectionHandle::kCisRangeStart &&
         connection_handle <= ConnectionHandle::kCisRangeEnd;
}

}  // namespace rootcanal

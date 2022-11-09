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

#include <cstdint>

namespace rootcanal {

// CSR Vendor command opcode.
static constexpr uint16_t CSR_VENDOR = 0xfc00;

enum CsrVarid : uint16_t {
  CSR_VARID_BUILDID = 0x2819,
  CSR_VARID_PS = 0x7003,
};

enum CsrPskey : uint16_t {
  CSR_PSKEY_ENC_KEY_LMIN = 0x00da,
  CSR_PSKEY_ENC_KEY_LMAX = 0x00db,
  CSR_PSKEY_LOCAL_SUPPORTED_FEATURES = 0x00ef,
  CSR_PSKEY_HCI_LMP_LOCAL_VERSION = 0x010d,
};

}  // namespace rootcanal

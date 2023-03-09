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

#include <cstddef>
#include <cstdint>

extern "C" {

void* ffi_controller_new(uint8_t const address[6],
                         void (*send_hci)(int idc, uint8_t const* data,
                                          size_t data_len),
                         void (*send_ll)(uint8_t const* data, size_t data_len,
                                         int phy, int tx_power));
void ffi_controller_delete(void* controller);
void ffi_controller_receive_hci(void* controller, int idc, uint8_t const* data,
                                size_t data_len);
void ffi_controller_receive_ll(void* controller, uint8_t const* data,
                               size_t data_len, int phy, int rssi);
void ffi_controller_tick(void* controller);
void ffi_generate_rpa(uint8_t const irk[16], uint8_t rpa[6]);

};  // extern "C"

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

// This header is currently needed for hci_packets.h
// FIXME: Change hci_packets.h to not depend on os/log.h
//        and remove this.
#include "include/log.h"

#define LOG_INFO(...)                                                       \
  rootcanal::log::Log(rootcanal::log::Verbosity::kInfo, __FILE__, __LINE__, \
                      "{}", fmt::sprintf(__VA_ARGS__))
#define LOG_WARN(...)                                                          \
  rootcanal::log::Log(rootcanal::log::Verbosity::kWarning, __FILE__, __LINE__, \
                      "{}", fmt::sprintf(__VA_ARGS__))
#define LOG_ERROR(...)                                                       \
  rootcanal::log::Log(rootcanal::log::Verbosity::kError, __FILE__, __LINE__, \
                      "{}", fmt::sprintf(__VA_ARGS__))
#define LOG_ALWAYS_FATAL(...)                                                \
  rootcanal::log::Log(rootcanal::log::Verbosity::kFatal, __FILE__, __LINE__, \
                      "{}", fmt::sprintf(__VA_ARGS__))

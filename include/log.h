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
#include <fmt/format.h>
#include <fmt/printf.h>

#include <optional>

namespace rootcanal::log {

enum Verbosity {
  kDebug,
  kInfo,
  kWarning,
  kError,
  kFatal,
};

void SetLogColorEnable(bool);

void VLog(Verbosity verb, char const* file, int line,
          std::optional<int> instance, char const* format,
          fmt::format_args args);

template <typename... Args>
static void Log(Verbosity verb, char const* file, int line, int instance,
                char const* format, const Args&... args) {
  VLog(verb, file, line, instance, format, fmt::make_format_args(args...));
}

template <typename... Args>
static void Log(Verbosity verb, char const* file, int line, char const* format,
                const Args&... args) {
  VLog(verb, file, line, {}, format, fmt::make_format_args(args...));
}

#define DEBUG(...)                                                           \
  rootcanal::log::Log(rootcanal::log::Verbosity::kDebug, __FILE__, __LINE__, \
                      __VA_ARGS__)

#define INFO(...)                                                           \
  rootcanal::log::Log(rootcanal::log::Verbosity::kInfo, __FILE__, __LINE__, \
                      __VA_ARGS__)

#define WARNING(...)                                                           \
  rootcanal::log::Log(rootcanal::log::Verbosity::kWarning, __FILE__, __LINE__, \
                      __VA_ARGS__)

#define ERROR(...)                                                           \
  rootcanal::log::Log(rootcanal::log::Verbosity::kError, __FILE__, __LINE__, \
                      __VA_ARGS__)

#define FATAL(...)                                                           \
  rootcanal::log::Log(rootcanal::log::Verbosity::kFatal, __FILE__, __LINE__, \
                      __VA_ARGS__)

#define ASSERT(x)                                                       \
  __builtin_expect((x) != 0, true) ||                                   \
      (rootcanal::log::Log(rootcanal::log::Verbosity::kFatal, __FILE__, \
                           __LINE__, "Check failed: {}", #x),           \
       false)

#define ASSERT_LOG(x, ...)                                              \
  __builtin_expect((x) != 0, true) ||                                   \
      (rootcanal::log::Log(rootcanal::log::Verbosity::kFatal, __FILE__, \
                           __LINE__, "Check failed: {}, {}", #x,        \
                           fmt::sprintf(__VA_ARGS__)),                  \
       false)

}  // namespace rootcanal::log

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

#include "log.h"

#include <fmt/color.h>
#include <fmt/core.h>

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <optional>

namespace rootcanal::log {

// Enable flag for log styling.
static bool enable_log_color = true;

void SetLogColorEnable(bool enable) { enable_log_color = enable; }

static std::array<char, 5> verbosity_tag = {'D', 'I', 'W', 'E', 'F'};

static std::array<fmt::text_style, 5> text_style = {
    fmt::fg(fmt::color::dim_gray),
    fmt::fg(fmt::color::floral_white),
    fmt::emphasis::bold | fmt::fg(fmt::color::yellow),
    fmt::emphasis::bold | fmt::fg(fmt::color::orange_red),
    fmt::emphasis::bold | fmt::fg(fmt::color::red),
};

static std::array<fmt::color, 16> text_color = {
    fmt::color::cadet_blue,   fmt::color::aquamarine,
    fmt::color::indian_red,   fmt::color::blue_violet,
    fmt::color::chartreuse,   fmt::color::medium_sea_green,
    fmt::color::deep_pink,    fmt::color::medium_orchid,
    fmt::color::green_yellow, fmt::color::dark_orange,
    fmt::color::golden_rod,   fmt::color::medium_slate_blue,
    fmt::color::coral,        fmt::color::lemon_chiffon,
    fmt::color::wheat,        fmt::color::turquoise,
};

void VLog(Verbosity verb, char const* file, int line,
          std::optional<int> instance, char const* format,
          fmt::format_args args) {
  // Generate the time label.
  auto now = std::chrono::system_clock::now();
  auto now_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now);
  auto now_t = std::chrono::system_clock::to_time_t(now);
  char time_str[19];  // "mm-dd_HH:MM:SS.mmm\0" is 19 byte long
  auto n = std::strftime(time_str, sizeof(time_str), "%m-%d %H:%M:%S",
                         std::localtime(&now_t));
  snprintf(time_str + n, sizeof(time_str) - n, ".%03u",
           static_cast<unsigned int>(now_ms.time_since_epoch().count() % 1000));

  // Generate the file label.
  char delimiter = '/';
  char const* file_name = ::strrchr(file, delimiter);
  file_name = file_name == nullptr ? file : file_name + 1;
  char file_str[40];  // file:line limited to 40 characters
  snprintf(file_str, sizeof(file_str), "%.35s:%d", file_name, line);

  fmt::print("root-canal {} {} {:<35.35} ", verbosity_tag[verb], time_str,
             file_str);

  if (instance.has_value() && enable_log_color) {
    fmt::color instance_color = text_color[*instance % text_color.size()];
    fmt::print(fmt::bg(instance_color) | fmt::fg(fmt::color::black), " {:>2} ",
               *instance);
    fmt::print(" ");
  } else if (instance.has_value()) {
    fmt::print(" {:>2}  ", *instance);
  } else {
    fmt::print("     ");
  }

  if (enable_log_color) {
    fmt::text_style style = text_style[verb];
    fmt::vprint(stdout, style, format, args);
  } else {
    fmt::vprint(stdout, format, args);
  }

  fmt::print("\n");

  if (verb == Verbosity::kFatal) {
    std::abort();
  }
}

}  // namespace rootcanal::log

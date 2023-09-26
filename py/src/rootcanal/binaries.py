# Copyright 2023 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import importlib.resources
import platform
import sys

_PLATFORM_TO_OS_NAME_MAP = {
    "darwin": "macos",
}


def get_package_binary_resource_path(name: str) -> str:
    os_name = _PLATFORM_TO_OS_NAME_MAP.get(sys.platform, sys.platform)
    return str(
        importlib.resources.files(__package__).joinpath(
            f"bin/{os_name}-{platform.machine()}/{name}"
        )
    )

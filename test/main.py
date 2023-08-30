# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from importlib import resources
from pathlib import Path
import importlib
import sys
import tempfile
import unittest

tests = [
    'LL.CIS.CEN.BV_01_C',
    'LL.CIS.CEN.BV_03_C',
    'LL.CIS.CEN.BV_10_C',
    'LL.CIS.CEN.BV_26_C',
    'LL.CIS.PER.BV_01_C',
    'LL.CIS.PER.BV_02_C',
    'LL.CON_.CEN.BV_41_C',
    'LL.CON_.CEN.BV_43_C',
    'LL.CON_.PER.BV_40_C',
    'LL.CON_.PER.BV_42_C',
    'LL.DDI.ADV.BV_01_C',
    'LL.DDI.ADV.BV_02_C',
    'LL.DDI.ADV.BV_03_C',
    'LL.DDI.ADV.BV_04_C',
    'LL.DDI.ADV.BV_05_C',
    'LL.DDI.ADV.BV_06_C',
    'LL.DDI.ADV.BV_07_C',
    'LL.DDI.ADV.BV_08_C',
    'LL.DDI.ADV.BV_09_C',
    'LL.DDI.ADV.BV_11_C',
    'LL.DDI.ADV.BV_15_C',
    'LL.DDI.ADV.BV_16_C',
    'LL.DDI.ADV.BV_17_C',
    'LL.DDI.ADV.BV_18_C',
    'LL.DDI.ADV.BV_19_C',
    'LL.DDI.ADV.BV_20_C',
    'LL.DDI.ADV.BV_21_C',
    'LL.DDI.ADV.BV_22_C',
    'LL.DDI.ADV.BV_26_C',
    'LL.DDI.ADV.BV_47_C',
    'LL.DDI.SCN.BV_13_C',
    'LL.DDI.SCN.BV_14_C',
    'LL.DDI.SCN.BV_18_C',
    'LL.DDI.SCN.BV_19_C',
    'LL.DDI.SCN.BV_79_C',
    'LMP.LIH.BV_01_C',
    'LMP.LIH.BV_02_C',
    'LMP.LIH.BV_78_C',
    'LMP.LIH.BV_79_C',
    'LMP.LIH.BV_142_C',
    'LMP.LIH.BV_143_C',
    'LMP.LIH.BV_144_C',
    'LMP.LIH.BV_149_C',
    'LL.scan_collision',
    'LMP.page_collision',
]


def include_test(test: str, patterns) -> bool:
    return not patterns or any(test.startswith(prefix) for prefix in patterns)


if __name__ == "__main__":
    suite = unittest.TestSuite()
    patterns = [arg for arg in sys.argv[1:] if not arg.startswith('-')]
    for test in tests:
        if include_test(test, patterns):
            module = importlib.import_module(f'test.{test}')
            suite.addTest(unittest.defaultTestLoader.loadTestsFromModule(module))
    unittest.TextTestRunner(verbosity=3).run(suite)

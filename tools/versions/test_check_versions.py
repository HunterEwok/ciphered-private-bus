# SPDX-License-Identifier: MPL-2.0
# Copyright (C) 2026 HunterEwok
import tempfile
import unittest
from pathlib import Path

import check_versions as cv


class CheckVersionsTest(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(cv.parse("1.97.0"), (1, 97, 0))
        self.assertEqual(cv.parse("v0.62.4"), (0, 62, 4))
        self.assertIsNone(cv.parse("1.0.0-rc1"))
        self.assertGreater(cv.parse("0.10.0"), cv.parse("0.9.9"))

    def test_uses(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "a.txt").write_text('channel = "1.2.3"\n')
            pins = {"x": {"version": "1.2.3", "uses": [{"file": "a.txt", "text": 'channel = "{version}"'}]}}
            self.assertEqual(cv.check_uses(pins, Path(d)), [])
            pins["x"]["version"] = "1.2.4"
            self.assertEqual(len(cv.check_uses(pins, Path(d))), 1)
            pins["x"]["uses"][0]["file"] = "missing.txt"
            self.assertIn("does not exist", cv.check_uses(pins, Path(d))[0])

    def test_repository_pins(self):
        self.assertEqual(cv.check_uses(cv.load()), [])


if __name__ == "__main__":
    unittest.main()

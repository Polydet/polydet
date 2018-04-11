from unittest import TestCase

from polyglot_detector import PolyglotLevel
from polyglot_detector.plugins import bmp


class TestBMPDetector(TestCase):
    def test_regular_file(self):
        self.assertEqual(bmp.check('tests/samples/bmp/regular.bmp'), PolyglotLevel.VALID)

    def test_not_bmp(self):
        self.assertIsNone(bmp.check('tests/samples/zip/regular.zip'))

    def test_garbage_at_end(self):
        self.assertEqual(bmp.check('tests/samples/bmp/garbage_at_end.bmp'), PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END)

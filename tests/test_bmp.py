from unittest import TestCase

from polydet import PolyglotLevel
from polydet.plugins import bmp


class TestBMPDetector(TestCase):
    def test_regular_file(self):
        self.assertEqual(PolyglotLevel.VALID, bmp.check('tests/samples/bmp/regular.bmp'))

    def test_not_bmp(self):
        self.assertIsNone(bmp.check('tests/samples/zip/regular.zip'))

    def test_garbage_at_end(self):
        self.assertEqual(PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END,
                         bmp.check('tests/samples/bmp/garbage_at_end.bmp'))

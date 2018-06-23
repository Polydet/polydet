from unittest import TestCase, skip

from polydet import PolyglotLevel
from polydet.plugins import tiff


class TestTIFFDetector(TestCase):
    def test_le_regular_file(self):
        self.assertEqual(PolyglotLevel.VALID, tiff.check('tests/samples/tiff/regular-le.tiff'))

    def test_be_regular_file(self):
        self.assertEqual(PolyglotLevel.VALID, tiff.check('tests/samples/tiff/regular-be.tiff'))

    def test_not_tiff(self):
        self.assertIsNone(tiff.check('tests/samples/zip/regular.zip'))

    def test_le_garbage_at_end(self):
        self.assertEqual(PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END,
                         tiff.check('tests/samples/tiff/garbage_at_end-le.tiff'))

    def test_be_garbage_at_end(self):
        self.assertEqual(PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END,
                         tiff.check('tests/samples/tiff/garbage_at_end-be.tiff'))

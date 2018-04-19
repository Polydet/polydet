from unittest import TestCase, skip

from polyglot_detector import PolyglotLevel
from polyglot_detector.plugins import tiff


class TestTIFFDetector(TestCase):
    def test_regular_file(self):
        self.assertEqual(tiff.check('tests/samples/tiff/regular-le.tiff'), PolyglotLevel.VALID)
        self.assertEqual(tiff.check('tests/samples/tiff/regular-be.tiff'), PolyglotLevel.VALID)

    def test_not_tiff(self):
        self.assertIsNone(tiff.check('tests/samples/zip/regular.zip'))

    @skip
    def test_garbage_at_end(self):
        self.assertEqual(tiff.check('tests/samples/tiff/garbage_at_end-le.tiff'),
                         PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END)
        self.assertEqual(tiff.check('tests/samples/tiff/garbage_at_end-be.tiff'),
                         PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END)

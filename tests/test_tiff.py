from unittest import TestCase, skip

from polyglot_detector import PolyglotLevel
from polyglot_detector.plugins import tiff


class TestTIFFDetector(TestCase):
    def test_regular_file(self):
        self.assertEqual(PolyglotLevel.VALID, tiff.check('tests/samples/tiff/regular-le.tiff'))
        self.assertEqual(PolyglotLevel.VALID, tiff.check('tests/samples/tiff/regular-be.tiff'))

    def test_not_tiff(self):
        self.assertIsNone(tiff.check('tests/samples/zip/regular.zip'))

    @skip
    def test_garbage_at_end(self):
        self.assertEqual(PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END,
                         tiff.check('tests/samples/tiff/garbage_at_end-le.tiff'))
        self.assertEqual(PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END,
                         tiff.check('tests/samples/tiff/garbage_at_end-be.tiff'))

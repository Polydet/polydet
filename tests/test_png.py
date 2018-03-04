from unittest import TestCase

from polyglot_detector import PolyglotLevel
from polyglot_detector.plugins import png


class TestPNGDetector(TestCase):
    def test_no_png(self):
        self.assertIsNone(png.check('tests/samples/zip/regular.zip'))

    def test_regular_png(self):
        self.assertEqual(png.check('tests/samples/png/regular.png'), PolyglotLevel.VALID)

    def test_garbage_at_end(self):
        self.assertEqual(png.check('tests/samples/png/garbage_at_end.png'),
                         PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END)

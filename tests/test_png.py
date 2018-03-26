from unittest import TestCase

from polyglot_detector import PolyglotLevel
from polyglot_detector.plugins import png


class TestPNGDetector(TestCase):
    def test_no_png(self):
        self.assertIsNone(png.check('tests/samples/zip/regular.zip'))

    def test_regular_png(self):
        result = png.check('tests/samples/png/regular.png')
        self.assertIsNotNone(result)
        self.assertEqual(result['result'], PolyglotLevel.VALID)

    def test_garbage_at_end(self):
        result = png.check('tests/samples/png/garbage_at_end.png')
        self.assertIsNotNone(result)
        self.assertEqual(result['result'], PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END)

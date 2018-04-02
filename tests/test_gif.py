from unittest import TestCase

from polyglot_detector import PolyglotLevel
from polyglot_detector.plugins import gif


class TestGIFDetector(TestCase):
    def test_regular_file(self):
        self.assertEqual(gif.check('tests/samples/gif/regular.gif'), PolyglotLevel.VALID)
        self.assertEqual(gif.check('tests/samples/gif/gif87.gif'), PolyglotLevel.VALID)

    def test_not_gif(self):
        self.assertIsNone(gif.check('tests/samples/zip/regular.zip'))

    def test_garbage_at_end(self):
        self.assertEqual(gif.check('tests/samples/gif/garbage_at_end.gif'),
                         PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END)

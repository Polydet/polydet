from unittest import TestCase

from polydet import PolyglotLevel
from polydet.plugins import gif


class TestGIFDetector(TestCase):
    def test_regular_file(self):
        self.assertEqual(PolyglotLevel.VALID, gif.check('tests/samples/gif/regular.gif'))
        self.assertEqual(PolyglotLevel.VALID, gif.check('tests/samples/gif/gif87.gif'))

    def test_not_gif(self):
        self.assertIsNone(gif.check('tests/samples/zip/regular.zip'))

    def test_garbage_at_end(self):
        self.assertEqual(PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END,
                         gif.check('tests/samples/gif/garbage_at_end.gif'))

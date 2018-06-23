from unittest import TestCase

from polydet import PolyglotLevel
from polydet.plugins import gif


class TestGIFDetector(TestCase):
    def test_regular_file(self):
        self.assertEqual(PolyglotLevel(), gif.check('tests/samples/gif/regular.gif'))
        self.assertEqual(PolyglotLevel(), gif.check('tests/samples/gif/gif87.gif'))

    def test_not_gif(self):
        self.assertIsNone(gif.check('tests/samples/zip/regular.zip'))

    def test_garbage_at_end(self):
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0xE4D31, 0x343)]),
                         gif.check('tests/samples/gif/garbage_at_end.gif'))

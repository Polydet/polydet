from unittest import TestCase

from polydet import PolyglotLevel
from polydet.plugins import png


class TestPNGDetector(TestCase):
    def test_no_png(self):
        self.assertIsNone(png.check('tests/samples/zip/regular.zip'))

    def test_regular_png(self):
        self.assertEqual(PolyglotLevel(), png.check('tests/samples/png/regular.png'))

    def test_garbage_at_end(self):
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0x4CA0, 0x343)]),
                         png.check('tests/samples/png/garbage_at_end.png'))

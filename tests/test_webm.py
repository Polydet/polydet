from unittest import TestCase

from polydet import PolyglotLevel
from polydet.plugins import webm


class TestWEBMDetector(TestCase):
    def test_regular_file(self):
        self.assertEqual(PolyglotLevel(), webm.check('tests/samples/webm/regular.webm'))

    def test_not_webm(self):
        self.assertIsNone(webm.check('tests/samples/zip/regular.zip'))

    def test_garbage_at_end(self):
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0x3804F, 0x15)]),
                         webm.check('tests/samples/webm/garbage_at_end.webm'))

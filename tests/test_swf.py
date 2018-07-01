from unittest import TestCase

from polydet import PolyglotLevel
from polydet.plugins import swf


class TestSWFDetector(TestCase):
    def test_regular(self):
        self.assertEqual(PolyglotLevel(), swf.check('tests/samples/swf/regular.cws9'))
        self.assertEqual(PolyglotLevel(), swf.check('tests/samples/swf/regular.zws13'))

    def test_not_swf(self):
        self.assertIsNone(swf.check('tests/samples/zip/regular.zip'))

    def test_garbage_at_end(self):
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0x16B, 0xB5)]),
                         swf.check('tests/samples/swf/garbage-at-end.cws9'))
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0x2A9, 0xB5)]),
                         swf.check('tests/samples/swf/garbage-at-end.zws13'))

from unittest import TestCase

from polydet import PolyglotLevel
from polydet.plugins import avi


class TestAVIDetector(TestCase):
    def test_regular_file(self):
        self.assertEqual(PolyglotLevel(),
                         avi.check('tests/samples/avi/regular.avi'))

    def test_not_avi(self):
        self.assertIsNone(avi.check('tests/samples/zip/regular.zip'))

    def test_garbage_at_beginning(self):
        result = avi.check('tests/samples/avi/garbage_at_beginning.avi')
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0, 0x15)]), result)

    def test_garbage_at_end(self):
        result = avi.check('tests/samples/avi/garbage_at_end.avi')
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0x469F0, 0x15)]),
                         result)

    def test_garbage_at_beginning_and_end(self):
        result = avi.check('tests/samples/avi/garbage_at_beginning_and_end.avi')
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0, 0x15), (0x46A05, 0x15)]), result)

from unittest import TestCase

from polydet import PolyglotLevel
from polydet.plugins import flac


class TestFLACDetector(TestCase):
    def test_regular_file(self):
        self.assertEqual(PolyglotLevel(), flac.check('tests/samples/flac/regular.flac'))

    def test_not_flac(self):
        self.assertIsNone(flac.check('tests/samples/zip/regular.zip'))

    def test_garbage_at_beginning(self):
        result = flac.check('tests/samples/flac/garbage_at_beginning.flac')
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0, 0x15)]), result)

    def test_garbage_at_beginning_length(self):
        result = flac.check('tests/samples/flac/29999_bytes_of_garbage_at_beginning.flac')
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0, 29999)]), result)
        self.assertIsNone(flac.check('tests/samples/flac/30000_bytes_of_garbage_at_beginning.flac'))

from unittest import TestCase

from polydet import PolyglotLevel
from polydet.plugins import tiff


class TestTIFFDetector(TestCase):
    # TODO Add tests with TIFF with suspicious data before IFD
    def test_le_regular_file(self):
        self.assertEqual(PolyglotLevel(), tiff.check('tests/samples/tiff/regular-le.tiff'))

    def test_be_regular_file(self):
        self.assertEqual(PolyglotLevel(), tiff.check('tests/samples/tiff/regular-be.tiff'))

    def test_not_tiff(self):
        self.assertIsNone(tiff.check('tests/samples/zip/regular.zip'))

    def test_le_garbage_at_end(self):
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0x41FEC, 0x343)]),
                         tiff.check('tests/samples/tiff/garbage_at_end-le.tiff'))

    def test_be_garbage_at_end(self):
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0x41FEC, 0x343)]),
                         tiff.check('tests/samples/tiff/garbage_at_end-be.tiff'))

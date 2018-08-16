from unittest import TestCase

from polydet import PolyglotLevel
from polydet.plugins import pdf


class TestPDFDetector(TestCase):
    def test_regular_file(self):
        self.assertEqual(PolyglotLevel(), pdf.check('tests/samples/pdf/regular.pdf'))

    def test_not_pdf(self):
        self.assertIsNone(pdf.check('tests/samples/zip/regular.zip'))

    def test_truncated_magic(self):
        self.assertEqual(PolyglotLevel(is_valid=False), pdf.check('tests/samples/pdf/truncated_magic.pdf'))

    def test_magic_within_1024_first_bytes(self):
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0, 0x400)]),
                         pdf.check('tests/samples/pdf/garbage_at_beginning.pdf'))

    def test_magic_anywhere_in_the_file(self):
        self.assertEqual(PolyglotLevel(is_valid=False, suspicious_chunks=[(0, 0x1800)]),
                         pdf.check('tests/samples/pdf/lot_of_garbage_at_beginning.pdf'))

    def test_garbage_at_end(self):
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0x2E8C, 0xB5)]),
                         pdf.check('tests/samples/pdf/garbage_at_end.pdf'))

    def test_no_magic(self):
        self.assertEqual(PolyglotLevel(),
                         pdf.check('tests/samples/pdf/no-magic-nor-end.pdf'))

    def test_crlf(self):
        self.assertEqual(PolyglotLevel(),
                         pdf.check('tests/samples/pdf/18993-pdf.pdf'))

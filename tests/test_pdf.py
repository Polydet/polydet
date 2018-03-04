from unittest import TestCase

from polyglot_detector import PolyglotLevel
from polyglot_detector.plugins import pdf


class TestPDFDetector(TestCase):
    def test_regular_file(self):
        self.assertEqual(pdf.check('tests/samples/pdf/regular.pdf'), PolyglotLevel.VALID)

    def test_truncated_magic(self):
        self.assertEqual(pdf.check('tests/samples/pdf/truncated_magic.pdf'), PolyglotLevel.VALID)

    def test_magic_within_1024_first_bytes(self):
        self.assertTrue(pdf.check('tests/samples/pdf/garbage_at_beginning.pdf') & PolyglotLevel.GARBAGE_AT_BEGINNING)

    def test_magic_anywhere_in_the_file(self):
        self.assertTrue(pdf.check('tests/samples/pdf/lot_of_garbage_at_beginning.pdf')
                        & PolyglotLevel.GARBAGE_AT_BEGINNING)

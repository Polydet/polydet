from unittest import TestCase

from polyglot_detector import PolyglotLevel
from polyglot_detector.plugins import pdf


class TestPDFDetector(TestCase):
    def test_regular_file(self):
        result = pdf.check('tests/samples/pdf/regular.pdf')
        self.assertEqual(result, PolyglotLevel.VALID)

    def test_truncated_magic(self):
        result = pdf.check('tests/samples/pdf/truncated_magic.pdf')
        self.assertEqual(result, PolyglotLevel.VALID)

    def test_magic_within_1024_first_bytes(self):
        result = pdf.check('tests/samples/pdf/garbage_at_beginning.pdf')
        self.assertTrue(result & PolyglotLevel.GARBAGE_AT_BEGINNING)

    def test_magic_anywhere_in_the_file(self):
        result = pdf.check('tests/samples/pdf/lot_of_garbage_at_beginning.pdf')
        self.assertTrue(result & PolyglotLevel.GARBAGE_AT_BEGINNING)

    def test_garbage_at_end(self):
        result = pdf.check('tests/samples/pdf/garbage_at_end.pdf')
        self.assertEqual(result, PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END)

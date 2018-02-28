from polyglot_detector import pdf
from unittest import TestCase


class TestPDFDetector(TestCase):
    def test_regular_file(self):
        self.assertTrue(pdf.check('tests/samples/pdf/regular.pdf'))

    def test_truncated_magic(self):
        self.assertTrue(pdf.check('tests/samples/pdf/truncated_magic.pdf'))

    def test_magic_within_1024_first_bytes(self):
        self.assertTrue(pdf.check('tests/samples/pdf/garbage_at_beginning.pdf'))

    def test_magic_anywhere_in_the_file(self):
        self.assertTrue(pdf.check('tests/samples/pdf/lot_of_garbage_at_beginning.pdf'))

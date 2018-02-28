from polyglot_detector import zip
from unittest import TestCase


class TestZIPDetector(TestCase):
    def test_check_regular_file(self):
        self.assertTrue(zip.check('tests/samples/zip/regular.zip'))

    def test_check_garbage_at_the_beginning(self):
        self.assertTrue(zip.check('tests/samples/zip/garbage_at_beginning.zip'))

    def test_check_garbage_at_the_end(self):
        self.assertTrue(zip.check('tests/samples/zip/garbage_at_end.zip'))


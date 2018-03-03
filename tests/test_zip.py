from polyglot_detector import PolyglotLevel, zip
from unittest import TestCase


class TestZIPDetector(TestCase):
    def test_check_regular_file(self):
        self.assertEqual(zip.check('tests/samples/zip/regular.zip'), PolyglotLevel.VALID)

    def test_check_garbage_at_the_beginning(self):
        self.assertTrue(zip.check('tests/samples/zip/garbage_at_beginning.zip') & PolyglotLevel.GARBAGE_AT_BEGINNING)

    def test_check_garbage_at_the_end(self):
        self.assertTrue(zip.check('tests/samples/zip/garbage_at_end.zip') & PolyglotLevel.GARBAGE_AT_END,
                        "Should detect GARBAGE_AT_END")

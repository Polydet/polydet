from unittest import TestCase

from polyglot_detector import PolyglotLevel
from polyglot_detector.plugins import zip


class TestZIPDetector(TestCase):
    def test_check_regular_file(self):
        result = zip.check('tests/samples/zip/regular.zip')
        self.assertIsNotNone(result)
        self.assertEqual(result['result'], PolyglotLevel.VALID)

    def test_check_garbage_at_the_beginning(self):
        result = zip.check('tests/samples/zip/garbage_at_beginning.zip')
        self.assertIsNotNone(result)
        self.assertEqual(result['result'], PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_BEGINNING)

    def test_check_garbage_at_the_end(self):
        result = zip.check('tests/samples/zip/garbage_at_end.zip')
        self.assertIsNotNone(result)
        self.assertEqual(result['result'], PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END)

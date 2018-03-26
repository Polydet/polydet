from unittest import TestCase

from polyglot_detector import PolyglotLevel
from polyglot_detector.plugins import jpg


class TestJPGDetector(TestCase):
    def test_regular_file(self):
        result = jpg.check('tests/samples/jpg/regular.jpg')
        self.assertIsNotNone(result)
        self.assertEqual(result['result'], PolyglotLevel.VALID)

    def test_not_jpg(self):
        self.assertIsNone(jpg.check('tests/samples/zip/regular.zip'))

    def test_garbage_at_end(self):
        result = jpg.check('tests/samples/jpg/garbage_at_end.jpg')
        self.assertIsNotNone(result)
        self.assertEqual(result['result'], PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END)

from polyglot_detector import PolyglotLevel, jpg
from unittest import TestCase


class TestJPGDetector(TestCase):
    def test_regular_file(self):
        self.assertEqual(jpg.check('tests/samples/jpg/regular.jpg'), PolyglotLevel.VALID)

    def test_not_jpg(self):
        self.assertIsNone(jpg.check('tests/samples/zip/regular.zip'))

    def test_garbage_at_end(self):
        self.assertEqual(jpg.check('tests/samples/jpg/garbage_at_end.jpg'),
                         PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END)

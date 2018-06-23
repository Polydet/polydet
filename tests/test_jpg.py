from unittest import TestCase

from polydet import PolyglotLevel
from polydet.plugins import jpg


class TestJPGDetector(TestCase):
    def test_regular_file(self):
        result = jpg.check('tests/samples/jpg/regular.jpg')
        self.assertEqual(PolyglotLevel.VALID, result)

    def test_not_jpg(self):
        self.assertIsNone(jpg.check('tests/samples/zip/regular.zip'))

    def test_garbage_at_end(self):
        result = jpg.check('tests/samples/jpg/garbage_at_end.jpg')
        self.assertEqual(PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END, result)

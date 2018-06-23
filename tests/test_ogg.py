from unittest import TestCase

from polydet import PolyglotLevel
from polydet.plugins import ogg


class TestOGGDetector(TestCase):
    def test_regular_file(self):
        self.assertEqual(PolyglotLevel.VALID,
                         ogg.check('tests/samples/ogg/regular.ogg'))

    def test_not_ogg(self):
        self.assertIsNone(ogg.check('tests/samples/zip/regular.zip'))

    def test_garbage_at_beginning(self):
        result = ogg.check('tests/samples/ogg/garbage_at_beginning.ogg')
        self.assertEqual(PolyglotLevel.VALID
                         | PolyglotLevel.GARBAGE_AT_BEGINNING,
                         result)

    def test_garbage_in_middle(self):
        result = ogg.check('tests/samples/ogg/garbage_in_middle.ogg')
        self.assertEqual(PolyglotLevel.VALID | PolyglotLevel.GARBAGE_IN_MIDDLE,
                         result)

    def test_garbage_at_end(self):
        result = ogg.check('tests/samples/ogg/garbage_at_end.ogg')
        self.assertEqual(PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END,
                         result)

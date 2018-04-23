from unittest import TestCase

from polyglot_detector import PolyglotLevel
from polyglot_detector.plugins import mp3


class TestMP3Detector(TestCase):
    def test_regular_file(self):
        self.assertEqual(PolyglotLevel.VALID,
                         mp3.check('tests/samples/mp3/regular.mp3'))

    def test_not_mp3(self):
        self.assertIsNone(mp3.check('tests/samples/zip/regular.zip'))

    def test_garbage_at_beginning(self):
        result = mp3.check('tests/samples/mp3/garbage_at_beginning.mp3')
        self.assertEqual(PolyglotLevel.VALID
                         | PolyglotLevel.GARBAGE_AT_BEGINNING,
                         result)

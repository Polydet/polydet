from unittest import TestCase

from polyglot_detector import PolyglotLevel
from polyglot_detector.plugins import wav


class TestWAVDetector(TestCase):
    def test_regular_file(self):
        self.assertEqual(PolyglotLevel.VALID,
                         wav.check('tests/samples/wav/regular.wav'))

    def test_not_wav(self):
        self.assertIsNone(wav.check('tests/samples/zip/regular.zip'))

    def test_garbage_at_beginning(self):
        result = wav.check('tests/samples/wav/garbage_at_beginning.wav')
        self.assertEqual(PolyglotLevel.VALID
                         | PolyglotLevel.GARBAGE_AT_BEGINNING,
                         result)

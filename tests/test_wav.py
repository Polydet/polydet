from unittest import TestCase

from polyglot_detector import PolyglotLevel
from polyglot_detector.plugins import wav


class TestWAVDetector(TestCase):
    def test_regular_file(self):
        self.assertEqual(PolyglotLevel.VALID,
                         wav.check('tests/samples/wav/regular.wav'))

    def test_not_wav(self):
        self.assertIsNone(wav.check('tests/samples/zip/regular.zip'))

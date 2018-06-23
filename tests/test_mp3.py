from unittest import TestCase

from polydet import PolyglotLevel
from polydet.plugins import mp3


class TestMP3Detector(TestCase):
    def test_regular_file(self):
        self.assertEqual(PolyglotLevel(),
                         mp3.check('tests/samples/mp3/regular.mp3'))

    def test_not_mp3(self):
        self.assertIsNone(mp3.check('tests/samples/zip/regular.zip'))

    def test_garbage_at_beginning(self):
        result = mp3.check('tests/samples/mp3/garbage_at_beginning.mp3')
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0, 0x1AC)]),
                         result)

    def test_garbage_in_middle(self):
        result = mp3.check('tests/samples/mp3/garbage_in_middle.mp3')
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0x1AC, 0xF50)]),
                         result)

    def test_garbage_at_end(self):
        result = mp3.check('tests/samples/mp3/garbage_at_end.mp3')
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0x6C616, 0xB4)]),
                         result)

    def test_fake(self):
        self.assertIsNone(mp3.check('tests/samples/mp3/fake1.mp3'))
        self.assertIsNone(mp3.check('tests/samples/mp3/fake2.mp3'))
        self.assertIsNone(mp3.check('tests/samples/mp3/fake3.mp3'))

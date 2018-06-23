from unittest import TestCase

from polydet import PolyglotLevel
from polydet.plugins import jpg


class TestJPGDetector(TestCase):
    def test_regular_file(self):
        self.assertEqual(PolyglotLevel(), jpg.check('tests/samples/jpg/regular.jpg'))

    def test_not_jpg(self):
        self.assertIsNone(jpg.check('tests/samples/zip/regular.zip'))

    def test_garbage_at_end(self):
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0x63BF, 0x343)]),
                         jpg.check('tests/samples/jpg/garbage_at_end.jpg'))

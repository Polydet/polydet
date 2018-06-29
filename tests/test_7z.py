from unittest import TestCase

from polydet import PolyglotLevel
from polydet.plugins import seven_zip


class TestBMPDetector(TestCase):
    def test_is_7z(self):
        self.assertEqual(PolyglotLevel(), seven_zip.check('tests/samples/7z/regular.7z'))

    def test_not_7z(self):
        self.assertIsNone(seven_zip.check('tests/samples/zip/regular.zip'))

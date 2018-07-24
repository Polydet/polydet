from unittest import TestCase

from polydet import PolyglotLevel
from polydet.plugins import php


class TestPHPDetector(TestCase):
    def test_regular_file(self):
        self.assertEqual(PolyglotLevel(),
                         php.check('tests/samples/php/regular.php'))
        self.assertEqual(PolyglotLevel(),
                         php.check('tests/samples/php/upper-case.php'))
        self.assertEqual(PolyglotLevel(),
                         php.check('tests/samples/php/mixed-case.php'))

    def test_not_mp3(self):
        self.assertIsNone(php.check('tests/samples/zip/regular.zip'))

from unittest import TestCase

from polydet import PolyglotLevel
from polydet.plugins import elf


class TestELFDetector(TestCase):
    def test_regular_file(self):
        self.assertEqual(PolyglotLevel(), elf.check('tests/samples/elf/regular.elf'))

    def test_not_elf(self):
        self.assertIsNone(elf.check('tests/samples/zip/regular.zip'))

from unittest import TestCase

from polydet import PolyglotLevel
from polydet.plugins import exe


class TestEXEDetector(TestCase):
    def test_regular_file(self):
        self.assertEqual(PolyglotLevel(), exe.check('tests/samples/exe/regular.exe'))

    def test_not_exe(self):
        self.assertIsNone(exe.check('tests/samples/zip/regular.zip'))

    def test_garbage_after_image(self):
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0x170, 36003)]),
                         exe.check('tests/samples/exe/garbage-after-header.exe'))

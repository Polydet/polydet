from unittest import TestCase, skip

from polydet import PolyglotLevel
from polydet.plugins import exe


class TestEXEDetector(TestCase):
    def test_regular_file(self):
        self.assertEqual(PolyglotLevel(), exe.check('tests/samples/exe/regular.exe'))

    def test_not_exe(self):
        self.assertIsNone(exe.check('tests/samples/zip/regular.zip'))

    def test_garbage_at_end(self):
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0x4400, 35985)]),
                         exe.check('tests/samples/exe/garbage-at-end.exe'))

    # See FIXME in exe.check
    @skip
    def test_bad_optional_header(self):
        self.assertEqual(PolyglotLevel(), exe.check('tests/samples/exe/bad-optional-header-size.exe'))

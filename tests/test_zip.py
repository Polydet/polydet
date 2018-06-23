from unittest import TestCase

from polydet import PolyglotLevel
from polydet.plugins import zip


class TestZIPDetector(TestCase):
    def test_check_regular_file(self):
        self.assertEqual(PolyglotLevel(),
                         zip.check('tests/samples/zip/regular.zip'))

    def test_check_garbage_at_the_beginning(self):
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0, 0x8F)]),
                         zip.check('tests/samples/zip/garbage_at_beginning.zip'))

    def test_check_garbage_at_the_end(self):
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0xB5, 0x10)]),
                         zip.check('tests/samples/zip/garbage_at_end.zip'))

    def test_check_docx(self):
        self.assertEqual(PolyglotLevel(embedded={'docx'}),
                         zip.check('tests/samples/zip/docx.docx'))

    def test_check_jar(self):
        self.assertEqual(PolyglotLevel(embedded={'jar'}),
                         zip.check('tests/samples/zip/jar.jar'))

    def test_check_apk(self):
        self.assertEqual(PolyglotLevel(embedded={'apk', 'jar'}),
                         zip.check('tests/samples/zip/apk.apk'))

    def test_too_short(self):
        self.assertIsNone(zip.check('tests/samples/zip/too_short'))

    def test_fake_docx_or_jar(self):
        self.assertEqual(PolyglotLevel(), zip.check('tests/samples/zip/false-docx-jar.zip'))

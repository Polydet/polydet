from unittest import TestCase

from polyglot_detector import PolyglotLevel
from polyglot_detector.plugins import zip


class TestZIPDetector(TestCase):
    def test_check_regular_file(self):
        result = zip.check('tests/samples/zip/regular.zip')
        self.assertEqual(PolyglotLevel.VALID, result)

    def test_check_garbage_at_the_beginning(self):
        result = zip.check('tests/samples/zip/garbage_at_beginning.zip')
        self.assertEqual(PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_BEGINNING, result)

    def test_check_garbage_at_the_end(self):
        result = zip.check('tests/samples/zip/garbage_at_end.zip')
        self.assertEqual(PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END, result)

    def test_check_docx(self):
        result = zip.check('tests/samples/zip/docx.docx')
        self.assertEqual(PolyglotLevel.VALID.with_embedded('docx'), result)

    def test_check_jar(self):
        result = zip.check('tests/samples/zip/jar.jar')
        self.assertEqual(PolyglotLevel.VALID.with_embedded('jar'), result)

    def test_too_short(self):
        result = zip.check('tests/samples/zip/too_short')
        self.assertIsNone(result)

    def test_fake_docx_or_jar(self):
        result = zip.check('tests/samples/zip/false-docx-jar.zip')
        self.assertEqual(PolyglotLevel.VALID, result)

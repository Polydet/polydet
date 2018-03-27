from unittest import TestCase

from polyglot_detector import PolyglotLevel
from polyglot_detector.plugins import zip


class TestZIPDetector(TestCase):
    def test_check_regular_file(self):
        result = zip.check('tests/samples/zip/regular.zip')
        self.assertEqual(result, PolyglotLevel.VALID)

    def test_check_garbage_at_the_beginning(self):
        result = zip.check('tests/samples/zip/garbage_at_beginning.zip')
        self.assertEqual(result, PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_BEGINNING)

    def test_check_garbage_at_the_end(self):
        result = zip.check('tests/samples/zip/garbage_at_end.zip')
        self.assertEqual(result, PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END)

    def test_check_docx(self):
        result = zip.check('tests/samples/zip/docx.docx')
        self.assertEqual(result, PolyglotLevel.VALID.with_embedded('docx'))

    def test_check_jar(self):
        result = zip.check('tests/samples/zip/jar.jar')
        self.assertEqual(result, PolyglotLevel.VALID.with_embedded('jar'))

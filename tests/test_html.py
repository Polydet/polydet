from unittest import TestCase

from polyglot_detector import PolyglotLevel
from polyglot_detector.plugins import html


class TestHTMLDetector(TestCase):
    def test_base_file(self):
        result = html.check('tests/samples/html/base.html')
        self.assertEqual(PolyglotLevel.VALID, result)

    def test_not_html(self):
        self.assertIsNone(html.check('tests/samples/zip/regular.zip'))

    def test_only_doctype(self):
        result = html.check('tests/samples/html/only_doctype.html')
        self.assertEqual(PolyglotLevel.VALID, result)

    def test_only_html(self):
        result = html.check('tests/samples/html/only_html.html')
        self.assertEqual(PolyglotLevel.VALID, result)

    def test_only_body(self):
        result = html.check('tests/samples/html/only_body.html')
        self.assertEqual(PolyglotLevel.VALID, result)

    def test_only_js(self):
        result = html.check('tests/samples/html/only_js.html')
        self.assertEqual(PolyglotLevel.VALID, result)

    def test_lone_body(self):
        result = html.check('tests/samples/html/lone_body.html')
        self.assertEqual(PolyglotLevel.VALID, result)

    def test_garbage_beginning_1(self):
        result = html.check('tests/samples/html/garbage_beginning_1.html')
        self.assertEqual(PolyglotLevel.VALID
                         | PolyglotLevel.GARBAGE_AT_BEGINNING,
                         result)

    def test_garbage_beginning_2(self):
        result = html.check('tests/samples/html/garbage_beginning_2.html')
        self.assertEqual(PolyglotLevel.VALID
                         | PolyglotLevel.GARBAGE_AT_BEGINNING,
                         result)

    def test_garbage_end_1(self):
        result = html.check('tests/samples/html/garbage_end_1.html')
        self.assertEqual(PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END,
                         result)

    def test_garbage_end_2(self):
        result = html.check('tests/samples/html/garbage_end_2.html')
        self.assertEqual(PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END,
                         result)

    def test_garbage_end_3(self):
        result = html.check('tests/samples/html/garbage_end_3.html')
        self.assertEqual(PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END,
                         result)

    def test_garbage_end_4(self):
        result = html.check('tests/samples/html/garbage_end_4.html')
        self.assertEqual(PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END,
                         result)

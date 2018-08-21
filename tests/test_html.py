from unittest import TestCase

from polydet import PolyglotLevel
from polydet.plugins import html


class TestHTMLDetector(TestCase):
    def test_base_file(self):
        result = html.check('tests/samples/html/base.html')
        self.assertEqual(PolyglotLevel(), result)

    def test_not_html(self):
        self.assertIsNone(html.check('tests/samples/zip/regular.zip'))

    def test_only_doctype(self):
        result = html.check('tests/samples/html/only_doctype.html')
        self.assertEqual(PolyglotLevel(), result)

    def test_only_html(self):
        result = html.check('tests/samples/html/only_html.html')
        self.assertEqual(PolyglotLevel(), result)

    def test_only_body(self):
        result = html.check('tests/samples/html/only_body.html')
        self.assertEqual(PolyglotLevel(), result)

    def test_only_js(self):
        result = html.check('tests/samples/html/only_js.html')
        self.assertEqual(PolyglotLevel(), result)

    def test_lone_body(self):
        result = html.check('tests/samples/html/lone_body.html')
        self.assertEqual(PolyglotLevel(), result)

    def test_garbage_beginning_1(self):
        result = html.check('tests/samples/html/garbage_beginning_1.html')
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0, 0x14)]),
                         result)

    def test_garbage_beginning_2(self):
        result = html.check('tests/samples/html/garbage_beginning_2.html')
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0, 0x14)]),
                         result)

    def test_garbage_end_1(self):
        result = html.check('tests/samples/html/garbage_end_1.html')
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0xF, 0x12)]),
                         result)

    def test_garbage_end_2(self):
        result = html.check('tests/samples/html/garbage_end_2.html')
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0x1E, 0x12)]),
                         result)

    def test_garbage_end_3(self):
        result = html.check('tests/samples/html/garbage_end_3.html')
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0xE, 0x12)]),
                         result)

    def test_garbage_end_4(self):
        result = html.check('tests/samples/html/garbage_end_4.html')
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0x6, 0x12)]),
                         result)

    def test_whitespace_beginning(self):
        result = html.check('tests/samples/html/whitespace_beginning.html')
        self.assertEqual(PolyglotLevel(), result)

import unittest

from polyglot_detector import PolyglotLevel
from polyglot_detector.plugins import rar


class TestRARDetector(unittest.TestCase):
    # TODO: Add RAR5
    def test_rar3_regular(self):
        self.assertEqual(rar.check('tests/samples/rar/regular.rar'), PolyglotLevel.VALID)

    def test_not_rar(self):
        self.assertIsNone(rar.check('tests/samples/zip/regular.zip'))

    def test_rar3_garbage_at_beginning(self):
        self.assertEqual(rar.check('tests/samples/rar/garbage-at-beginning.rar'),
                         PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_BEGINNING)

    def test_rar3_garbage_at_end(self):
        self.assertEqual(rar.check('tests/samples/rar/garbage-at-end.rar'),
                         PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END)

    def test_rar3_garbage_everywhere(self):
        self.assertEqual(rar.check('tests/samples/rar/garbage-at-beginning-end.rar'),
                         PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_BEGINNING | PolyglotLevel.GARBAGE_AT_END)

    def test_no_endarc(self):
        self.assertEqual(rar.check('tests/samples/rar/no-endarc.rar'), PolyglotLevel.VALID)

    def test_unexpected_eof(self):
        self.assertEqual(rar.check('tests/samples/rar/unexpected_eof.rar'), PolyglotLevel.INVALID)

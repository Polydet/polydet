import unittest

from polyglot_detector import PolyglotLevel
from polyglot_detector.plugins import rar


class TestRARDetector(unittest.TestCase):
    # TODO: Add RAR5
    def test_rar3_regular(self):
        self.assertEqual(PolyglotLevel.VALID, rar.check('tests/samples/rar/regular.rar'))

    def test_not_rar(self):
        self.assertIsNone(rar.check('tests/samples/zip/regular.zip'))

    def test_rar3_garbage_at_beginning(self):
        self.assertEqual(PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_BEGINNING,
                         rar.check('tests/samples/rar/garbage-at-beginning.rar'))

    def test_rar3_garbage_at_end(self):
        self.assertEqual(PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END,
                         rar.check('tests/samples/rar/garbage-at-end.rar'))

    def test_rar3_garbage_everywhere(self):
        self.assertEqual(PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_BEGINNING | PolyglotLevel.GARBAGE_AT_END,
                         rar.check('tests/samples/rar/garbage-at-beginning-end.rar'))

    def test_rar3_no_endarc(self):
        self.assertEqual(PolyglotLevel.VALID, rar.check('tests/samples/rar/no-endarc.rar'))

    def test_rar3_unexpected_eof(self):
        self.assertEqual(PolyglotLevel.INVALID, rar.check('tests/samples/rar/unexpected_eof.rar'))

    def test_rar5_regular(self):
        self.assertEqual(PolyglotLevel.VALID, rar.check('tests/samples/rar/regular.rar5'))

    def test_rar5_garbage_at_beginning(self):
        self.assertEqual(PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_BEGINNING,
                         rar.check('tests/samples/rar/garbage-at-beginning.rar5'))

    def test_rar5_garbage_at_end(self):
        self.assertEqual(PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END,
                         rar.check('tests/samples/rar/garbage-at-end.rar5'))

    def test_rar5_no_endarc(self):
        self.assertEqual(PolyglotLevel.VALID, rar.check('tests/samples/rar/no-endarc.rar5'))

    def test_rar5_unexpected_eof(self):
        self.assertEqual(PolyglotLevel.INVALID, rar.check('tests/samples/rar/unexpected_eof.rar5'))

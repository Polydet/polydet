import unittest

from polydet import PolyglotLevel
from polydet.plugins import rar


class TestRARDetector(unittest.TestCase):
    def test_rar3_regular(self):
        self.assertEqual(PolyglotLevel(), rar.check('tests/samples/rar/regular.rar'))

    def test_not_rar(self):
        self.assertIsNone(rar.check('tests/samples/zip/regular.zip'))

    def test_rar3_garbage_at_beginning(self):
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0, 0x2060)]),
                         rar.check('tests/samples/rar/garbage-at-beginning.rar'))

    def test_rar3_garbage_at_end(self):
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0x59, 0x343)]),
                         rar.check('tests/samples/rar/garbage-at-end.rar'))

    def test_rar3_garbage_everywhere(self):
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0, 0x2060), (0x20B9, 0x343)]),
                         rar.check('tests/samples/rar/garbage-at-beginning-end.rar'))

    def test_rar3_no_endarc(self):
        self.assertEqual(PolyglotLevel(), rar.check('tests/samples/rar/no-endarc.rar'))

    def test_rar3_unexpected_eof(self):
        self.assertEqual(PolyglotLevel(is_valid=False), rar.check('tests/samples/rar/unexpected_eof.rar'))

    def test_rar3_garbage_at_end_no_endarc_size_0(self):
        self.assertEqual(PolyglotLevel(is_valid=False, suspicious_chunks=[(0x52, 0xC1)]),
                         rar.check('tests/samples/rar/garbage_at_end-no_endarc.rar'))

    def test_rar5_garbage_at_end_no_endarc(self):
        # FIXME Should be (0x4E, 0xC1), but the current reader can't discard all the invalid blocks
        # when there is no ENDARC
        self.assertEqual(PolyglotLevel(is_valid=False, suspicious_chunks=[(0x62, 0xAD)]),
                         rar.check('tests/samples/rar/garbage_at_end-no_endarc.rar5'))

    def test_rar5_regular(self):
        self.assertEqual(PolyglotLevel(),
                         rar.check('tests/samples/rar/regular.rar5'))

    def test_rar5_garbage_at_beginning(self):
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0, 0x1F8)]),
                         rar.check('tests/samples/rar/garbage-at-beginning.rar5'))

    def test_rar5_garbage_at_end(self):
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0x56, 0x343)]),
                         rar.check('tests/samples/rar/garbage-at-end.rar5'))

    def test_rar5_no_endarc(self):
        self.assertEqual(PolyglotLevel(),
                         rar.check('tests/samples/rar/no-endarc.rar5'))

    def test_rar5_unexpected_eof(self):
        self.assertEqual(PolyglotLevel(is_valid=False),
                         rar.check('tests/samples/rar/unexpected_eof.rar5'))

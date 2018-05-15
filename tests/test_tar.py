import unittest

from polyglot_detector import PolyglotLevel
from polyglot_detector.plugins import tar


# TODO: look at https://sourceforge.net/projects/s-tar/files/testscripts/ for tests
class TestTARDetector(unittest.TestCase):
    def test_is_tar(self):
        self.assertEqual(PolyglotLevel.VALID, tar.check('tests/samples/tar/regular.tar'))

    def test_is_not_tar(self):
        # From https://sourceforge.net/projects/s-tar/files/testscripts/
        self.assertIsNone(tar.check('tests/samples/tar/not_a_tar_file'))
        self.assertIsNone(tar.check('tests/samples/zip/regular.zip'))

    def test_payload_in_filename_field(self):
        self.assertEqual(PolyglotLevel.VALID | PolyglotLevel.GARBAGE_IN_MIDDLE,
                         tar.check('tests/samples/tar/payload_in_filename_field.tar'))

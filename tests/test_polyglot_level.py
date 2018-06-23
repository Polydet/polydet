from unittest import TestCase

from polydet import PolyglotLevel


class TestPolyglotLevel(TestCase):
    def test_equal(self):
        self.assertEqual(PolyglotLevel(), PolyglotLevel())
        self.assertEqual(PolyglotLevel(is_valid=False,
                                       suspicious_chunks=[(0, 100), (105, 5)],
                                       embedded={'docx', 'jar'}),
                         PolyglotLevel(is_valid=False,
                                       suspicious_chunks=[(0, 100), (105, 5)],
                                       embedded={'docx', 'jar'}))

    def test_builder(self):
        self.assertEqual(PolyglotLevel(is_valid=False), PolyglotLevel().invalid())
        self.assertEqual(PolyglotLevel(suspicious_chunks=[(0, 100), (105, 5)]),
                         PolyglotLevel()
                         .add_chunk(0, 100)
                         .add_chunk(105, 5))
        self.assertEqual(PolyglotLevel(embedded={'jar'}), PolyglotLevel().embed('jar'))

    def test_str(self):
        self.assertEqual('PolyglotLevel()', str(PolyglotLevel()))
        self.assertEqual('PolyglotLevel(is_valid=False)', str(PolyglotLevel(is_valid=False)))
        self.assertEqual('PolyglotLevel(suspicious_chunks=[(0, 100), (5, 200)])',
                         str(PolyglotLevel(suspicious_chunks=[(0, 100), (5, 200)])))
        self.assertEqual("PolyglotLevel(embedded={'docx'})", str(PolyglotLevel(embedded={'docx'})))
        self.assertEqual("PolyglotLevel(is_valid=False, suspicious_chunks=[(0, 100), (5, 200)], embedded={'jar'})",
                         str(PolyglotLevel(is_valid=False, suspicious_chunks=[(0, 100), (5, 200)], embedded={'jar'})))

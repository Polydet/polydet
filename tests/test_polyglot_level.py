from unittest import TestCase

from polyglot_detector import PolyglotLevel


class TestPolyglotLevel(TestCase):
    def test_eq(self):
        self.assertEqual(PolyglotLevel.VALID, PolyglotLevel.VALID)
        self.assertEqual(PolyglotLevel.GARBAGE_AT_BEGINNING, PolyglotLevel.GARBAGE_AT_BEGINNING)
        self.assertEqual(PolyglotLevel.GARBAGE_AT_END, PolyglotLevel.GARBAGE_AT_END)
        self.assertEqual(PolyglotLevel.GARBAGE_IN_MIDDLE, PolyglotLevel.GARBAGE_IN_MIDDLE)
        self.assertEqual(PolyglotLevel.EMBED, PolyglotLevel.EMBED)
        self.assertEqual(PolyglotLevel.EMBED.with_embedded('jar'), PolyglotLevel.EMBED.with_embedded('jar'))

        self.assertNotEqual(PolyglotLevel.VALID, PolyglotLevel.GARBAGE_AT_BEGINNING)
        self.assertNotEqual(PolyglotLevel.GARBAGE_AT_BEGINNING, PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END)

    def test_xor(self):
        self.assertEqual(PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END,
                         PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END)
        self.assertEqual(PolyglotLevel.VALID.with_embedded('jar').with_embedded('zip'),
                         PolyglotLevel.VALID.with_embedded('jar') | PolyglotLevel.VALID.with_embedded('zip'))

    def test_str(self):
        self.assertEqual('PolyglotLevel.VALID', str(PolyglotLevel.VALID))
        self.assertEqual('PolyglotLevel.INVALID', str(PolyglotLevel.INVALID))
        self.assertEqual('PolyglotLevel.VALID|GARBAGE_AT_BEGINNING',
                         str(PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_BEGINNING))
        self.assertEqual('PolyglotLevel.VALID|EMBED(jar)', str(PolyglotLevel.VALID.with_embedded('jar')))
        self.assertEqual('PolyglotLevel.VALID|EMBED(docx,jar)',
                         str(PolyglotLevel.VALID.with_embedded('jar').with_embedded('docx')))

    def test_invert(self):
        self.assertEqual(PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END | PolyglotLevel.EMBED,
                         ~(PolyglotLevel.INVALID | PolyglotLevel.GARBAGE_IN_MIDDLE | PolyglotLevel.GARBAGE_AT_BEGINNING))

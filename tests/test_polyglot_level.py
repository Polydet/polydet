from unittest import TestCase

from polyglot_detector import PolyglotLevel


class TestPolyglotLevel(TestCase):
    def test_eq(self):
        self.assertEqual(PolyglotLevel.VALID, PolyglotLevel.VALID)
        self.assertEqual(PolyglotLevel.GARBAGE_AT_BEGINNING, PolyglotLevel.GARBAGE_AT_BEGINNING)
        self.assertEqual(PolyglotLevel.GARBAGE_AT_END, PolyglotLevel.GARBAGE_AT_END)
        self.assertEqual(PolyglotLevel.EMBED, PolyglotLevel.EMBED)
        self.assertEqual(PolyglotLevel.EMBED.with_embedded('jar'), PolyglotLevel.EMBED.with_embedded('jar'))

        self.assertNotEqual(PolyglotLevel.VALID, PolyglotLevel.GARBAGE_AT_BEGINNING)
        self.assertNotEqual(PolyglotLevel.GARBAGE_AT_BEGINNING, PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END)

    def test_xor(self):
        self.assertEqual(PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END,
                         PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_END)
        self.assertEqual(PolyglotLevel.VALID.with_embedded('jar') | PolyglotLevel.VALID.with_embedded('zip'),
                         PolyglotLevel.VALID.with_embedded('jar').with_embedded('zip'))

    def test_str(self):
        self.assertEqual(str(PolyglotLevel.VALID), 'PolyglotLevel.VALID')
        self.assertEqual(str(PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_BEGINNING),
                         'PolyglotLevel.VALID|GARBAGE_AT_BEGINNING')
        self.assertEqual(str(PolyglotLevel.VALID.with_embedded('jar')), 'PolyglotLevel.VALID|EMBED(jar)')
        self.assertEqual(str(PolyglotLevel.VALID.with_embedded('jar').with_embedded('docx')),
                         'PolyglotLevel.VALID|EMBED(docx,jar)')

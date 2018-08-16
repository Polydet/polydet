import os
import yara
from polydet.polyglot_level import PolyglotLevel


FILE_EXTENSION = 'pdf'

RULES = """
rule HasTruncatedMagic {
  strings:
    $magic = "%PDF-"
  condition:
    $magic
}
rule HasMagic {
  strings:
    $magic = /%PDF-\d.\d\\r?\\n/
  condition:
    $magic
}
rule HasEOF {
  strings:
    $eof = /\\n%%EOF\\r?\\n?/
  condition:
    HasTruncatedMagic and $eof
}
rule IsPDF {
  strings:
    $root_obj = /<<.*\/Root.+>>/is // TODO Test a PDF with /rOOT
  condition:
    HasTruncatedMagic or $root_obj
}
"""


def check(filename):
    rules = yara.compile(source=RULES)
    matches = rules.match(filename)
    return check_with_matches(filename, {m.rule: m for m in matches})


def check_with_matches(filename, matches):
    if 'IsPDF' not in matches:
        return None

    level = PolyglotLevel()

    if 'HasTruncatedMagic' in matches:
        truncated_magic_offset = matches['HasTruncatedMagic'].strings[0][0]

        magic_offset = matches['HasMagic'].strings[0][0] if 'HasMagic' in matches else None

        # If the offset of the full magic is the first magic found in the file
        if not (magic_offset == truncated_magic_offset <= 1024):
            level.invalid()

        if truncated_magic_offset > 0:
            level.add_chunk(0, truncated_magic_offset)

    eof_match = matches['HasEOF'].strings[-1] if 'HasEOF' in matches else None
    file_size = os.stat(filename).st_size

    if eof_match is not None and eof_match[0] + len(eof_match[2]) < file_size:
        pdf_end = eof_match[0] + len(eof_match[2])
        level.add_chunk(pdf_end, file_size - pdf_end)

    return level

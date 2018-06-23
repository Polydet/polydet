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
    $magic = /%PDF-\d.\d\\n/
  condition:
    $magic
}
rule HasEOF {
  strings:
    $eof = /\\n%%EOF\\n?/
  condition:
    HasTruncatedMagic and $eof
}
"""


def check(filename):
    rules = yara.compile(source=RULES)
    matches = rules.match(filename)
    return check_with_matches(filename, {m.rule: m for m in matches})


def check_with_matches(filename, matches):
    truncated_magic_offset = matches['HasTruncatedMagic'].strings[0][0] if 'HasTruncatedMagic' in matches else None
    if truncated_magic_offset is None:
        return None

    magic_offset = matches['HasMagic'].strings[0][0] if 'HasMagic' in matches else None
    eof_match = matches['HasEOF'].strings[-1] if 'HasEOF' in matches else None

    # If the offset of the full magic is the first magic found in the file
    level = PolyglotLevel(is_valid=magic_offset == truncated_magic_offset <= 1024)

    if truncated_magic_offset > 0:
        level.add_chunk(0, truncated_magic_offset)

    file_size = os.stat(filename).st_size

    if eof_match is not None and eof_match[0] + len(eof_match[2]) < file_size:
        pdf_end = eof_match[0] + len(eof_match[2])
        level.add_chunk(pdf_end, file_size - pdf_end)

    return level

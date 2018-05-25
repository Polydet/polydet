import os
import yara

from polyglot_detector.polyglot_level import PolyglotLevel

RULES = """
rule OGGHeader {
  strings:
    $magic = "OggS"
  condition:
    $magic
}
"""


def check(filename):
    rules = yara.compile(source=RULES)
    matches = rules.match(filename)
    return check_with_matches(filename, {m.rule: m for m in matches})


def check_with_matches(filename: str, matches):
    if 'OGGHeader' not in matches:
        return None
    flag = PolyglotLevel.VALID
    if matches['OGGHeader'].strings[0][0] > 0:
        flag |= PolyglotLevel.GARBAGE_AT_BEGINNING
    for string_idx, string in enumerate(matches['OGGHeader'].strings):
        page_size = __get_page_size(filename, string)
        if string_idx < len(matches['OGGHeader'].strings) - 1:
            if matches['OGGHeader'].strings[string_idx + 1][0] > string[0] + page_size:
                flag |= PolyglotLevel.GARBAGE_IN_MIDDLE
        else:
            if os.stat(filename).st_size != string[0] + page_size:
                flag |= PolyglotLevel.GARBAGE_AT_END
    return flag


def __get_page_size(filename, string):
    with open(filename, 'rb') as file:
        file.seek(string[0] + 26)
        segments_nb = int.from_bytes(file.read(1), byteorder='big')
        segment_table = file.read(segments_nb)
        size = sum(segment_table) + 27 + len(segment_table)
        return size

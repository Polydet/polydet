import os
import yara

from polydet.polyglot_level import PolyglotLevel

FILE_EXTENSION = 'ogg'

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
    level = PolyglotLevel()
    begin_offset = matches['OGGHeader'].strings[0][0]
    if begin_offset > 0:
        level.add_chunk(0, begin_offset)
    for string_idx, string in enumerate(matches['OGGHeader'].strings):
        page_size = __get_page_size(filename, string)
        if string_idx < len(matches['OGGHeader'].strings) - 1:
            next_header_offset = matches['OGGHeader'].strings[string_idx + 1][0]
            if next_header_offset > string[0] + page_size:
                level.add_chunk(string[0] + page_size, next_header_offset - (string[0] + page_size))
        else:
            file_size = os.stat(filename).st_size
            end_offset = string[0] + page_size
            if file_size != end_offset:
                level.add_chunk(end_offset, file_size - end_offset)
    return level


def __get_page_size(filename, string):
    with open(filename, 'rb') as file:
        file.seek(string[0] + 26)
        segments_nb = int.from_bytes(file.read(1), byteorder='big')
        segment_table = file.read(segments_nb)
        size = sum(segment_table) + 27 + len(segment_table)
        return size

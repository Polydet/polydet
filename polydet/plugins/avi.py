import os
import yara

from polydet.polyglot_level import PolyglotLevel

FILE_EXTENSION = 'avi'

RULES = """
rule AVIHeader {
  strings:
    //          R  I  F  F              A  V  I SP
    $magic = { 52 49 46 46 ?? ?? ?? ?? 41 56 49 20 }
  condition:
    $magic
}
"""


def check(filename):
    rules = yara.compile(source=RULES)
    matches = rules.match(filename)
    return check_with_matches(filename, {m.rule: m for m in matches})


def check_with_matches(filename: str, matches):
    if 'AVIHeader' not in matches:
        return None
    level = PolyglotLevel()
    start = matches['AVIHeader'].strings[0][0]
    if start > 0:
        level.add_chunk(0, start)
    size = __get_size(matches['AVIHeader'].strings[0][2])
    end_offset = start + size
    file_size = os.stat(filename).st_size
    if end_offset < file_size:
        level.add_chunk(end_offset, file_size - end_offset)
    return level


# The size of the file should be equal to the size indicated
# by the four bytes in the middle of the signature in middle endian,
# plus eight to account for the first eight "container" bytes.
def __get_size(string):
    return int.from_bytes(string[4:8], byteorder='little') + 8

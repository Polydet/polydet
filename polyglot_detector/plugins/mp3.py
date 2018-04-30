import mmap
import yara

from polyglot_detector.polyglot_level import PolyglotLevel

FILE_EXTENSION = 'mp3'

RULES = """
rule IsMP3 {
  strings:
    $magic = { FF FB }
  condition:
    $magic
}

rule HasID3 {
  strings:
    //        I  D  3
    $id3 = { 49 44 33 [6] ?? }
  condition:
    $id3 at 0
}
"""

_MAGIC = b'\xFF\xFB'


def check(filename):
    rules = yara.compile(source=RULES)
    matches = rules.match(filename)
    return check_with_matches(filename, {m.rule: m for m in matches})


def check_with_matches(filename: str, matches):
    if 'IsMP3' not in matches:
        return None
    begin = 0
    if 'HasID3' in matches:
        size = __synchsafe(bytes(matches['HasID3'].strings[0][2][6:]))
        begin = 10 + size
    flag = PolyglotLevel.VALID
    if matches['IsMP3'].strings[0][0] > begin:
        flag |= PolyglotLevel.GARBAGE_AT_BEGINNING
    return flag


# synchsafe is a number encoding method in ID3V2 which removes the highest bit.
def __synchsafe(input: bytes):
    ret = 0
    for byte in input:
        ret *= 128
        ret += int(byte) & 127
    return ret

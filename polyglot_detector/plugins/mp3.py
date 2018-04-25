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
"""

_MAGIC = b'\xFF\xFB'


def check(filename):
    rules = yara.compile(source=RULES)
    matches = rules.match(filename)
    return check_with_matches(filename, {m.rule: m for m in matches})


def check_with_matches(filename: str, matches):
    if 'IsMP3' not in matches:
        return None

    with open(filename, 'rb') as file:
        begin = 0
        if file.read(len("ID3")) == b'ID3':
            file.seek(6)
            size = __synchsafe(file.read(4))
            begin = 10 + size
        try:
            with mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as s:
                flag = PolyglotLevel.VALID
                magic = s.find(_MAGIC)
                if magic > begin:
                    flag |= PolyglotLevel.GARBAGE_AT_BEGINNING
                return flag
        except ValueError:  # mmap raise ValueError if empty file
            return None


# synchsafe is a number encoding method in ID3V2 which removes the highest bit.
def __synchsafe(input: bytes):
    ret = 0
    for byte in input:
        ret *= 128
        ret += int(byte) & 127
    return ret

import mmap
from polyglot_detector.polyglot_level import PolyglotLevel


# TODO Check if the magic is within the first 1024 bytes to declare VALID ?
def check(filename):
    magic = b"%PDF-"

    with open(filename, 'rb') as file, \
            mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as s:
        magic_index = s.find(magic)
        if magic_index == -1:
            return None
        elif magic_index == 0:
            return PolyglotLevel.VALID
        else:
            return PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_BEGINNING

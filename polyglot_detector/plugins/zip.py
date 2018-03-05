import mmap
from polyglot_detector.polyglot_level import PolyglotLevel

FILE_EXTENSION = 'zip'

MAGIC = b'PK'
EOCD_MIN_SIZE = 22


# TODO Return GARBAGE_AT_END only if garbage after comment ?
def check(filename):
    with open(filename, 'rb') as file:
        try:
            with mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as s:
                size = s.size()
                magic_index = s.rfind(MAGIC, 0, max(0, size - EOCD_MIN_SIZE + len(MAGIC)))
                if magic_index == -1:
                    return None
                else:
                    size_of_eocd = size - magic_index
                    flag = PolyglotLevel.VALID
                    if s.find(MAGIC) != 0:
                        flag |= PolyglotLevel.GARBAGE_AT_BEGINNING
                    if size_of_eocd != EOCD_MIN_SIZE:
                        flag |= PolyglotLevel.GARBAGE_AT_END
                    return flag
        except ValueError:  # mmap raise ValueError if empty file
            return None

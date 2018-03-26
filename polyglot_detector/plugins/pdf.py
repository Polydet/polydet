import mmap
from polyglot_detector.polyglot_level import PolyglotLevel


FILE_EXTENSION = 'pdf'


_PDF_EOF = b'\n%%EOF'


# TODO Check if the magic is within the first 1024 bytes to declare VALID ?
def check(filename):
    magic = b"%PDF-"

    with open(filename, 'rb') as file:
        try:
            with mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as s:
                magic_index = s.find(magic)
                if magic_index == -1:
                    return None
                flag = PolyglotLevel.VALID
                if magic_index != 0:
                    flag |= PolyglotLevel.GARBAGE_AT_BEGINNING
                if has_garbage_at_end(s):
                    flag |= PolyglotLevel.GARBAGE_AT_END
                return {'result': flag}
        except ValueError:  # mmap raise ValueError if empty file
            return None


def has_garbage_at_end(buffer) -> bool:
    eof_index = buffer.find(_PDF_EOF)
    return eof_index != -1 and eof_index + len(_PDF_EOF) + 1 < buffer.size()  # +1 for potential \n

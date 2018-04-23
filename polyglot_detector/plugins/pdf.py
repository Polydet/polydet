import mmap
import re
from polyglot_detector.polyglot_level import PolyglotLevel


FILE_EXTENSION = 'pdf'


__PDF_MAGIC = b'%PDF-'
__PDF_EOF = b'\n%%EOF'

__PDF_FULL_MAGIC_LEN = 9
__PDF_FULL_MAGIC_RE = re.compile(b'%PDF-\d.\d\n')


def check(filename):

    with open(filename, 'rb') as file:
        try:
            with mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as buf:

                magic_offset = buf.find(__PDF_MAGIC)
                if magic_offset == -1:
                    return None

                if magic_offset <= 1024 and is_magic_valid(buf, magic_offset):
                    flag = PolyglotLevel.VALID
                else:
                    flag = PolyglotLevel.INVALID

                if magic_offset != 0:
                    flag |= PolyglotLevel.GARBAGE_AT_BEGINNING
                if has_garbage_at_end(buf):
                    flag |= PolyglotLevel.GARBAGE_AT_END

                return flag

        except ValueError:  # mmap raise ValueError if empty file
            return None


def is_magic_valid(buf, magic_offset) -> bool:
    buf.seek(magic_offset)
    full_magic = buf.read(__PDF_FULL_MAGIC_LEN)
    return __PDF_FULL_MAGIC_RE.match(full_magic) is not None


def has_garbage_at_end(buf) -> bool:
    eof_index = buf.find(__PDF_EOF)
    return eof_index != -1 and eof_index + len(__PDF_EOF) + 1 < buf.size()  # +1 for potential \n

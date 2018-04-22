import io
import mmap
import struct

from polyglot_detector.polyglot_level import PolyglotLevel
from polyglot_detector.utils import must_read


FILE_EXTENSION = 'jpg'


__JPG_MAGIC = b'\xFF\xD8'
__JPG_START_OF_SCAN = b'\xFF\xDA'
__JPG_END_MARKER = b'\xFF\xD9'


def check(filename: str):
    with open(filename, 'rb') as file:
        try:
            with mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as buf:
                if buf.read(len(__JPG_MAGIC)) != __JPG_MAGIC:
                    return None
                flag = PolyglotLevel.VALID

                try:
                    section = b''
                    while section != __JPG_START_OF_SCAN:
                        section, length = read_section(buf)
                        buf.seek(length - 2, io.SEEK_CUR)
                except (ValueError, SyntaxError):
                    return PolyglotLevel.INVALID

                # Read the image data until end marker
                end_marker_pos = buf.find(__JPG_END_MARKER, buf.tell())
                if end_marker_pos != -1 and end_marker_pos + len(__JPG_END_MARKER) < buf.size():
                    flag |= PolyglotLevel.GARBAGE_AT_END
                return flag

        except ValueError:
            return None


def read_section(file) -> (int, int):
    section = must_read(file, 2)
    length = struct.unpack('>H', must_read(file, 2))[0]
    return section, length

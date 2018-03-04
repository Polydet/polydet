import io
import struct
from .polyglot_level import PolyglotLevel
from .utils import must_read


_MAGIC = b'\xFF\xD8'
_START_OF_SCAN = b'\xFF\xDA'
_END_MARKER = b'\xFF\xD9'


def check(filename: str):
    with open(filename, 'rb') as file:
        if file.read(len(_MAGIC)) != _MAGIC:
            return None

        flag = PolyglotLevel.VALID

        # Read the sections until start of scan
        try:
            section = ''
            while section != _START_OF_SCAN:
                section, length = read_section(file)
                file.seek(length - 2, io.SEEK_CUR)
        except SyntaxError:
            return None

        # Read the image data until end marker
        # TODO Optimize
        buf = file.read()
        end_marker_pos = buf.find(_END_MARKER)
        # TODO Do what when no marker ?
        if end_marker_pos != -1 and len(buf) > end_marker_pos + 2:
            flag |= PolyglotLevel.GARBAGE_AT_END
        return flag


def read_section(file) -> (int, int):
    section = must_read(file, 2)
    length = struct.unpack('>H', must_read(file, 2))[0]
    return section, length

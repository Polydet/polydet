import io
from struct import unpack

from PIL.BmpImagePlugin import BmpImageFile
from polyglot_detector.polyglot_level import PolyglotLevel

FILE_EXTENSION = 'bmp'


def check(filename):
    try:
        image = BmpImageFile(filename)
    except SyntaxError:
        return None
    flag = PolyglotLevel.VALID
    image.fp.seek(2)
    file_size = unpack('<I', image.fp.read(4))[0]
    image.fp.seek(0, io.SEEK_END)
    if image.fp.tell() != file_size:
        flag |= PolyglotLevel.GARBAGE_AT_END
    return flag

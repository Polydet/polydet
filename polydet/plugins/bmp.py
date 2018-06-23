import io
from struct import unpack
import yara

from PIL.BmpImagePlugin import BmpImageFile
from polydet.polyglot_level import PolyglotLevel

FILE_EXTENSION = 'bmp'

RULES = """
rule IsBMP {
  strings:
    $magic = { 42 4D }
  condition:
    $magic at 0
}
"""


def check(filename):
    rules = yara.compile(source=RULES)
    matches = rules.match(filename)
    return check_with_matches(filename, {m.rule: m for m in matches})


def check_with_matches(filename, matches):
    if 'IsBMP' not in matches:
        return None

    try:
        with BmpImageFile(filename) as image:
            level = PolyglotLevel()
            image.fp.seek(2)
            image_size = unpack('<I', image.fp.read(4))[0]
            image.fp.seek(0, io.SEEK_END)
            file_size = image.fp.tell()
            if file_size != image_size:
                level.add_chunk(image_size, file_size - image_size)
            return level
    except SyntaxError:
        return None

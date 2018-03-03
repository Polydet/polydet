from PIL.PngImagePlugin import PngImageFile
from .polyglot_level import PolyglotLevel


def check(filename: str):
    try:
        file = PngImageFile(filename)
    except SyntaxError:
        return None
    flag = PolyglotLevel.VALID
    # back up to beginning of IDAT block (see PngImageFile.verify)
    file.fp.seek(file.tile[0][2] - 8)
    # Verify the png without closing it
    file.png.verify()
    if len(file.png.fp.read(8)) != 4:  # There is something after the CRC
        flag |= PolyglotLevel.GARBAGE_AT_END
    file.close()
    return flag

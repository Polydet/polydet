from PIL.TiffImagePlugin import TiffImageFile

from polyglot_detector.polyglot_level import PolyglotLevel

FILE_EXTENSION = 'tiff'


def check(filename: str):
    try:
        from PIL import TiffImagePlugin
        TiffImageFile(filename)
    except SyntaxError:
        return None
    return PolyglotLevel.VALID

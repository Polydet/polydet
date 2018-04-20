from PIL.TiffImagePlugin import TiffImageFile

from polyglot_detector.polyglot_level import PolyglotLevel

FILE_EXTENSION = 'tiff'


def check(filename: str):
    try:
        with TiffImageFile(filename):
            return PolyglotLevel.VALID
    except SyntaxError:
        return None

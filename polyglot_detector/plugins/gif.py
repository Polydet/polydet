from PIL.GifImagePlugin import GifImageFile
from polyglot_detector.polyglot_level import PolyglotLevel

FILE_EXTENSION = 'gif'


def check(filename):
    try:
        image = GifImageFile(filename)
    except SyntaxError:
        return None

    image.seek(image.n_frames - 1)
    while image.data():  # Pass the last frame
        pass
    flag = PolyglotLevel.VALID
    if image.fp.read(2) != b';':
        flag |= PolyglotLevel.GARBAGE_AT_END
    return flag

from PIL.GifImagePlugin import GifImageFile
import io
import yara

from polydet.polyglot_level import PolyglotLevel

FILE_EXTENSION = 'gif'

RULES = """
rule IsGIF {
  strings:
    $magic = /GIF8[79]a/
  condition:
    $magic at 0
}
"""


def check(filename: str):
    rules = yara.compile(source=RULES)
    matches = rules.match(filename)
    return check_with_matches(filename, {m.rule: m for m in matches})


def check_with_matches(filename, matches):
    if 'IsGIF' not in matches:
        return None

    try:
        with GifImageFile(filename) as image:
            image.seek(image.n_frames - 1)
            while image.data():  # Pass the last frame
                pass
            level = PolyglotLevel()
            image_end = image.fp.tell()
            if image.fp.read(1) == b';':
                image_end += 1
            image.fp.seek(0, io.SEEK_END)
            image_size = image.fp.tell()
            if image_end != image_size:
                level.add_chunk(image_end, image_size - image_end)
            return level
    except SyntaxError:
        return None

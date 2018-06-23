from PIL.GifImagePlugin import GifImageFile
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
            flag = PolyglotLevel.VALID
            if image.fp.read(2) != b';':
                flag |= PolyglotLevel.GARBAGE_AT_END
            return flag
    except SyntaxError:
        return None

import yara

from polydet import PolyglotLevel

FILE_EXTENSION = 'flac'

RULES = """
rule FLACMagic {
  strings:
    $magic = "fLaC"
  condition:
    $magic in (0..29999)
}
"""


def check(filename):
    rules = yara.compile(source=RULES)
    matches = rules.match(filename)
    return check_with_matches(filename, {m.rule: m for m in matches})


def check_with_matches(filename: str, matches):
    if 'FLACMagic' not in matches:
        return None
    level = PolyglotLevel()
    start = matches['FLACMagic'].strings[0][0]
    if start > 0:
        level.add_chunk(0, start)
    return level

import yara

from polyglot_detector.polyglot_level import PolyglotLevel

FILE_EXTENSION = 'wav'

RULES = """
rule WAVHeader {
  strings:
    //          R  I  F  F              W  A  V  E
    $magic = { 52 49 46 46 ?? ?? ?? ?? 57 41 56 45 }
  condition:
    $magic
}
"""


def check(filename):
    rules = yara.compile(source=RULES)
    matches = rules.match(filename)
    return check_with_matches(filename, {m.rule: m for m in matches})


def check_with_matches(filename: str, matches):
    if 'WAVHeader' not in matches:
        return None
    flag = PolyglotLevel.VALID
    if matches['WAVHeader'].strings[0][0] > 0:
        flag |= PolyglotLevel.GARBAGE_AT_BEGINNING
    return flag

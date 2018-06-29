import yara

from polydet import PolyglotLevel

FILE_EXTENSION = '7z'

RULES = """
rule Is7Z {
  strings:
    $magic = { 37 7A BC AF 27 1C }
  condition:
    $magic at 0
}
"""


def check(filename):
    rules = yara.compile(source=RULES)
    matches = rules.match(filename)
    return check_with_matches(filename, {m.rule: m for m in matches})


def check_with_matches(filename, matches):
    if 'Is7Z' in matches:
        return PolyglotLevel()
    return None

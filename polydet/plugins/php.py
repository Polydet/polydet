import yara

from polydet.polyglot_level import PolyglotLevel

FILE_EXTENSION = 'php'

RULES = """
rule HasPHPOpen {
  strings:
    $PHPOpen = /<\?[pP][hH][pP]/
  condition:
    $PHPOpen
}
"""


def check(filename):
    rules = yara.compile(source=RULES)
    matches = rules.match(filename)
    return check_with_matches(filename, {m.rule: m for m in matches})


def check_with_matches(filename, matches):
    if 'HasPHPOpen' not in matches:
        return None
    return PolyglotLevel()

import yara

from polydet.polyglot_level import PolyglotLevel

FILE_EXTENSION = 'elf'

RULES = """
rule IsELF {
  strings:
    //            E  L  F
    $magic = { 7F 45 4C 46 }
  condition:
    $magic at 0
}
"""


def check(filename: str):
    rules = yara.compile(source=RULES)
    matches = rules.match(filename)
    return check_with_matches(filename, {m.rule: m for m in matches})


def check_with_matches(filename, matches):
    if 'IsELF' not in matches:
        return None
    return PolyglotLevel()

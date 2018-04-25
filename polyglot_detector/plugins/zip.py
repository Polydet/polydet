import os
import yara

from polyglot_detector.polyglot_level import PolyglotLevel

FILE_EXTENSION = 'zip'

RULES = """
rule IsZIP {
  strings:
    $EOCD_magic = { 50 4B 05 06 }

  condition:
    $EOCD_magic in (0..filesize - 22)
}
rule GarbageAtBeginning {
  strings:
    $LFH_magic = { 50 4B 03 04 }
  condition:
    not $LFH_magic at 0
}
rule IsDOCX {
  strings:
    $ContentTypesFilename = "[Content_Types].xml"

  condition:
    IsZIP and $ContentTypesFilename
}
rule IsJAR {
  strings:
    $MetaInfFilename = "META-INF"

  condition:
    IsZIP and $MetaInfFilename
}
"""

__EOCD_MIN_SIZE = 22


def check(filename):
    rules = yara.compile(source=RULES)
    matches = rules.match(filename)
    return check_with_matches(filename, {m.rule: m for m in matches})


def check_with_matches(filename, matches):
    zip_rule = matches.get('IsZIP', None)
    if zip_rule is None:
        return None

    flag = PolyglotLevel.VALID

    file_size = os.stat(filename).st_size
    last_eocd_magic = [s for s in zip_rule.strings if s[1] == '$EOCD_magic'][0]
    eocd_offset = last_eocd_magic[0]

    if eocd_offset + __EOCD_MIN_SIZE < file_size:
        flag |= PolyglotLevel.GARBAGE_AT_END

    if 'GarbageAtBeginning' in matches:
        flag |= PolyglotLevel.GARBAGE_AT_BEGINNING

    if 'IsDOCX' in matches:
        flag = flag.with_embedded('docx')

    if 'IsJAR' in matches:
        flag = flag.with_embedded('jar')

    return flag

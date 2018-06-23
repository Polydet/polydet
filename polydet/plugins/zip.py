import os
import yara

from polydet.polyglot_level import PolyglotLevel

FILE_EXTENSION = 'zip'

RULES = """
rule IsZIP {
  strings:
    $EOCD_magic = { 50 4B 05 06 }

  condition:
    $EOCD_magic in (0..filesize - 22)
}
rule HasZIPMagic {
  strings:
    $CDFH_magic = { 50 4B 01 02 }
    $LFH_magic = { 50 4B 03 04 }
    $EOCD_magic = { 50 4B 05 06 }
    $DD_magic = { 50 4B 07 08 }
  condition:
    $LFH_magic or $CDFH_magic or $EOCD_magic or $DD_magic
}
rule IsDOCX {
  strings:
    //                         P  K             [  C  o  n  t  e  n  t  _  T  y  p  e  s  ]  .  x  m  l
    $lfh_and_content_type = { 50 4B 03 04 [26] 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C }

  condition:
    IsZIP and $lfh_and_content_type
}
rule IsJAR {
  strings:
    //                 P  K             M  E  T  A  -  I  N  F  /
    $lfh_and_meta = { 50 4B 03 04 [26] 4D 45 54 41 2D 49 4E 46 2F }
    // the file name must be 30 bytes after the beginning of the LFH (or the CFD)

  condition:
    IsZIP and $lfh_and_meta
}
rule IsAPK {
  strings:
  //                    P  K             A  n  d  r  o  i  d  M  a  n  i  f  e  s  t  .  x  m  l
  $lfh_and_android = { 50 4B 03 04 [26] 41 6E 64 72 6F 69 64 4D 61 6e 69 66 65 73 74 2E 78 6D 6C}
  
  condition:
    IsZIP and $lfh_and_android
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

    flag = PolyglotLevel()

    file_size = os.stat(filename).st_size
    last_eocd_magic = [s for s in zip_rule.strings if s[1] == '$EOCD_magic'][0]
    eocd_offset = last_eocd_magic[0]

    if 'HasZIPMagic' in matches:
        rules = matches['HasZIPMagic']
        sorted_strings = sorted(rules.strings, key=lambda string: string[0])
        first_string = sorted_strings[0]
        if first_string[0] != 0:
            flag.add_chunk(0, first_string[0])

    # TODO Take comment in account ? Mark as less suspicious ?
    eocd_min_end = eocd_offset + __EOCD_MIN_SIZE
    if eocd_min_end < file_size:
        flag.add_chunk(eocd_min_end, file_size - eocd_min_end)

    if 'IsDOCX' in matches:
        flag.embed('docx')

    if 'IsJAR' in matches:
        flag.embed('jar')

    if 'IsAPK' in matches:
        flag.embed('apk')

    return flag

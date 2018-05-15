import io
import yara

from polyglot_detector import PolyglotLevel

FILE_EXTENSION = 'tar'

# TODO: This rules may be too restrictive
RULES = """
// Inspired from the file software
rule IsTAR {
  strings:
    $padding = { 00 00 00 00 00 00 00 00 }
    $null_space_or_oct = /\\x00| |[0-7]/
    $null_or_space = { ( 00 | 20 ) }
    $space_or_0 = { ( 20 | 30 ) }
  condition:
    $padding at 500
      and uint16be(0) > 0x1F00 and uint16be(0) < 0xFCFD
      and uint16be(508)&0x8B9E8DFF == 0
      and $null_space_or_oct at 100
      and $null_space_or_oct at 101
      and $space_or_0 at 148
      and $null_or_space at 155
}
//rule is_ustar {
//  strings:
//    $ustar = "ustar"
//    $ending_posix_spaces = { 20 20 00 }
//    $ending_posix_00 = { 00 30 30 }
//    $ending_full_zero = { 00 00 00 }
//  condition:
//    IsTAR and $ustar at 257 and for any of ($ending_*): ( $ at 262 )
//}
"""

__BLOCK_SIZE = 512


def check(filename):
    rules = yara.compile(source=RULES)
    matches = rules.match(filename)
    return check_with_matches(filename, {m.rule: m for m in matches})


def check_with_matches(filename, matches):
    if 'IsTAR' not in matches:
        return None
    flag = PolyglotLevel.VALID

    with open(filename, 'rb') as file:
        while True:
            header = file.read(512)
            if len(header) != 512 or all(b == 0 for b in header):
                break
            filename_field = header[:100]
            null = filename_field.find(b'\x00')
            after_null = filename_field[null + 1:]
            if not all(b == 0 for b in after_null):
                flag |= PolyglotLevel.GARBAGE_IN_MIDDLE
            file_size = int(header[124:124+12].strip(b'\x00'), base=8)
            data_block_nb = 1
            while data_block_nb * __BLOCK_SIZE < file_size:
                data_block_nb += 1
            file.seek(data_block_nb * __BLOCK_SIZE, io.SEEK_CUR)

    return flag

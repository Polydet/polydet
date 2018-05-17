import io
import yara

from polyglot_detector import PolyglotLevel

FILE_EXTENSION = 'tar'

# TODO: This rules may be too restrictive
RULES = """
rule IsTAR {
  // Inspired from the file software, "archive" magic file
  condition:
    uint32(500) == 0 and uint32(504) == 0
      and uint16be(0) > 0x1F00 and uint16be(0) < 0xFCFD
      and uint16be(508)&0x8B9E8DFF == 0
      // File mode begins with 0, space or octal
      and (uint8(100) == 0 or uint8(100) == 0x20 or uint8(100) >= 0x30 and uint8(100) <= 0x37)
      and (uint8(101) == 0 or uint8(101) == 0x20 or uint8(101) >= 0x30 and uint8(101) <= 0x37)
      // 147 is \\x00 or ASCII '0'
      and (uint8(148) == 0 or uint8(148) == 0x30)
      // 155 is \\x00 or space
      and (uint8(155) == 0 or uint8(155) == 0x20)
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
            try:
                file_size = int(header[124:124+12].strip(b'\x00'), base=8)
            except ValueError:
                return None
            data_block_nb = 1
            while data_block_nb * __BLOCK_SIZE < file_size:
                data_block_nb += 1
            file.seek(data_block_nb * __BLOCK_SIZE, io.SEEK_CUR)

    return flag

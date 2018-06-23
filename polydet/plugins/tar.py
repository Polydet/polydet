import io
import yara

from polydet import PolyglotLevel

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
"""

__BLOCK_SIZE = 512


def check(filename):
    rules = yara.compile(source=RULES)
    matches = rules.match(filename)
    return check_with_matches(filename, {m.rule: m for m in matches})


def check_with_matches(filename, matches):
    if 'IsTAR' not in matches:
        return None
    level = PolyglotLevel()

    with open(filename, 'rb') as fd:
        offset = 0
        while True:
            # Read header
            header = fd.read(__BLOCK_SIZE)
            if len(header) != __BLOCK_SIZE or all(b == 0 for b in header):
                # End of file header
                break

            # Detect garbage in file name
            filename_field = header[:100]
            null = filename_field.find(b'\x00')
            after_null = filename_field[null + 1:]
            for i, b in enumerate(after_null):
                if b != 0:
                    level.add_chunk(offset + (100 - len(after_null) + i), len(after_null) - i)
                    break

            try:
                file_size = int(header[124:124+12].strip(b'\x00'), base=8)
            except ValueError:
                # TODO Return Invalid
                return None
            data_block_nb = 0
            while data_block_nb * __BLOCK_SIZE < file_size:
                data_block_nb += 1
            fd.seek(data_block_nb * __BLOCK_SIZE, io.SEEK_CUR)
            offset += __BLOCK_SIZE + data_block_nb * __BLOCK_SIZE

        # Test for non-null byte at the end
        block = fd.read(__BLOCK_SIZE)
        while len(block) != 0 and all(b == 0 for b in block):
            block = fd.read(__BLOCK_SIZE)
        offset = fd.tell() - len(block)

        fd.seek(0, io.SEEK_END)
        file_size = fd.tell()

        if len(block) != 0:
            level.add_chunk(offset, file_size - offset)

    return level

import io
import os
import yara

from polydet import PolyglotLevel
from polydet._parser import FileParser, LITTLE_ENDIAN

FILE_EXTENSION = 'exe'

RULES = """
rule IsMZ {
  condition:
    uint16(0) == 0x5A4D
}
rule IsPE {
  condition:
    IsMZ and uint32(uint32(0x3C)) == 0x00004550
}
"""

__PE_MAGIC_SIZE = 4
__COFF_HEADER_SIZE = 0x14
__OPTIONAL_HEADER_PE32_MAGIC = 0x10B
__OPTIONAL_HEADER_PE32_PLUS_MAGIC = 0x20B
__OPTIONAL_HEADER_SIZE_OF_IMAGE_OFFSET = 0x38


def check(filename):
    rules = yara.compile(source=RULES)
    matches = rules.match(filename)
    return check_with_matches(filename, {m.rule: m for m in matches})


# TODO: Detect other MZ format than PE?
# TODO: Detect big endian PE?
# FIXME: Know why some legitimate exe trigger the SizeOfImage rule
def check_with_matches(filename, matches):
    if 'IsPE' not in matches:
        return None

    try:
        level = PolyglotLevel()

        with open(filename, mode='rb') as fp:
            fp.seek(0x3C, io.SEEK_SET)
            parser = FileParser(fp, LITTLE_ENDIAN)
            nt_header_offset = parser.read_i32()

            fp.seek(nt_header_offset + __PE_MAGIC_SIZE + __COFF_HEADER_SIZE, io.SEEK_SET)
            optional_header_magic = parser.read_i16()

            if optional_header_magic == __OPTIONAL_HEADER_PE32_MAGIC \
                    or optional_header_magic == __OPTIONAL_HEADER_PE32_PLUS_MAGIC:
                file_size = os.stat(filename).st_size
                fp.seek(__OPTIONAL_HEADER_SIZE_OF_IMAGE_OFFSET - 2, io.SEEK_CUR)
                size_of_image = parser.read_i32()

                # Check that the size_of_image correspond to the size of the EXE
                if file_size > size_of_image:
                    level.add_chunk(size_of_image, file_size - size_of_image)

        return level
    except ValueError:
        return None

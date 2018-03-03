import struct
from .polyglot_level import PolyglotLevel


SECTION_HEADING_SIZE = 8
CRC_SIZE = 4
IEND = 'IEND'
SEEK_CUR = 1


def check(filename: str):
    magic = b'\x89PNG\r\n\x1a\n'

    with open(filename, 'rb') as file:
        if magic != file.read(len(magic)):
            return None
        try:
            name = ''
            while name != IEND:
                name, length = read_section(file)
                file.seek(length + CRC_SIZE, SEEK_CUR)
            file.seek(CRC_SIZE, SEEK_CUR)
            flag = PolyglotLevel.VALID
            if len(file.read(1)) != 0:
                flag |= PolyglotLevel.GARBAGE_AT_END
            return flag
        except SyntaxError:
            return None


def read_section(file) -> (str, int):
    section_heading = file.read(SECTION_HEADING_SIZE)
    if len(section_heading) != SECTION_HEADING_SIZE:
        raise SyntaxError('Truncated PNG file')
    name = section_heading[4:].decode('utf-8')
    length = struct.unpack('>I', section_heading[:4])[0]
    return name, length

import struct
import os
import yara
import zlib

from polydet import PolyglotLevel
from polydet._parser import FileParser, LITTLE_ENDIAN


FILE_EXTENSION = 'swf'

RULES = """
rule IsSWF {
  strings:
    $magic = /(F|C|Z)WS/
  condition:
    $magic at 0
}
"""


def check(filename):
    rules = yara.compile(source=RULES)
    matches = rules.match(filename)
    return check_with_matches(filename, {m.rule: m for m in matches})


def check_with_matches(filename, matches):
    if 'IsSWF' not in matches:
        return None

    try:
        with open(filename, 'rb') as fp:
            return SWFParser(fp, filename).scan()
    except SyntaxError:
        return None


class SWFParser(FileParser):
    def __init__(self, fp, filename):
        super().__init__(fp, LITTLE_ENDIAN)
        self.file_size = os.stat(filename).st_size

    def scan(self) -> PolyglotLevel:
        level = PolyglotLevel()
        magic = self.must_read(3)
        version = self.read_i8(1)
        uncompressed_size = self.read_i32()

        if magic == b'FWS':
            if self.file_size != uncompressed_size:
                level.add_chunk(uncompressed_size, self.file_size - uncompressed_size)
        elif magic == b'CWS':
            # FIXME Find a way to not read all the file into memory (e.g. by buffering)
            to_decompress = self.buf.read()
            decompressor = zlib.decompressobj()
            decompressor.decompress(to_decompress, uncompressed_size - 8)
            if decompressor.unused_data:
                level.add_chunk(self.file_size - len(decompressor.unused_data), len(decompressor.unused_data))
        elif magic == b'ZWS':
            # TODO Check if works correctly!!
            compressed_size = self.read_i32()
            lzma_size = compressed_size + 5 + 4
            if lzma_size + 8 != self.file_size:
                level.add_chunk(lzma_size + 8, self.file_size - (lzma_size + 8))


        return level

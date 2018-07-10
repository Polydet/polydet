import os
import yara

from polydet.polyglot_level import PolyglotLevel


FILE_EXTENSION = 'webm'

RULES = """
rule IsWEBM {
  strings:
    $magic = { 1A 45 DF A3 }
  condition:
    $magic at 0
}
"""


def check(filename: str):
    rules = yara.compile(source=RULES)
    matches = rules.match(filename)
    return check_with_matches(filename, {m.rule: m for m in matches})


def check_with_matches(filename, matches):
    if 'IsWEBM' not in matches:
        return None
    level = PolyglotLevel()
    reader = WebmReader(filename)
    reader.read_ebml_header()
    reader.read_segment_id()
    segment_size = reader.read_size()
    webm_size = segment_size + reader.file.tell()
    reader.close()
    file_size = os.stat(filename).st_size
    if file_size > webm_size:
        level.add_chunk(webm_size, file_size - webm_size)
    return level


class WebmReader:
    def __init__(self, filename):
        self.file = open(filename, mode='rb')

    def read_ebml_header(self):
        self.file.read(4)
        headerSize = self.read_size()
        self.file.read(headerSize)

    def read_segment_id(self):
        self.file.read(4)

    def read_size(self):
        first_byte = self.file.read(1)
        numberRep = int.from_bytes(first_byte, byteorder='big')
        first_one_idx = 0
        while numberRep >> (7 - first_one_idx) == 0:
            first_one_idx += 1
        remaining_bytes = self.file.read(first_one_idx)
        size_as_bytes = first_byte + remaining_bytes
        size = int.from_bytes(size_as_bytes, byteorder='big') & (pow(2, (7 * (first_one_idx + 1))) - 1)
        return size

    def close(self):
        self.file.close()

import math
import mmap
import os
import yara

from polydet.polyglot_level import PolyglotLevel

FILE_EXTENSION = 'mp3'

RULES = """
rule MP3Header {
  strings:
    $magic = { FF FB ?? }
  condition:
    $magic
}

rule HasID3 {
  strings:
    //        I  D  3
    $id3 = { 49 44 33 [6] ?? }
  condition:
    $id3 at 0
}
"""

_MAGIC = b'\xFF\xFB'


def check(filename):
    rules = yara.compile(source=RULES)
    matches = rules.match(filename)
    return check_with_matches(filename, {m.rule: m for m in matches})


def check_with_matches(filename: str, matches):
    if 'MP3Header' not in matches:
        return None
    strings = list(filter(__is_good, matches['MP3Header'].strings))
    if not strings:
        return None
    # Heuristic to reduce the number of false positives:
    # each frame is 28ms long, so we search for at least 50 frames
    if len(strings) < 50:
        return None
    begin = 0
    if 'HasID3' in matches:
        size = __synchsafe(bytes(matches['HasID3'].strings[0][2][6:]))
        begin = 10 + size
    level = PolyglotLevel()
    first_mp3_header_offset = matches['MP3Header'].strings[0][0]
    if first_mp3_header_offset > begin:
        level.add_chunk(0, first_mp3_header_offset)
    idx = 0
    while idx < len(strings):
        string = strings[idx]
        third_byte = string[2][2]
        bitrate = __bitrate_conversion[(int(third_byte) & 0xF0) >> 4] * 1000
        sampling_frequency = __sampling_conversion[(int(third_byte) & 0x0C) >> 2]
        padding = (int(third_byte) & 0x02) >> 1
        unit_size = math.floor(144 * bitrate / sampling_frequency) + padding  # Source for computation : https://www.researchgate.net/publication/225793510_A_study_on_multimedia_file_carving_method, page 8
        next_headers = [s for s in strings if s[0] >= string[0] + unit_size]
        if not next_headers:
            file_size = os.stat(filename).st_size
            if file_size != string[0] + unit_size:
                level.add_chunk(string[0] + unit_size, file_size - (string[0] + unit_size))
            break
        if next_headers[0][0] != string[0] + unit_size:
            level.add_chunk(string[0] + unit_size, next_headers[0][0] - (string[0] + unit_size))
        idx = strings.index(next_headers[0])
    return level


def __is_good(string):
    third_byte = string[2][2]
    if (int(third_byte) & 0xF0) >> 4 == 0xF:
        return False
    if (int(third_byte) & 0xF0) >> 4 == 0x0:
        return False
    if (int(third_byte) & 0x0C) >> 2 == 0x3:
        return False
    return True


# synchsafe is a number encoding method in ID3V2 which removes the highest bit.
def __synchsafe(input: bytes):
    ret = 0
    for byte in input:
        ret *= 128
        ret += int(byte) & 127
    return ret


# Source : https://www.researchgate.net/publication/225793510_A_study_on_multimedia_file_carving_method, page 8
__bitrate_conversion = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320]

# Source : https://www.researchgate.net/publication/225793510_A_study_on_multimedia_file_carving_method, page 8
__sampling_conversion = [44100, 48000, 32000]

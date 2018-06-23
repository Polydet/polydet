import io
import mmap
import struct
import yara

from polydet.polyglot_level import PolyglotLevel
from polydet.utils import must_read


FILE_EXTENSION = 'jpg'

RULES = """
rule IsJPG {
  strings:
    $magic = { FF D8 }
    
  condition:
    $magic at 0
}
rule HasEndMarker {
  strings:
    $end_marker = { FF D9 }
    
  condition:
    IsJPG and $end_marker
}
"""

__JPG_MAGIC = b'\xFF\xD8'
__JPG_START_OF_SCAN = b'\xFF\xDA'
__JPG_END_MARKER = b'\xFF\xD9'


def check(filename: str):
    rules = yara.compile(source=RULES)
    matches = rules.match(filename)
    return check_with_matches(filename, {m.rule: m for m in matches})


def check_with_matches(filename, matches):
    if 'IsJPG' not in matches:
        return None

    with open(filename, 'rb') as file:
        try:
            with mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as buf:
                level = PolyglotLevel()

                buf.seek(len(__JPG_MAGIC))
                try:
                    section = b''
                    while section != __JPG_START_OF_SCAN:
                        section, length = read_section(buf)
                        buf.seek(length - 2, io.SEEK_CUR)
                except (ValueError, SyntaxError):
                    return level.invalid()

                scan_offset = buf.tell()

                # Read the image data until end marker
                end_marker_matches = matches['HasEndMarker'].strings if 'HasEndMarker' in matches else None
                end_marker_matches_after_start_of_scan = [m for m in end_marker_matches if m[0] > scan_offset]
                end_marker_offset = end_marker_matches_after_start_of_scan[0][0] if end_marker_matches_after_start_of_scan else None
                if end_marker_offset is not None and end_marker_offset + len(__JPG_END_MARKER) < buf.size():
                    end_offset = end_marker_offset + len(__JPG_END_MARKER)
                    level.add_chunk(end_offset, buf.size() - end_offset)
                return level

        except ValueError:
            return None


def read_section(file) -> (int, int):
    section = must_read(file, 2)
    length = struct.unpack('>H', must_read(file, 2))[0]
    return section, length

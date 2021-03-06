import io
import mmap
import yara

from polydet.polyglot_level import PolyglotLevel
from polydet._parser import FileParser, LITTLE_ENDIAN, BIG_ENDIAN

FILE_EXTENSION = 'tiff'

RULES = """
rule IsTIFF {
  strings:
    $ii_magic = { 49 49 2A 00 }
    $mm_magic = { 4D 4D 00 2A }
    
  condition:
    $ii_magic at 0 or $mm_magic at 0
}
"""


def check(filename: str):
    rules = yara.compile(source=RULES)
    matches = rules.match(filename)
    return check_with_matches(filename, {m.rule: m for m in matches})


def check_with_matches(filename, matches):
    """
    Check if the file is a TIFF file, and if it is, if there is potentially other formats in the file
    WARNING: The method used to know if there is unusued garbage at the end of the file is not perfect !
    It only check if the last used zone is at the end of the file, but it would be very easy for an attacker to
    craft a TIFF with a tag which has an offset at the end of the file
    :param filename: Path to the file
    :return: A PolyglotLevel or None if the file is not a TIFF
    """

    if 'IsTIFF' not in matches:
        return None

    try:
        with _TIFFFile(filename) as image:
            level = PolyglotLevel()
            for chunk in image.buf.get_not_read_zones():
                # FIXME Add other unreaded zone when parser will read image data
                # For now we only add the last zone if it is at the end of the file
                if chunk[0] + chunk[1] == image.buf.size():
                    level.suspicious_chunks.append(chunk)
            return level
    except SyntaxError:
        return None


class _TIFFFile:

    __TIFF_II_MAGIC = b'II\x2A\x00'
    __TIFF_MM_MAGIC = b'MM\x00\x2A'

    def __init__(self, filename):
        self.filename = filename
        self.buf = None  # type: _MemoryMarker

    def open(self):
        with open(self.filename, 'rb') as fp:
            try:
                self.buf = _MemoryMarker(mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ))
            except ValueError:
                raise SyntaxError('Empty file')
        self.__parse()

    def close(self):
        self.buf.close()

    def __parse(self):
        magic = self.buf.read(len(_TIFFFile.__TIFF_II_MAGIC))
        if magic == _TIFFFile.__TIFF_II_MAGIC:
            parser = _TIFFFileParser(self.buf, LITTLE_ENDIAN)
        elif magic == _TIFFFile.__TIFF_MM_MAGIC:
            parser = _TIFFFileParser(self.buf, BIG_ENDIAN)
        else:
            raise SyntaxError("Not a TIFF File")
        parser.parse()

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class _TIFFFileParser(FileParser):

    __TAG_TYPES_SIZE = {
        1: 1,  # Byte
        2: 1,  # Ascii
        3: 2,  # Short
        4: 4,  # Long
        5: 8,  # Rational
        6: 1,  # SByte
        7: 1,  # Undefined
        8: 2,  # SShort
        9: 4,  # SLong
        10: 8,  # SRational
        11: 4,  # Float
        12: 8,  # Double
    }

    def parse(self):
        self.buf.seek(4, io.SEEK_SET)
        ifd_offset = self.read_i32()
        while ifd_offset != 0:
            ifd_offset = self.__parse_ifd(ifd_offset)

    def __parse_ifd(self, offset):
        self.buf.seek(offset, io.SEEK_SET)
        entry_count = self.read_i16()
        for i in range(entry_count):
            tag_type = self.read_i16()
            value_type = self.read_i16()
            value_count = self.read_i32()
            value = self.read_i32()
            if value_type not in _TIFFFileParser.__TAG_TYPES_SIZE:
                print("TIFF: Unkown Tag value type %d" % value_type)  # TODO Remove
                continue
            total_length = _TIFFFileParser.__TAG_TYPES_SIZE[value_type] * value_count
            if total_length > 4:
                save = self.buf.tell()
                self.buf.seek(value)
                value = self.buf.read(total_length)
                self.buf.seek(save)
        return self.read_i32()


class _MemoryMarker:
    """Keep a track of the read zone of a buffer"""
    def __init__(self, buf):
        self.__buf = buf  # type: mmap.mmap
        self.__offset = self.__buf.tell()
        self.map = {}  # Map of offset and the length read at this offset

    def mark(self, offset, size):
        # Search previous read zone that contains offset
        previous_zones = [item for item in self.map.items() if item[0] <= offset <= item[0] + item[1]]
        if len(previous_zones):
            previous_offset = previous_zones[0][0]
            previous_size = previous_zones[0][1]
            overlap = offset + size - (previous_offset + previous_size)
            if overlap <= 0:
                return
            self.map[previous_offset] += overlap
        else:
            self.map[offset] = size

    def clean(self):
        """Try to reduce the number of entries in map"""
        items = sorted(self.map.items(), key=lambda item: item[0])
        for (offset, size) in items:
            previous_zones = [item for item in self.map.items() if item[0] < offset <= item[0] + item[1]]
            if len(previous_zones):
                previous_offset = previous_zones[0][0]
                previous_size = previous_zones[0][1]
                overlap = offset + size - (previous_offset + previous_size)
                if overlap <= 0:
                    return
                self.map[previous_offset] += overlap
                del self.map[offset]

    def get_read_zones(self):
        return sorted(self.map.items(), key=lambda item: item[0])

    def get_not_read_zones(self):
        self.clean()
        results = {}
        items = sorted([i for i in self.map.items()], key=lambda item: item[0])
        for i in range(len(items)):
            is_last = i + 1 == len(items)
            offset, size = items[i]
            if not is_last:
                next_offset, _ = items[i + 1]
                zone_size = next_offset - (offset + size)
            else:
                zone_size = self.size() - (offset + size)
            if zone_size != 0:
                results[offset + size] = zone_size
        return sorted(results.items(), key=lambda s: s[0])

    def read(self, size):
        res = self.__buf.read(size)
        read_size = len(res)
        self.mark(self.__offset, read_size)
        self.__offset += read_size
        return res

    def seek(self, offset, whence=io.SEEK_SET):
        self.__buf.seek(offset, whence)
        self.__offset = self.__buf.tell()

    def tell(self):
        return self.__buf.tell()

    def size(self):
        return self.__buf.size()

    def close(self):
        self.__buf.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.__buf.close()

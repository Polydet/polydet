import io
import mmap
import yara
from polydet.polyglot_level import PolyglotLevel
from polydet._binary import *
from polydet._parser import FileParser, LITTLE_ENDIAN


FILE_EXTENSION = 'rar'

RULES = """
rule IsRAR {
  strings:
    $rar3_magic = { 52 61 72 21 1A 07 00 }
    $rar5_magic = { 52 61 72 21 1A 07 01 00 }
  condition:
    $rar3_magic or $rar5_magic
}
"""

_RAR3_MAGIC = b'Rar!\x1A\x07\x00'
_RAR5_MAGIC = b'Rar!\x1A\x07\x01\x00'


def check(filename: str):
    rules = yara.compile(source=RULES)
    matches = rules.match(filename)
    return check_with_matches(filename, {m.rule: m for m in matches})


def check_with_matches(filename, matches):
    if 'IsRAR' not in matches:
        return None
    try:
        with _RARFile(filename) as rar_file:
            level = PolyglotLevel(is_valid=rar_file.is_valid)
            if rar_file.magic_offset != 0:
                level.add_chunk(0, rar_file.magic_offset)
            if rar_file.buf.tell() != rar_file.buf.size():
                level.add_chunk(rar_file.buf.tell(), rar_file.buf.size() - rar_file.buf.tell())
            return level
    except SyntaxError:
        return None


class _RARFile:

    def __init__(self, filename):
        self.filename = filename
        self.magic_offset = None
        self.buf = None  # type: mmap.mmap
        self.is_valid = None

    def open(self):
        with open(self.filename, 'rb') as fp:
            try:
                self.buf = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
            except ValueError:
                raise SyntaxError("Empty file")
            self._parse()

    def close(self):
        self.buf.close()

    def _parse(self):
        rar3_magic_offset = self.buf.find(_RAR3_MAGIC)
        rar5_magic_offset = self.buf.find(_RAR5_MAGIC)
        if rar3_magic_offset != -1 and (rar5_magic_offset == -1 or rar3_magic_offset < rar5_magic_offset):
            self.magic_offset = rar3_magic_offset
            self._parse_rar3()
        elif rar5_magic_offset != -1 and (rar3_magic_offset == -1 or rar5_magic_offset < rar3_magic_offset):
            self.magic_offset = rar5_magic_offset
            self._parse_rar5()
        else:
            raise SyntaxError("Not a RAR3 file")

    def _parse_rar3(self):
        self.buf.seek(self.magic_offset, io.SEEK_SET)
        parser = _RAR3FileParser(self.buf)
        parser.parse()
        self.is_valid = parser.is_valid

    def _parse_rar5(self):
        self.buf.seek(self.magic_offset, io.SEEK_SET)
        parser = _RAR5FileParser(self.buf)
        parser.parse()
        self.is_valid = parser.is_valid

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class _RAR3FileParser(FileParser):

    _HEAD_FILE = 0x74
    _HEAD_ENDARC = 0x7b

    def __init__(self, buf):
        super().__init__(buf, LITTLE_ENDIAN)
        self.is_valid = True

    def parse(self):
        try:
            while self._parse_block():
                pass
        except ValueError:
            self.is_valid = False

    def _parser_marker(self):
        self.buf.seek(len(_RAR3_MAGIC), io.SEEK_CUR)

    def _parse_block(self):
        offset = self.buf.tell()
        try:  # RAR files may terminate without ENDARC block
            crc = self.read_i16()
        except SyntaxError:
            return False
        type = self.read_i8()
        flags = self.read_i16()
        size = self.read_i16()
        add_size = 0
        if flags & 0x8000 != 0:
            add_size = self.read_i32()

        if type == _RAR3FileParser._HEAD_FILE:
            unp_size = self.read_i32()
            host = self.read_i32()
            file_crc = self.read_i32()
            ftime = self.read_i32()
            unp_version = self.read_i32()
            unp_method = self.read_i32()
            name_size = self.read_i32()
            file_attr = self.read_i32()
            if flags & 0x100 != 0:
                high_pack_size = self.read_i32()
                add_size += high_pack_size
            self.buf.seek(offset + size, io.SEEK_SET)  # Go to the end of the header, at the beginning of the file
            try:  # Some tool may try to extract the file even if it is truncated
                self.buf.seek(add_size, io.SEEK_CUR)
            except ValueError:
                self.buf.seek(0, io.SEEK_END)
                raise
        else:
            self.buf.seek(offset + size + add_size, io.SEEK_SET)

        if size + add_size == 0:
            raise ValueError("Invalid null block size")

        if type == _RAR3FileParser._HEAD_ENDARC:
            return False

        return True


class _RAR5FileParser(FileParser):

    _HEAD_ENDARC = 5

    def __init__(self, buf):
        super().__init__(buf, LITTLE_ENDIAN)
        self.is_valid = True

    def parse(self):
        # Skip marker
        self.buf.seek(len(_RAR5_MAGIC), io.SEEK_CUR)
        try:
            while self._parse_block():
                pass
        except ValueError:
            self.is_valid = False

    def _parse_block(self):
        try:
            crc = self.read_i32()
        except SyntaxError:
            return False
        size = self._read_vint()
        offset = self.buf.tell()
        type = self._read_vint()
        flag = self._read_vint()
        data_size = 0
        if flag & 0x1 != 0:
            extra_size = self._read_vint()
        if flag & 0x2 != 0:
            data_size = self._read_vint()
        self.buf.seek(offset + size, io.SEEK_SET)

        if data_size != 0:
            try:
                self.buf.seek(data_size, io.SEEK_CUR)
            except ValueError:
                self.buf.seek(0, io.SEEK_END)
                self.is_valid = False
                return False

        if size + data_size == 0:
            raise ValueError("Invalid null block size")

        if type == _RAR5FileParser._HEAD_ENDARC:
            return False

        return True

    def _read_vint(self):
        byte = 0x80
        total = 0
        c = 0
        while byte & 0x80 != 0:
            byte = i8(self.must_read(1))
            total += (byte & ~0x80) << (c * 7)
            c += 1
        return total

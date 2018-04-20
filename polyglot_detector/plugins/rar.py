import io
import mmap
from polyglot_detector.polyglot_level import PolyglotLevel
from polyglot_detector._binary import *


FILE_EXTENSION = 'rar'

_RAR3_MAGIC = b'Rar!\x1A\x07\x00'


def check(filename: str):
    try:
        with _RARFile(filename) as rar_file:
            flag = PolyglotLevel(0)
            if rar_file.magic_offset != 0:
                flag |= PolyglotLevel.GARBAGE_AT_BEGINNING
            if rar_file.buf.tell() != rar_file.buf.size():
                flag |= PolyglotLevel.GARBAGE_AT_END
            if rar_file.is_valid:
                flag |= PolyglotLevel.VALID
            else:
                flag |= PolyglotLevel.INVALID
            return flag
    except SyntaxError:
        return None


class _RARFile:

    def __init__(self, filename):
        self.filename = filename
        self.magic_offset = None
        self.buf = None  # type: mmap.mmap

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
        self.magic_offset = self.buf.find(_RAR3_MAGIC)
        if self.magic_offset == -1:
            raise SyntaxError("Not a RAR3 file")
        self.buf.seek(self.magic_offset, io.SEEK_SET)
        parser = _RAR3FileParser(self.buf)
        parser.parse()
        self.is_valid = parser.is_valid

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class _RAR3FileParser:

    _HEAD_FILE = 0x74
    _HEAD_ENDARC = 0x7b

    def __init__(self, buf):
        self._buf = buf # type: mmap.mmap
        self.is_valid = True

    def parse(self):
        while self._parse_block():
            pass

    def _parser_marker(self):
        self._buf.seek(len(_RAR3_MAGIC), io.SEEK_CUR)

    def _parse_block(self):
        offset = self._buf.tell()
        try:  # RAR files may terminate without ENDARC block
            crc = i16le(self._must_read(2))
        except SyntaxError:
            return False
        type = i8(self._must_read(1))
        flags = i16le(self._must_read(2))
        size = i16le(self._must_read(2))
        add_size = 0
        if flags & 0x8000 != 0:
            add_size = i32le(self._must_read(4))

        if type == _RAR3FileParser._HEAD_FILE:
            unp_size = i32le(self._must_read(4))
            host = i8(self._must_read(1))
            file_crc = i32le(self._must_read(4))
            ftime = i32le(self._must_read(4))
            unp_version = i8(self._must_read(1))
            unp_method = i8(self._must_read(1))
            name_size = i16le(self._must_read(2))
            file_attr = i32le(self._must_read(4))
            if flags & 0x100 != 0:
                high_pack_size = i32le(self._must_read(4))
                add_size += high_pack_size
            self._buf.seek(offset + size, io.SEEK_SET)  # Go to the end of the header, at the beginning of the file
            try:  # Some tool may try to extract the file even if it is truncated
                self._buf.seek(add_size, io.SEEK_CUR)
            except ValueError:
                self._buf.seek(0, io.SEEK_END)
                self.is_valid = False
                return False
        else:
            self._buf.seek(offset + size + add_size, io.SEEK_SET)

        if type == _RAR3FileParser._HEAD_ENDARC:
            return False

        return True

    def _must_read(self, size):
        read = self._buf.read(size)
        if len(read) != size:
            raise SyntaxError("Unexpected EOF")
        return read

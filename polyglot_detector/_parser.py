import mmap
from struct import unpack

BIG_ENDIAN = '>'
LITTLE_ENDIAN = '<'

if bytes is str:
    def i8(c):
        return ord(c)
else:
    def i8(c):
        return c if c.__class__ is int else c[0]


class FileParser:
    def __init__(self, buf, endian):
        self.buf = buf        # type: mmap.mmap
        self.endian = endian

    def read_i8(self, must_read=True):
        read = self.must_read(1) if must_read else self.buf.read(1)
        return i8(read)

    def read_i16(self, must_read=True):
        read = self.must_read(2) if must_read else self.buf.read(2)
        return unpack(self.endian + 'H', read)[0]

    def read_i32(self, must_read=True):
        read = self.must_read(4) if must_read else self.buf.read(4)
        return unpack(self.endian + 'I', read)[0]

    def must_read(self, size):
        res = self.buf.read(size)
        if len(res) != size:
            raise SyntaxError("Unexpected EOF")
        return res

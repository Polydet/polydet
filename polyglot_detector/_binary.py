# From Python Imaging Library

from struct import unpack

if bytes is str:
    def i8(c):
        return ord(c)
else:
    def i8(c):
        return c if c.__class__ is int else c[0]


# Input, le = little endian, be = big endian
def i16le(c, o=0):
    """
    Converts a 2-bytes (16 bits) string to an unsigned integer.

    c: string containing bytes to convert
    o: offset of bytes to convert in string
    """
    return unpack("<H", c[o:o+2])[0]


def si16le(c, o=0):
    """
    Converts a 2-bytes (16 bits) string to a signed integer.

    c: string containing bytes to convert
    o: offset of bytes to convert in string
    """
    return unpack("<h", c[o:o+2])[0]


def i32le(c, o=0):
    """
    Converts a 4-bytes (32 bits) string to an unsigned integer.

    c: string containing bytes to convert
    o: offset of bytes to convert in string
    """
    return unpack("<I", c[o:o+4])[0]


def si32le(c, o=0):
    """
    Converts a 4-bytes (32 bits) string to a signed integer.

    c: string containing bytes to convert
    o: offset of bytes to convert in string
    """
    return unpack("<i", c[o:o+4])[0]


def i16be(c, o=0):
    return unpack(">H", c[o:o+2])[0]


def i32be(c, o=0):
    return unpack(">I", c[o:o+4])[0]

from enum import Flag, auto


class PolyglotLevel(Flag):
    VALID = auto()
    """Is a valid file of the scanned type"""

    HIDDEN = auto()
    """Is a hidden file of the scanned type"""

    GARBAGE_AT_BEGINNING = auto()
    """The file has suspicious data at its beginning"""

    GARBAGE_AT_END = auto()
    """The file has suspicious data at its end"""

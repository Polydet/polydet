class PolyglotLevel:
    _VALID_VALUE = 0x1
    """Is a valid file of the scanned type"""

    _GARBAGE_AT_BEGINNING_VALUE = 0x2
    """The file has suspicious data at its beginning"""

    _GARBAGE_AT_END_VALUE = 0x4
    """The file has suspicious data at its end"""

    _EMBED_VALUE = 0x8
    """The file also carry an other valid format (e.g. DOCX and JAR embeded in ZIP)"""

    _INVALID_VALUE = 0x10

    def __init__(self, value, embed=None):
        self._value_ = value
        self.embedded = embed if embed is not None else set()

    def with_embedded(self, type):
        c = self | PolyglotLevel.EMBED
        c.embedded.add(type)
        return c

    def __str__(self) -> str:
        ret = []
        if self._value_ & PolyglotLevel._VALID_VALUE:
            ret.append('VALID')
        if self._value_ & PolyglotLevel._GARBAGE_AT_BEGINNING_VALUE:
            ret.append('GARBAGE_AT_BEGINNING')
        if self._value_ & PolyglotLevel._GARBAGE_AT_END_VALUE:
            ret.append('GARBAGE_AT_END')
        if self._value_ & PolyglotLevel._EMBED_VALUE:
            ret.append('EMBED(%s)' % ','.join(sorted(self.embedded)))
        if self._value_ & PolyglotLevel._INVALID_VALUE:
            ret.append('INVALID')
        return self.__class__.__name__ + '.' + '|'.join(ret)

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self._value_ == other._value_ and self.embedded == other.embedded

    def __repr__(self):
        return '<%s: %d [%s]>' % (str(self), self._value_, ','.join(self.embedded))

    def __contains__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return other._value_ & self._value_ == other._value_

    def __bool__(self):
        return bool(self._value_)

    def __or__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.__class__(self._value_ | other._value_, self.embedded | other.embedded)

    def __and__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.__class__(self._value_ & other._value_, self.embedded & other.embedded)

    def __xor__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.__class__(self._value_ ^ other._value_, self.embedded ^ other.embedded)


PolyglotLevel.VALID = PolyglotLevel(PolyglotLevel._VALID_VALUE)
PolyglotLevel.GARBAGE_AT_BEGINNING = PolyglotLevel(PolyglotLevel._GARBAGE_AT_BEGINNING_VALUE)
PolyglotLevel.GARBAGE_AT_END = PolyglotLevel(PolyglotLevel._GARBAGE_AT_END_VALUE)
PolyglotLevel.EMBED = PolyglotLevel(PolyglotLevel._EMBED_VALUE)
PolyglotLevel.INVALID = PolyglotLevel(PolyglotLevel._INVALID_VALUE)

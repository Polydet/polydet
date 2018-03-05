class PolyglotLevel:
    _VALID_VALUE = 1
    """Is a valid file of the scanned type"""

    _GARBAGE_AT_BEGINNING_VALUE = 2
    """The file has suspicious data at its beginning"""

    _GARBAGE_AT_END_VALUE = 4
    """The file has suspicious data at its end"""

    def __init__(self, value):
        self._value_ = value

    def __str__(self) -> str:
        ret = []
        if self._value_ & PolyglotLevel._VALID_VALUE:
            ret.append('VALID')
        if self._value_ & PolyglotLevel._GARBAGE_AT_BEGINNING_VALUE:
            ret.append('GARBAGE_AT_BEGINNING')
        if self._value_ & PolyglotLevel._GARBAGE_AT_END_VALUE:
            ret.append('GARBAGE_AT_END')
        return self.__class__.__name__ + '.' + '|'.join(ret)

    def __eq__(self, other):
        return self._value_ == other._value_

    def __repr__(self):
        return '<%s: %d>' % (str(self), self._value_)

    def __contains__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return other._value_ & self._value_ == other._value_

    def __bool__(self):
        return bool(self._value_)

    def __or__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.__class__(self._value_ | other._value_)

    def __and__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.__class__(self._value_ & other._value_)

    def __xor__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.__class__(self._value_ ^ other._value_)


PolyglotLevel.VALID = PolyglotLevel(PolyglotLevel._VALID_VALUE)
PolyglotLevel.GARBAGE_AT_BEGINNING = PolyglotLevel(PolyglotLevel._GARBAGE_AT_BEGINNING_VALUE)
PolyglotLevel.GARBAGE_AT_END = PolyglotLevel(PolyglotLevel._GARBAGE_AT_END_VALUE)

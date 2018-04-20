import mmap
from polyglot_detector.polyglot_level import PolyglotLevel

_MAGIC = b'\xFF\xFB'

# synchsafe is a method of encoding numbers in ID3V2 which discards the highest bit.
def synchsafe(input: bytes):
    ret = 0
    for byte in input:
        ret *= 128
        ret += int(byte) & 127
    return ret

def check(filename: str):
    with open(filename, 'rb') as file:
        begin = 0
        if file.read(len("ID3")) == b'ID3':
            file.seek(6)
            size = synchsafe(file.read(4))
            begin = 10 + size
        try:
            with mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as s:
                magic = s.find(_MAGIC)
                if magic == -1:
                    return None
                elif magic == begin:
                    return PolyglotLevel.VALID
                else:
                    return PolyglotLevel.VALID | PolyglotLevel.GARBAGE_AT_BEGINNING
        except ValueError:  # mmap raise ValueError if empty file
            return None

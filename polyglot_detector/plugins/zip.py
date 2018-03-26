import mmap
from polyglot_detector.polyglot_level import PolyglotLevel

FILE_EXTENSION = 'zip'

_ZIP_EOCD_MAGIC = b'PK\x05\x06'
_ZIP_LFH_MAGIC = b'PK\x03\x04'
EOCD_MIN_SIZE = 22


# TODO Return GARBAGE_AT_END only if garbage after comment ?
def check(filename):
    with open(filename, 'rb') as file:
        try:
            with mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as s:
                size = s.size()
                magic_index = s.rfind(_ZIP_EOCD_MAGIC, 0, max(0, size - EOCD_MIN_SIZE + len(_ZIP_EOCD_MAGIC)))
                if magic_index == -1:
                    return None
                else:
                    size_of_eocd = size - magic_index
                    flag = PolyglotLevel.VALID
                    if s.find(_ZIP_LFH_MAGIC) != 0:
                        flag |= PolyglotLevel.GARBAGE_AT_BEGINNING
                    if size_of_eocd != EOCD_MIN_SIZE:
                        flag |= PolyglotLevel.GARBAGE_AT_END
                    additional_types = []
                    if s.find(b'[Content_Types].xml') != -1:
                        additional_types.append('docx')
                    if s.find(b'META-INF') != -1:
                        additional_types.append('jar')
                    result = {'result': flag}
                    if additional_types:
                        result['additional_types'] = additional_types
                    return result
        except ValueError:  # mmap raise ValueError if empty file
            return None

import mmap
from polyglot_detector.polyglot_level import PolyglotLevel

FILE_EXTENSION = 'html'

def is_whitespace(contents: bytes):
    for elem in contents:
        if elem != ord(' ') and elem != ord('\t') and elem != ord('\n'):
            return False
    return True

def check(filename: str):
    with open(filename, 'rb') as file:
        try:
            with mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as s:
                doc_start = -1
                doc_end = -1
                doctype_pos = s.find(b'<!DOCTYPE html>')
                if doctype_pos != -1:
                    doc_start = doctype_pos
                    doc_end = doc_start + len('<!DOCTYPE html>')
                tags = ['html', 'body', 'script']
                for tag in tags:
                    tag_pos = s.find(bytes('<' + tag + '>', 'utf8'))
                    if tag_pos != -1:
                        if doc_start == -1:
                            doc_start = tag_pos
                        end_tag_pos = s.find(bytes('</' + tag + '>', 'utf8'))
                        if end_tag_pos != -1:
                            doc_end = end_tag_pos + len(tag) + 3
                        elif doc_end == -1:
                            doc_end = tag_pos + len(tag) + 2
                        break
                if doc_start != -1:
                    flag = PolyglotLevel.VALID
                    if doc_start != 0:
                        flag |= PolyglotLevel.GARBAGE_AT_BEGINNING
                    s.seek(doc_end)
                    contents = s.read()
                    if not is_whitespace(contents):
                        flag |= PolyglotLevel.GARBAGE_AT_END
                    return flag
                else:
                    return None
        except ValueError:  # mmap raise ValueError if empty file
            return None

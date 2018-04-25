import mmap
import yara

from polyglot_detector.polyglot_level import PolyglotLevel

FILE_EXTENSION = 'html'

RULES = """
rule IsHTML {
  strings:
    $doctype = /<!DOCTYPE html>/
    $opening_tag = /<(html|body|script)/

  condition:
    $doctype or $opening_tag
}
"""

__DOCTYPE = b'<!DOCTYPE html>'


def check(filename):
    rules = yara.compile(source=RULES)
    matches = rules.match(filename)
    return check_with_matches(filename, {m.rule: m for m in matches})


# TODO Check lowercase doctypes
# TODO Check unclosed tags as '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"' or '<html onload="">'.
#    Can be done with ungreedy matching in yara
# TODO Improve to use results of yara matching
def check_with_matches(filename: str, matches):
    if 'IsHTML' not in matches:
        return None

    with open(filename, 'rb') as file, \
            mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as buf:
            doc_start = -1
            doc_end = -1
            doctype_pos = buf.find(__DOCTYPE)
            if doctype_pos != -1:
                doc_start = doctype_pos
                doc_end = doc_start + len(__DOCTYPE)
            tags = [b'html', b'body', b'script']
            for tag in tags:
                tag_pos = buf.find(b'<' + tag + b'>')
                if tag_pos != -1:
                    if doc_start == -1:
                        doc_start = tag_pos
                    end_tag_pos = buf.find(b'</' + tag + b'>')
                    if end_tag_pos != -1:
                        doc_end = end_tag_pos + len(tag) + 3
                    elif doc_end == -1:
                        doc_end = tag_pos + len(tag) + 2
                    break
            if doc_start != -1:
                flag = PolyglotLevel.VALID
                if doc_start != 0:
                    flag |= PolyglotLevel.GARBAGE_AT_BEGINNING
                buf.seek(doc_end)
                contents = buf.read()
                if not __is_whitespace(contents):
                    flag |= PolyglotLevel.GARBAGE_AT_END
                return flag
            else:
                return None


def __is_whitespace(contents: bytes):
    for elem in contents:
        if elem != ord(' ') and elem != ord('\t') and elem != ord('\n'):
            return False
    return True

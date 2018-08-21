import mmap
import io
import yara

from polydet.polyglot_level import PolyglotLevel

FILE_EXTENSION = 'html'

RULES = """
rule IsHTML {
  strings:
    $doctype = /<!DOCTYPE html/ nocase
    $opening_tag = /<(html|body|script)/ nocase

  condition:
    $doctype or $opening_tag
}
"""

__DOCTYPE = b'<!DOCTYPE html>'


def check(filename):
    rules = yara.compile(source=RULES)
    matches = rules.match(filename)
    return check_with_matches(filename, {m.rule: m for m in matches})


# TODO Support uppercase and random case doctype and tags
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
                level = PolyglotLevel()

                buf.seek(0, io.SEEK_SET)
                begin_content = buf.read(doc_start)  # Read until doc start
                if not __is_whitespace(begin_content):
                    level.add_chunk(0, doc_start)

                buf.seek(doc_end)
                contents = buf.read()
                if not __is_whitespace(contents):
                    level.add_chunk(doc_end, len(contents))
                return level
            else:
                return None


def __is_whitespace(contents: bytes):
    whitespaces = b' \t\r\n'
    return all(b in whitespaces for b in contents)

import magic
import mimetypes

__MAGIC = None
""":type __MAGIC: magic.Magic"""

__OCTET_STREAM_MIME = 'application/octet-stream'


def __get_instance() -> magic.Magic:
    global __MAGIC
    if __MAGIC is None:
        __MAGIC = magic.open(magic.MAGIC_MIME_TYPE | magic.MAGIC_CONTINUE | magic.MAGIC_RAW)
        __MAGIC.load()
    return __MAGIC


def set_magic_file(path):
    __get_instance().load(path)


def magic_scan(filename):
    """Scan for a single file type with libmagic"""
    global __MAGIC

    results = []
    file_mimes = __get_instance().file(filename)
    for file_mime in file_mimes.split('\012- '):
        if file_mime != __OCTET_STREAM_MIME:
            extension = mimetypes.guess_extension(file_mime)
            if extension is not None:
                results.append(extension[1:])
    return results

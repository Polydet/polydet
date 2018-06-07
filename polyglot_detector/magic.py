import magic
import mimetypes

__magic = None
""":type __magic: magic.Magic"""

__OCTET_STREAM_MIME = 'application/octet-stream'

__inited = False


def __init():
    global __inited, __magic
    if __inited:
        return
    __inited = True
    __magic = magic.open(magic.MAGIC_MIME_TYPE | magic.MAGIC_CONTINUE | magic.MAGIC_RAW)
    __magic.load()
    mimetypes.add_type('application/x-sharedlib', '.elf', strict=True)
    mimetypes.add_type('application/x-executable', '.elf', strict=True)
    mimetypes.add_type('application/x-dosexec', '.exe', strict=True)


def set_magic_file(path):
    __init()
    __magic.load(path)


def magic_scan(filename):
    """Scan for a single file type with libmagic"""
    global __magic

    __init()

    results = []
    file_mimes = __magic.file(filename)
    for file_mime in file_mimes.split('\012- '):
        if file_mime != __OCTET_STREAM_MIME:
            extension = mimetypes.guess_extension(file_mime)
            if extension is not None:
                results.append(extension[1:])
    return results

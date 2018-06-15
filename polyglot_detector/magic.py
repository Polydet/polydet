import logging
import magic

from . import mime

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

__magic = None
""":type __magic: magic.Magic"""

__inited = False


def __init():
    global __inited, __magic
    if __inited:
        return
    __inited = True
    __magic = magic.open(magic.MAGIC_MIME_TYPE | magic.MAGIC_CONTINUE | magic.MAGIC_RAW)
    __magic.load()


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
        extension = mime.guess_extension(file_mime)
        logger.debug('Guessed %s extension for MIME %s' % (extension, file_mime))
        if extension is not None:
            results.append(extension)
    return results

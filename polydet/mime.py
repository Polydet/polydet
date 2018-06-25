import logging
import mimetypes

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

mimetypes.add_type('application/x-sharedlib', '.o', strict=True)
mimetypes.add_type('application/x-executable', '.o', strict=True)
mimetypes.add_type('application/x-dosexec', '.exe', strict=True)

# There are some duplicate in the mimetypes package, so we handle some known types.
extension_map = {
    'application/octet-stream': None,
    'application/vnd.ms-excel': 'xls',
    'application/vnd.ms-powerpoint': 'ppt',
    'application/x-python-code': 'pyc',
    'image/jpeg': 'jpg',
    'image/tiff': 'tiff',
    'video/mpeg': 'mpeg',
}


def guess_extension(mime: str) -> str:
    """
    :param mime: The mime to guess the extension for
    :return: The extension, without dot
    """
    if mime in extension_map:
        return extension_map[mime]
    ext = mimetypes.guess_extension(mime)
    return ext[1:] if ext is not None else None

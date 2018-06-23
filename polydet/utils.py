def must_read(file, length) -> bytes:
    data = file.read(length)
    if len(data) != length:
        raise SyntaxError('File truncated')
    return data

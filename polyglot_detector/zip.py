import mmap


def check(filename):
    magic = b'PK'
    eocd_min_size = 22

    with open(filename, 'rb') as file, \
            mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as s:
        size = s.size()
        return s.find(magic, 0, max(0, size - eocd_min_size + len(magic))) != -1

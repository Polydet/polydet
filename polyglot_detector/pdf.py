import mmap


def check(filename):
    magic = b"%PDF-"

    with open(filename, 'rb') as file, \
            mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as s:
        return s.find(magic) != -1

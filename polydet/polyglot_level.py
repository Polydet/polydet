class PolyglotLevel:

    def __init__(self, is_valid = True, suspicious_chunks: [(int, int)] = None, embedded: set = None):
        self.is_valid = is_valid
        self.suspicious_chunks = suspicious_chunks if suspicious_chunks is not None else []
        self.embedded = embedded if embedded is not None else set()

    def invalid(self) -> 'PolyglotLevel':
        """
        Set the valid flag to False
        :return: self
        """
        self.is_valid = False

        return self

    def add_chunk(self, offset: int, size: int) -> 'PolyglotLevel':
        """
        Add a chunk to the list of suspicious chunks

        Note: do not try to merge overlapping chunks (for now?)
        :param offset: Offset of the chunk to add
        :param size: Size of the chunk to add
        :return: self
        """
        self.suspicious_chunks.append((offset, size))
        self.suspicious_chunks.sort(key=lambda chunk: chunk[0])
        return self

    def embed(self, type: str) -> 'PolyglotLevel':
        """
        Add a type to the list of embedded types
        :param type: type to add
        :return: self
        """
        self.embedded.add(type)

        return self

    def __eq__(self, other):
        if not isinstance(other, PolyglotLevel):
            return NotImplemented
        return self.is_valid == other.is_valid \
            and self.suspicious_chunks == other.suspicious_chunks \
            and self.embedded == other.embedded

    def __repr__(self):
        args = []
        if not self.is_valid:
            args.append('is_valid=False')
        if self.suspicious_chunks:
            args.append('suspicious_chunks=[%s]' % ', '.join('(0x%X, %d)' % chunk for chunk in self.suspicious_chunks))
        if self.embedded:
            args.append('embedded=%s' % self.embedded)
        return 'PolyglotLevel(' + ', '.join(args) + ')'

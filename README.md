# Polydet

Polydet is a library built to detect polyglots files, i.e. files readable in multiple formats.
It focuses on the common formats that are usually embedded in polyglot files (HTML, JS, PDF, ZIP, ...), as well as
common media file formats (PNG, JPG, MP3, ...) to detect abnormal data chunks.

TODO:

- Detect comments in common formats
- Refactor PolyglotLevel to show range of unusued bytes.
- Refactor TIFF format to not treat the data between the header and the IFD as automatically "used".

## Dependencies

- Python 3.5 or above.
- (yara-python)[https://github.com/VirusTotal/yara-python] (can be installed with `pip3 install yara-python`).

## Contributing

Don't forget to run the tests (*and do TDD!*) with `python3 -m unittest`.

## Common polyglot formats

This section describe some of the detected formats and how the detector works, its limitations, etc...

### PDF

A PDF starts with the magic number `%PDF-1.X`, where `X` is the minor version number.
However, most of the PDF reader will accept the document as a valid PDF if the truncated magic number `%PDF-` is anywhere within the 1024 first bytes.

The list below list some readers with different behaviour regarding the validation of a PDF:

- Google Chrome accepts the PDF it the magic is within the 1029 first bytes (1024 + length of `%PDF-`).
- Mozilla Firefox accepts the PDF if the magic number is anywhere in the file, as long as the Content-Type correspond to a PDF format.
- Evince accepts the PDF if the magic number is anywhere in the file, as long as the file extension is `.pdf`.

For now, this package only search for `%PDF-` anywhere in the file.
It would be possible to improve this by searching any form of this magic number followed by a line feed `\n`.

### ZIP

A ZIP file ends with a *End of central directory* record.
It is a structure between 22 and 65557 long due to the comment at the end.
However, some program (as *zipinfo*) will try to search for the EOCD even if there is garbage after the EOCD, after the 65535 bytes of comments.

Fow now, this package only search for `PK\x05\x06` with at least 18 bytes after anywhere in the file.

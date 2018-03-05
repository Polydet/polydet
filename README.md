# Polyglot detector

The purpose of this package is to detect polyglot files.
It focuses on the common formats that are usually embeded in polyglot files (HTML, JS, PDF, ZIP, ...)

## Contributing

Don't forget to run the tests (*and do TDD!*) with `python3 -m unittest tests`.

## Polyglot files

### PDF

A PDF starts with the magic number `%PDF-1.X`, where `X` is the minor version number.
However, most of the PDF reader will accept the document as a valid PDF if the truncated magic number `%PDF-` is anywhere within the 1024 first bytes.

The list below list some readers with different behaviour regarding the validation of a PDF:

- Google Chrome accepts the PDF it the magic is within the 1029 first bytes (1024 + length of `%PDF-`).
- Mozilla Firefox accepts the PDF if the magic number is anywhere in the file, as long as the Content-Type correspond to a PDF format.
- Evince accepts the PDF if the magic number is anywhere in the file, as long as the file extension is `.pdf`.

For now, this package only search for `%PDF-` anywhere in the file.

### ZIP

A ZIP file ends with a *End of central directory* record.
It is a structure between 22 and 65557 long due to the comment at the end.
However, some program (as *zipinfo*) will try to search for the EOCD even if there is garbage after the EOCD, after the 65535 bytes of comments.

Fow now, this package only search for `PK` with at least 20 bytes after anywhere in the file, but we aim for improvements.
For example, I plan to look at the source code of *zipinfo* to know how it searches for the EOCD.

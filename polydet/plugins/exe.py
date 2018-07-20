import os
import pefile
import yara

from polydet import PolyglotLevel

FILE_EXTENSION = 'exe'

RULES = """
rule IsMZ {
  condition:
    uint16(0) == 0x5A4D
}
rule IsPE {
  condition:
    IsMZ and uint32(uint32(0x3C)) == 0x00004550
}
"""

__PE_MAGIC_SIZE = 4
__COFF_HEADER_SIZE = 0x14
__OPTIONAL_HEADER_PE32_MAGIC = 0x10B
__OPTIONAL_HEADER_PE32_PLUS_MAGIC = 0x20B
__OPTIONAL_HEADER_SIZE_OF_IMAGE_OFFSET = 0x38


def check(filename):
    rules = yara.compile(source=RULES)
    matches = rules.match(filename)
    return check_with_matches(filename, {m.rule: m for m in matches})


# TODO: Detect other MZ format than PE?
# TODO: Detect big endian PE?
# TODO: Check the correctness of the CertificateTable?
# FIXME: Fix case when PE.FILE_HEADER.SizeOfOptionalHeader is bad
def check_with_matches(filename, matches):
    if 'IsPE' not in matches:
        return None

    level = PolyglotLevel()
    file_size = os.stat(filename).st_size
    pe = pefile.PE(filename)

    overlay_offset = pe.get_overlay_data_start_offset()
    if overlay_offset is not None:
        entry_id = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > entry_id \
                and pe.OPTIONAL_HEADER.DATA_DIRECTORY[entry_id].VirtualAddress != 0:
            certificate_table = pe.OPTIONAL_HEADER.DATA_DIRECTORY[entry_id]
            certificate_table_begin = certificate_table.VirtualAddress
            certificate_table_end = certificate_table_begin + certificate_table.Size
        else:
            certificate_table_begin = overlay_offset
            certificate_table_end = certificate_table_begin


        # Check if there is some data before the certificate table
        if overlay_offset < certificate_table_begin:
            level.add_chunk(overlay_offset, certificate_table_begin - overlay_offset)

        # Check if there is some data after the certificate table
        if file_size > certificate_table_end:
            level.add_chunk(certificate_table_end, file_size - certificate_table_end)

    return level

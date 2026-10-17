"""Explicitly regenerate the reviewed synthetic corpus; never run by make test.

Review changed bytes, expectations, and checksums together before committing.
No fixture contains third-party code or a collected malware sample.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fixtures import fuzz_seeds, elf_variant

root = Path(__file__).resolve().parent
cases = []


def add(name, data, reason, status=0, tools=()):
    filename = name + '.bin'
    (root / filename).write_bytes(data)
    cases.append(dict(file=filename, sha256=hashlib.sha256(data).hexdigest(),
                      exit=status, reason=reason, differential=list(tools)))


for name, data in fuzz_seeds().items():
    tools = ('llvm-readobj',) if name.startswith('directories-pe') else ()
    add(name, data, 'Synthetic ' + name + ': preserve successful parsing and cleanup.', tools=tools)
for wide in (False, True):
    for big in (False, True):
        for extended in (False, True):
            name = f'matrix-elf{64 if wide else 32}-{"big" if big else "little"}-{"extended" if extended else "standard"}'
            add(name, elf_variant(wide, big, extended),
                'ELF byte order and extended-numbering table values agree with independent tools.',
                tools=('readelf', 'llvm-readelf', 'llvm-readobj'))
# Reproduce the Linux CI failure: @VERSION is literal in a static symbol name.
strings = b'\0free@GLIBC_2.2.5\0'
string_offset = 64 + 3 * 64
symbol_offset = string_offset + len(strings)
header = struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF' + bytes([2, 1, 1]) + bytes(9),
                     1, 62, 1, 0, 0, 64, 0, 64, 0, 0, 64, 3, 0)
def section(kind, offset, size, link=0, width=0):
    return struct.pack('<IIQQQQIIQQ', 0, kind, 0, 0, offset, size, link, 0, 1, width)
image = header + bytes(64) + section(3, string_offset, len(strings))
image += section(2, symbol_offset, 48, 1, 24) + strings + bytes(24)
image += struct.pack('<IBBHQQ', 1, 0x12, 0, 0, 0, 0)
add('elf-static-versioned-symbol', image, 'Linux CI regression: retain literal @GLIBC suffix in static symbols.',
    tools=('readelf', 'llvm-readelf', 'llvm-readobj'))

seeds = fuzz_seeds()
image = bytearray(seeds['directories-pe32'])
struct.pack_into('<I', image, 512 + 0x414, 0x80000000)
add('pe-resource-cycle', image, 'Reject a resource directory pointing back to its root.', 1)
for name, data in [('empty', b''), ('truncated-pe', b'MZ' + bytes(14)),
                   ('truncated-elf', b'\x7fELF' + bytes(12)),
                   ('truncated-mach', b'\xcf\xfa\xed\xfe' + bytes(12))]:
    tools = ('llvm-readobj',) + (('readelf', 'llvm-readelf') if name in ('empty', 'truncated-elf') else ())
    add(name, data, 'Reject truncated input without a crash or successful report.', 1, tools)
image = bytearray(seeds['universal-mach32'])
# Both fat_arch entries must not reference the same disk bytes.
image[36:40] = image[16:20]
add('mach-overlapping-slices', image, 'Reject overlapping universal Mach-O slices.', 1)
# Preserve cases promoted from future fuzz failures when regenerating this set.
manifest = root / 'manifest.json'
if manifest.exists():
    generated = {case['file'] for case in cases}
    cases.extend(case for case in json.loads(manifest.read_text())
                 if case['file'] not in generated)
(root / 'manifest.json').write_text(json.dumps(cases, indent=2) + '\n')
print(f'Wrote {len(cases)} reviewed corpus cases')

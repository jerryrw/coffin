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
from stress_fixtures import aliased_pe, elf_dynamic_aliases, universal_names, pe_resource_chain, pe_resource_aliases

root = Path(__file__).resolve().parent
cases = []


def add(name, data, reason, status=0, tools=(), stdout=(), stderr=()):
    filename = name + '.bin'
    (root / filename).write_bytes(data)
    cases.append(dict(file=filename, sha256=hashlib.sha256(data).hexdigest(),
                      exit=status, reason=reason, differential=list(tools)))
    if stdout:
        cases[-1]['stdout_contains'] = list(stdout)
    if stderr:
        cases[-1]['stderr_contains'] = list(stderr)


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
# Small versions of adversarial controls are frozen; oversized stress cases are
# generated only in temporary directories by tests/test_stress.py.
add('pe-shared-raw-ranges', aliased_pe(3),
    'Distinct PE RVAs can share physical payload bytes; retain every section.',
    stdout=('Counts: 3 sections',))
add('pe-ambiguous-directory-rvas', aliased_pe(2, overlapping_rvas=True),
    'A directory cannot map through overlapping RVA sections.', 1, stderr=('Invalid PE',))
add('elf-dynamic-address-control', elf_dynamic_aliases(1),
    'Resolve DT_NEEDED through one unambiguous LOAD range.', stdout=('libstress.so',))
add('elf-ambiguous-dynamic-loads', elf_dynamic_aliases(2),
    'Overlapping LOAD ranges make dynamic addresses ambiguous.', 1, stderr=('Invalid',))
image = bytearray(universal_names(2, 1))
add('mach-adjacent-slices', image, 'Adjacent nonoverlapping slices must remain accepted.',
    stdout=('Slice 1:', 'Slice 2:'))
struct.pack_into('>I', image, 20, struct.unpack_from('>I', image, 20)[0] + 1)
add('mach-one-byte-overlap', image, 'Reject a single byte of universal-slice overlap.',
    1, stderr=('Invalid',))
# Preserve depth/cycle/reference-sharing regressions in both PE header widths.
for wide in (False, True):
    prefix = 'pe64' if wide else 'pe32'
    add(prefix + '-resource-depth16', pe_resource_chain(16, wide),
        'Sixteen directory levels including the root remain inspectable.',
        stdout=('RCDATA(#10)' + '/#1' * 15,))
    add(prefix + '-resource-depth17', pe_resource_chain(17, wide),
        'Reject the seventeenth directory level with an explicit depth limit.', 1,
        stderr=('Parser resource limit exceeded: PE resource directory depth (16 levels)',))
    add(prefix + '-resource-shared-subtree', pe_resource_aliases(branches=2, leaves=2, wide=wide),
        'Repeated references are not cycles: retain separate name/language paths.',
        stdout=tuple(f'RCDATA(#10)/#{name}/#{language}'
                     for name in (1, 2) for language in (1033, 1034)))
    add(prefix + '-resource-ancestor-cycle', pe_resource_chain(3, wide, cycle_to=1),
        'Reject a non-root ancestor cycle, separately from depth/read exhaustion.', 1,
        stderr=('Invalid PE resource directory: ancestor cycle',))
    add(prefix + '-resource-reference-amplification', pe_resource_aliases(branches=16, leaves=128, wide=wide),
        'Repeated visits exceed the 4096-read allowance despite a small on-disk graph.', 1,
        stderr=('Parser resource limit exceeded: PE resource directory reads (4096)',))
# Preserve cases promoted from future fuzz failures when regenerating this set.
manifest = root / 'manifest.json'
if manifest.exists():
    generated = {case['file'] for case in cases}
    cases.extend(case for case in json.loads(manifest.read_text())
                 if case['file'] not in generated)
(root / 'manifest.json').write_text(json.dumps(cases, indent=2) + '\n')
print(f'Wrote {len(cases)} reviewed corpus cases')

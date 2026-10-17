"""Compare reports against installed independent binary tools, never execute inputs.

Linux CI requires GNU readelf and llvm-readobj; macOS CI requires otool. Other
available tools add cross-format checks. Missing optional tools are reported.
"""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def tool(name):
    candidates = [shutil.which(name)]
    for prefix in (os.environ.get('LLVM_BIN', ''), '/opt/homebrew/opt/llvm/bin', '/usr/local/opt/llvm/bin'):
        if prefix:
            candidates.append(str(Path(prefix) / name))
    return next((p for p in candidates if p and Path(p).is_file()), None)


def run(*args):
    p = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=30)
    if p.returncode:
        raise AssertionError(f'{args}: {p.stderr}')
    return p.stdout


def rows(text):
    # Report rows start with a numeric index and have pipe-separated fields.
    return [[p.strip() for p in line.split('|')] for line in text.splitlines()
            if '|' in line and re.match(r'^\s*\d+(?:\s|\|)', line)]


def field(block, name):
    match = re.search(r'^\s*' + re.escape(name) + r':\s*(.*)$', block, re.M)
    assert match, (name, block)
    return match.group(1)


def number(block, name):
    return int(field(block, name).split()[0], 0)


def llvm_sections(binary, oracle, path):
    fmt = 'pe' if path.suffix == '.exe' else 'elf' if 'mach' not in path.name else 'mach'
    output = run(oracle, '--file-headers', '--sections', path)
    # A universal file emits one independent File block per architecture.
    blocks = re.split(r'\nFile: ', output)[1:]
    report = run(binary, '--sections', path)
    if fmt == 'mach' and 'universal' in path.name:
        reports = re.split(r'\nSlice \d+:', report)[1:]
    else:
        reports = [report]
    assert len(blocks) == len(reports), path
    for block, text in zip(blocks, reports):
        sections = re.findall(r'  Section \{\n(.*?)\n  \}', block, re.S)
        actual = rows(text)
        assert len(sections) == len(actual), (path, len(sections), len(actual))
        bitness = 64 if '64bit' in block else 32
        assert (f'ELF{bitness}' if fmt == 'elf' else f'{bitness}-bit') in text, path
        arch = field(block, 'Arch')
        label = {'i386': 'x86', 'x86_64': 'x86-64', 'arm': 'ARM', 'aarch64': 'AArch64', 'arm64': 'AArch64'}[arch]
        assert re.search(r'Summary:.* / ' + re.escape(label) + r' / ', text), (path, arch)
        for expected, found in zip(sections, actual):
            name = field(expected, 'Name').split(' (')[0]
            if name.startswith('('):
                name = ''
            if fmt == 'pe':
                assert found[0].split(maxsplit=1)[1] == name, (path, found, name)
                assert [int(found[i], 0) for i in (1, 2, 3, 4)] == [number(expected, n) for n in
                    ('VirtualAddress', 'PointerToRawData', 'RawDataSize', 'VirtualSize')], (path, found)
                raw = int(re.search(r'Characteristics \[ \((0x[0-9A-Fa-f]+)\)', expected).group(1), 0)
                assert found[5] == ''.join(c if raw & m else '-' for c, m in [('R', 0x40000000), ('W', 0x80000000), ('X', 0x20000000)])
            elif fmt == 'elf':
                assert found[1] == (name or '<unnamed>'), (path, found, name)
                assert int(found[4], 0) == number(expected, 'Address'), path
                assert int(found[5]) == number(expected, 'Size'), path
                if found[3] != '--':
                    assert int(found[3], 0) == number(expected, 'Offset'), path
                raw = int(re.search(r'Flags \[ \((0x[0-9A-Fa-f]+)\)', expected).group(1), 0)
                assert found[6] == ''.join(c if raw & m else '-' for c, m in [('W', 1), ('A', 2), ('X', 4)])
            else:
                assert found[1] == field(expected, 'Segment').split(' (')[0] + ',' + name, (path, found)
                assert int(found[2], 0) == number(expected, 'Address'), path
                assert int(found[5]) == number(expected, 'Size'), path
                if 'zero-fill' not in found[3]:
                    assert int(found[3], 0) == number(expected, 'Offset'), path
    if fmt == 'pe':
        entry = int(field(output, 'AddressOfEntryPoint'), 0)
        assert f'RVA 0x{entry:08X}' in report, path
        imports = run(oracle, '--coff-imports', path)
        actual = run(binary, '--imports', path)
        for name in re.findall(r'^  (?:Name|Symbol): (\S+)', imports, re.M):
            assert name in actual, (path, name)


def readelf_programs(output):
    # GNU readelf prints a zero alignment as plain 0; LLVM uses 0x0.
    # Flags may also be empty. Neither variation changes the segment itself.
    programs = []
    for line in output.splitlines():
        m = re.match(r'^\s+(\S+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+0x[0-9a-f]+\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+([RWE \t]*)\s+(?:0x[0-9a-f]+|[0-9]+)\s*$', line)
        if m:
            kind, offset, va, size, mem, perms = m.groups()
            programs.append((kind, int(offset, 16), int(va, 16), int(size, 16), int(mem, 16), ''.join(perms.split())))
    return programs


def elf_reference(binary, oracle, path):
    expected = run(oracle, '-W', '-h', '-l', '-s', '-d', path)
    actual = run(binary, '--headers', '--program-headers', '--symbols', '--dependencies', path)
    entry = int(re.search(r'Entry point address:\s*(0x[0-9a-fA-F]+)', expected).group(1), 0)
    assert f'VA 0x{entry:016X}' in actual if re.search(r'Class:\s+ELF64', expected) else f'VA 0x{entry:08X}' in actual
    expected_programs = readelf_programs(expected)
    program_report = run(binary, '--program-headers', path)
    found = rows(program_report)
    assert len(found) == len(expected_programs), (path, found, expected_programs)
    for row, p in zip(found, expected_programs):
        assert row[1].split('/')[0] == {'EXIDX': 'ARM_EXIDX'}.get(p[0], p[0]), (path, row, p)
        assert tuple(int(row[i], 0) for i in (2, 3, 4, 5)) == p[1:5], (path, row, p)
        assert row[6] == ''.join(c if ('E' if c == 'X' else c) in p[5] else '-' for c in 'RWX')
    # Compare symbol name/value/size, rather than just finding the names anywhere.
    symbol_rows = rows(run(binary, '--symbols', path))
    expected_symbols = re.findall(r'^\s*\d+:[ \t]+([0-9a-f]+)[ \t]+(\d+)[ \t]+\S+[ \t]+\S+[ \t]+\S+[ \t]+\S+[ \t]*([^\n]*)$', expected, re.M)
    assert len(symbol_rows) == len(expected_symbols), (path, len(symbol_rows), len(expected_symbols))
    for row, (value, size, tail) in zip(symbol_rows, expected_symbols):
        # readelf annotates versioned names (foo@GLIBC_2.x); coffin reports the
        # underlying string-table name and explicitly does not decode versions.
        name = tail.split()[0].split('@')[0] if tail.strip() else ''
        assert row[1] == (name or '<unnamed>') and int(row[2], 0) == int(value, 16) and int(row[3]) == int(size), (path, row, name)

    for name in re.findall(r'\(NEEDED\).*?\[([^]]+)\]', expected):
        assert name in actual, (path, name)


def mach_reference(binary, oracle, path):
    expected = run(oracle, '-l', path)
    actual = rows(run(binary, '--sections', path))
    sections = re.findall(r'^Section\n\s+sectname (\S+)\n\s+segname (\S+)\n\s+addr (0x[0-9a-f]+)\n\s+size (0x[0-9a-f]+)\n\s+offset (\d+)', expected, re.M)
    assert len(actual) == len(sections), path
    for row, (name, segment, address, size, offset) in zip(actual, sections):
        assert row[1] == segment + ',' + name and int(row[2], 0) == int(address, 16) and int(row[5]) == int(size, 16), (path, row)
        if 'zero-fill' not in row[3]:
            assert int(row[3], 0) == int(offset), path
    report = run(binary, '--dependencies', path)
    for name in re.findall(r'^\s+(\S+) \(compatibility version', run(oracle, '-L', path), re.M):
        assert name in report, (path, name)
    for segment in re.findall(r'\n\s+segname (\S+)\n\s+vmaddr .*?\n\s+initprot (0x[0-9a-f]+)', expected, re.S):
        # Section-level permissions are checked against their containing segment.
        name, flags = segment; flags = int(flags, 16)
        for row in actual:
            if row[1].startswith(name + ','):
                assert row[6] == ''.join(c if flags & m else '-' for c, m in [('R', 1), ('W', 2), ('X', 4)])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--require-tools', nargs='*', default=[])
    args = parser.parse_args()
    tools = {name: tool(name) for name in ('readelf', 'llvm-readelf', 'llvm-readobj', 'otool')}
    missing = [name for name in args.require_tools if not tools.get(name)]
    if missing:
        parser.error('Required independent tools missing: ' + ', '.join(missing))
    binary = args.binary.resolve(); checks = 0
    for name, executable in tools.items():
        if not executable:
            print(f'SKIP optional tool {name}: not installed'); continue
        paths = sorted(ROOT.glob('hello-*'))
        if name in ('readelf', 'llvm-readelf') and binary.read_bytes()[:4] == b'\x7fELF':
            paths.append(binary)  # A real dynamic Linux executable, not just fixtures.
        for path in paths:
            if name == 'llvm-readobj':
                llvm_sections(binary, executable, path)
            elif name in ('readelf', 'llvm-readelf') and path.read_bytes()[:4] == b'\x7fELF':
                elf_reference(binary, executable, path)
            elif name == 'otool' and 'mach' in path.name:
                mach_reference(binary, executable, path)
            else:
                continue
            checks += 1
            print(f'PASS {name}: {path.name}')
    if not checks:
        parser.error('No independent checks ran; install LLVM tools, GNU readelf, or macOS otool')
    print(f'Differential checks passed: {checks} file/tool comparisons')


if __name__ == '__main__':
    main()

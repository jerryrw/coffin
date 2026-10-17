"""Integration test: universal slices share one retained-table budget."""
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


def universal_symbols(slices, symbols):
    entries, payload = [], bytearray()
    start = 8 + slices * 20
    for index in range(slices):
        # Distinct subtypes avoid duplicate-architecture rejection. Every thin
        # slice is otherwise independently valid, with empty undefined symbols.
        header = struct.pack('<8I', 0xfeedfacf, 0x1000007, index, 2, 1, 24, 0, 0)
        command = struct.pack('<6I', 2, 24, 56, symbols, 56 + symbols * 16, 1)
        thin = header + command + bytes(symbols * 16 + 1)
        entries.append(struct.pack('>5I', 0x1000007, index, start + len(payload), len(thin), 0))
        payload.extend(thin)
    return struct.pack('>2I', 0xcafebabe, slices) + b''.join(entries) + payload


binary = str(Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory() as directory:
    source = Path(directory) / 'symbols.mach'
    for slices, expected in ((1, 0), (64, 1)):
        source.write_bytes(universal_symbols(slices, 2048))
        result = subprocess.run([binary, '--summary', str(source)],
                                capture_output=True, text=True, timeout=30)
        assert result.returncode == expected, result.stderr
        assert ('Analysis Report' in result.stdout) == (expected == 0), result.stdout[:200]
        if expected:
            assert 'Parser resource limit exceeded: aggregate table allocation' in result.stderr, result.stderr
        assert 'Sanitizer' not in result.stderr and 'runtime error:' not in result.stderr, result.stderr
print('Universal Mach-O aggregate allocation limit passed')

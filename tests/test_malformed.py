# End-to-end tests launch the actual C executable and inspect its exit status,
# stdout, stderr, and extracted bytes. A nonzero parser result is expected for
# malformed file structure; an unsupported resource preview can still be a
# successful inspection. unittest discovers methods whose names start test_.
# Temporary directories isolate each case and are removed automatically.

"""Run against a freshly built CLI, preferably with ASan and UBSan enabled."""
import hashlib
import json
import math
import re
from collections import Counter
import platform
import shutil
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from fixtures import pe_details, mach_sections, resource_payload, version_payload, universal_mach, elf_variant, big_mach, image_resources, delay_imports, dialog_controls

# Locate the repository from this script, independent of the shell's directory.
# An optional first command-line argument chooses the normal or sanitizer binary.
ROOT = Path(__file__).resolve().parents[1]
BINARY = str(Path(sys.argv.pop(1)).resolve()) if len(sys.argv) > 1 else str(ROOT / 'bin/coffin')


class ParserTests(unittest.TestCase):
    # Write a byte image to a temporary file and inspect it with --verbose.
    # Check status and sanitizer diagnostics, then independently compare reported
    # hashes with hashlib. The helper returns output for more specific assertions.
    def run_file(self, data, success):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(data)
            result = subprocess.run([BINARY, '--verbose', str(path)], capture_output=True, text=True)
        self.assertNotIn('Sanitizer', result.stderr)
        self.assertEqual(result.returncode, 0 if success else 1, result.stderr)
        self.assertEqual('Analysis Report' in result.stdout, success)
        if success:
            self.assertTrue(all(line.startswith('Analyzing ') for line in result.stderr.splitlines()), result.stderr)
            self.assertIn(hashlib.sha256(data).hexdigest(), result.stdout)
            self.assertIn(hashlib.md5(data).hexdigest(), result.stdout)
        return result

    # Smoke-check the original three files through the full inspection path.
    def test_bundled_samples(self):
        for name in ('testexecutable.exe', 'testelf', 'testmach'):
            with self.subTest(name=name):
                self.run_file((ROOT / name).read_bytes(), True)

    # Corrupt PE signatures, offsets, sizes, and section storage one field at a time.
    # Keep unrelated bytes intact so each failure targets a specific validation.
    def test_pe(self):
        original = (ROOT / 'testexecutable.exe').read_bytes()
        pe = struct.unpack_from('<I', original, 60)[0]
        optional = pe + 24
        wide = struct.unpack_from('<H', original, optional)[0] == 0x20b
        fixed = 112 if wide else 96
        section = optional + struct.unpack_from('<H', original, pe + 20)[0]
        cases = [(60, '<i', -1), (pe, '<I', 0x12344550),
                 (optional, '<H', 0x999), (pe + 20, '<H', 2),
                 (optional + fixed - 4, '<I', 64),
                 (section + 20, '<I', len(original)),
                 (section + 16, '<I', 0xffffffff)]
        for offset, fmt, value in cases:
            with self.subTest(offset=offset, value=value):
                data = bytearray(original)
                struct.pack_into(fmt, data, offset, value)
                self.run_file(data, False)
        self.run_file(original[:section + 10], False)
        # Extra optional-header padding must not shift section parsing.
        data = bytearray(original)
        size = struct.unpack_from('<H', data, pe + 20)[0]
        data[section:section] = b'\0' * 8
        struct.pack_into('<H', data, pe + 20, size + 8)
        count = struct.unpack_from('<H', data, pe + 6)[0]
        for i in range(count):
            off = section + 8 + i * 40 + 20
            raw = struct.unpack_from('<I', data, off)[0]
            if raw:
                struct.pack_into('<I', data, off, raw + 8)
        self.run_file(data, True)

    # Build both PE widths with a 256-byte section: a uniform byte histogram must
    # measure 8, constant bytes 0, and a truncated raw section must fail.
    def test_minimal_pe_bitness_and_entropy(self):
        for wide in (False, True):
            fixed = 112 if wide else 96
            data = bytearray(64)
            data[:2] = b'MZ'
            struct.pack_into('<I', data, 60, 64)
            data += b'PE\0\0' + struct.pack('<HHIIIHH', 0x8664 if wide else 0x14c,
                                             1, 0, 0, 0, fixed, 0)
            optional = bytearray(fixed)
            struct.pack_into('<H', optional, 0, 0x20b if wide else 0x10b)
            data += optional
            raw_offset = len(data) + 40
            data += struct.pack('<8sIIIIIIHHI', b'.data', 256, 4096, 256,
                                raw_offset, 0, 0, 0, 0, 0)
            result = self.run_file(data + bytes(range(256)), True)
            self.assertIn('Entropy: 8.000000', result.stdout)
            result = self.run_file(data + b'A' * 256, True)
            self.assertIn('Entropy: 0.000000', result.stdout)
            self.run_file(data + b'A' * 255, False)

    # Compare whole-file, window, and section measurements with a Python reference.
    # Also verify the shorter final window, zero-fill labels, and universal Mach-O
    # container-offset translations, where slice-relative reads would be wrong.
    def test_entropy_reports_and_windows(self):
        # Compute byte-histogram entropy independently in Python for report checks.
        def reference(data):
            return -sum((n / len(data)) * math.log2(n / len(data)) for n in Counter(data).values())

        images = [mach_sections(), mach_sections(True), universal_mach(),
                  elf_variant(), elf_variant(True, True, True),
                  (ROOT / 'hello-linux-arm32').read_bytes(),
                  (ROOT / 'hello-linux-arm64').read_bytes(), pe_details()]
        for data in images:
            with self.subTest(magic=data[:4]):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / 'sample'
                    path.write_bytes(data)
                    result = subprocess.run([BINARY, '--sections', '--entropy-window', '257', str(path)],
                                            capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f'Whole-file entropy: {reference(data):7.4f} bits/byte', result.stdout)
                self.assertIn('High entropy alone does not establish', result.stdout)
                windows = result.stdout.split('Entropy windows', 1)[1].split('Summary:', 1)[0]
                rows = re.findall(r'^  0x([0-9A-F]+) \|\s+(\d+) \|\s+([0-9.]+)$', windows, re.M)
                self.assertEqual(len(rows), (len(data) + 256) // 257)
                for index, (offset, size, value) in enumerate(rows):
                    chunk = data[index * 257:(index + 1) * 257]
                    self.assertEqual(int(offset, 16), index * 257)
                    self.assertEqual(int(size), len(chunk))
                    self.assertAlmostEqual(float(value), reference(chunk), places=4)
                # Verify section measurements from the reported container ranges,
                # including each architecture in a universal Mach-O.
                for line in result.stdout.splitlines():
                    fields = [part.strip() for part in line.split('|')]
                    if len(fields) == 9 and fields[0].isdigit() and ',' in fields[1]:
                        if fields[7] == 'N/A':
                            self.assertIn('zero-fill', fields[3])
                        else:
                            offset, size = int(fields[4], 16), int(fields[5])
                            self.assertAlmostEqual(float(fields[7]), reference(data[offset:offset + size]), places=4)
                    if data[:4] == b'\x7fELF' and len(fields) == 9 and fields[0].isdigit():
                        if fields[3] == '--':
                            self.assertEqual(fields[7], 'N/A')
                        elif int(fields[5]):
                            offset, size = int(fields[3], 16), int(fields[5])
                            self.assertAlmostEqual(float(fields[7]), reference(data[offset:offset + size]), places=4)
                if data[:4] in (b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe'):
                    self.assertRegex(result.stdout, r'__DATA,__data[^\n]+1\.5000')
                    self.assertRegex(result.stdout, r'__DATA,__bss[^\n]+N/A')
                if data[:4] == b'\x7fELF':
                    self.assertRegex(result.stdout, r'NULL/0x00000000[^\n]+N/A')

    # Show that raw PE padding counts toward entropy even when virtual size is one.
    # Then remove raw bytes and verify N/A rather than a misleading measured zero.
    def test_entropy_empty_sections_and_padding(self):
        # No directories; a virtual byte plus 255 raw padding bytes.
        data = bytearray(64)
        data[:2] = b'MZ'
        struct.pack_into('<I', data, 60, 64)
        data += b'PE\0\0' + struct.pack('<HHIIIHH', 0x14c, 1, 0, 0, 0, 96, 0)
        optional = bytearray(96)
        struct.pack_into('<H', optional, 0, 0x10b)
        data += optional
        start = len(data)
        data += struct.pack('<8sIIIIIIHHI', b'.data', 1, 4096, 256, start + 40, 0, 0, 0, 0, 0)
        result = self.run_file(data + bytes(range(256)), True)
        self.assertIn('Entropy: 8.000000 bits/byte (raw file bytes, including padding)', result.stdout)
        struct.pack_into('<I', data, start + 16, 0)
        result = self.run_file(data, True)
        self.assertIn('Entropy: N/A (no file bytes)', result.stdout)

    # Reject invalid numbers and too many windows, but accept the largest uint64
    # window size without arithmetic overflow in the window-count calculation.
    def test_entropy_window_argument_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sample'
            path.write_bytes((ROOT / 'hello-pe64.exe').read_bytes() + bytes(4096))
            for value in ('0', '-1', 'abc', '18446744073709551616', '1'):
                result = subprocess.run([BINARY, '--entropy-window', value, str(path)],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertNotIn('Sanitizer', result.stderr)
            self.assertIn('exceeds 4096 windows', result.stderr)
            result = subprocess.run([BINARY, '--summary', '--entropy-window', '18446744073709551615', str(path)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('Entropy windows', result.stdout)

    # Corrupt original ELF table offsets, entry sizes, counts, and name data.
    # The parser should fail safely rather than following invalid table references.
    def test_elf(self):
        original = (ROOT / 'testelf').read_bytes()
        self.run_file(original[:64], False)
        for offset, fmt, value in ((32, '<Q', 0xffffffffffffffff),
                                   (54, '<H', 1), (58, '<H', 1)):
            data = bytearray(original)
            struct.pack_into(fmt, data, offset, value)
            self.run_file(data, False)
        # A valid sectionless ELF is allowed.
        data = bytearray(original[:64])
        struct.pack_into('<Q', data, 32, 0)
        struct.pack_into('<Q', data, 40, 0)
        struct.pack_into('<H', data, 56, 0)
        struct.pack_into('<H', data, 60, 0)
        struct.pack_into('<H', data, 62, 0)
        self.run_file(data, True)

    # Exercise zero, short, overflowing, and truncated command sizes.
    # Also confirm a valid command sequence beyond the old 16-command limit.
    def test_mach_commands(self):
        for size in (0, 4, 12, 0xfffffff8):
            header = struct.pack('<8I', 0xfeedfacf, 0x1000007, 3, 2, 1, 8, 0, 0)
            self.run_file(header + struct.pack('<2I', 2, size), False)
        header = struct.pack('<8I', 0xfeedfacf, 0x1000007, 3, 2, 17, 136, 0, 0)
        commands = struct.pack('<2I', 2, 8) * 16
        self.run_file(header + commands + struct.pack('<2I', 2, 0), False)
        self.run_file(header + commands + struct.pack('<2I', 2, 8), True)

    # Use 17 entries to catch the former 16-row reporting cap in every format.
    # A later out-of-bounds entry must still be validated, not skipped after the cap.
    def test_reporting_limits(self):
        # Seventeen valid ELF sections, including a names table.
        ident = b'\x7fELF' + bytes([2, 1, 1]) + bytes(9)
        header = struct.pack('<16sHHIQQQIHHHHHH', ident, 2, 62, 1, 0, 0, 64,
                             0, 64, 0, 0, 64, 17, 1)
        names = b'\0.text\0.shstrtab\0'
        table = bytearray(17 * 64)
        struct.pack_into('<IIQQQQIIQQ', table, 64, 7, 3, 0, 0, 64 + len(table),
                         len(names), 0, 0, 1, 0)
        struct.pack_into('<I', table, 128, 1)
        result = self.run_file(header + table + names, True)
        self.assertNotIn('omitted', result.stdout)
        self.assertIn('Section 17:', result.stdout)
        self.assertIn('Name: .text', result.stdout)
        struct.pack_into('<IIQQQQIIQQ', table, 16 * 64, 0, 1, 0, 0,
                         0xffffffffffffffff, 1, 0, 0, 1, 0)
        self.run_file(header + table + names, False)
        # Seventeen zero-length PE sections, valid without raw data.
        data = bytearray(64)
        data[:2] = b'MZ'
        struct.pack_into('<I', data, 60, 64)
        data += b'PE\0\0' + struct.pack('<HHIIIHH', 0x14c, 17, 0, 0, 0, 96, 0)
        optional = bytearray(96)
        struct.pack_into('<H', optional, 0, 0x10b)
        result = self.run_file(data + optional + bytes(17 * 40), True)
        self.assertNotIn('omitted', result.stdout)
        header = struct.pack('<8I', 0xfeedfacf, 0x1000007, 3, 2, 17, 136, 0, 0)
        result = self.run_file(header + struct.pack('<2I', 2, 8) * 17, True)
        self.assertNotIn('omitted', result.stdout)

    # Use identical segment intentions in thin 32/64-bit layouts and verify the
    # same decoded segment name and declared read/execute permissions.
    def test_mach_bitness_and_permissions(self):
        for wide in (False, True):
            segment = struct.pack('<II16s' + ('QQQQ' if wide else 'IIII') + 'IIII',
                                  0x19 if wide else 1, 72 if wide else 56,
                                  b'__TEXT', 0x1000, 0x2000, 0, 0, 7, 5, 0, 0)
            header = struct.pack('<' + ('8I' if wide else '7I'),
                                 0xfeedfacf if wide else 0xfeedface,
                                 0x1000007 if wide else 7, 3, 2, 1, len(segment), 0,
                                 *([0] if wide else []))
            result = self.run_file(header + segment, True)
            self.assertIn('Segment: __TEXT', result.stdout)
            self.assertIn('read execute', result.stdout)

    # Separate unsupported ELF class/order errors from accepted big-endian Mach-O.
    # Changing magic bytes must select the correct decoding path.
    def test_unsupported_variants(self):
        elf = bytearray((ROOT / 'testelf').read_bytes())
        for offset, value in ((4, 3), (5, 3)):
            data = bytearray(elf)
            data[offset] = value
            self.assertIn('Unsupported ELF', self.run_file(data, False).stderr)
        for magic in (b'\xfe\xed\xfa\xcf',):
            self.assertIn('big-endian', self.run_file(magic + bytes(60), True).stdout)

    # Check default versus verbose output, argument errors, and --help status.
    # --json is deliberately unsupported; the project's reports are plain text.
    def test_cli(self):
        path = str(ROOT / 'testmach')
        normal = subprocess.run([BINARY, path], capture_output=True, text=True)
        verbose = subprocess.run([BINARY, '--verbose', path], capture_output=True, text=True)
        self.assertEqual(verbose.returncode, 0)
        self.assertIn('Summary:', normal.stdout)
        self.assertIn('Full field details:', verbose.stdout)
        self.assertIn('Summary:', verbose.stdout)
        self.assertIn('Analyzing', verbose.stderr)
        self.assertEqual(normal.stderr, '')
        for args in ([], ['--json', path], [path, path]):
            self.assertEqual(subprocess.run([BINARY, *args], capture_output=True).returncode, 1)
        self.assertEqual(subprocess.run([BINARY, '--help'], capture_output=True).returncode, 0)

    # Verify normalized imports, ordinal imports, direct/forwarded exports, and
    # resource labels in PE32 and PE32+ using the same logical fixture contents.
    def test_pe_directory_reports(self):
        for wide in (False, True):
            with self.subTest(wide=wide):
                data = pe_details(wide)
                result = self.run_file(data, True)
                for text in ('KERNEL32.dll!CreateFileA (hint 5)', 'KERNEL32.dll!#12 (ordinal)',
                             'Ordinal 7: Exported', 'Ordinal 8: <ordinal-only>',
                             '-> OTHER.Forwarded', 'Ordinal 9: <ordinal-only>',
                             'RCDATA(#10)/greeting😀/#1033', 'size 4, code page 65001'):
                    self.assertIn(text, result.stdout)
                # FirstThunk fallback when OriginalFirstThunk is absent.
                struct.pack_into('<I', data, 512 + 0x200, 0)
                self.assertIn('CreateFileA', self.run_file(data, True).stdout)

    # Break RVA references, ordinal indices, resource recursion, and terminators.
    # Each mutation should fail structurally without an out-of-bounds read or hang.
    def test_pe_malformed_directories(self):
        original = pe_details(True)
        cases = ((512 + 0x200, '<I', 0x90000000),  # Unmapped lookup table.
                 (512 + 0x240, '<Q', 0x1000012a0),  # Invalid PE32+ name RVA.
                 (512 + 0x60, '<H', 3),  # Export ordinal outside address table.
                 (512 + 0x410 + 4, '<I', 0x80000000),  # Resource cycle.
                 (512 + 0x428 + 4, '<I', 0x800001ff),  # Truncated child directory.
                 (512 + 0x448, '<I', 0x90000000),  # Unmapped resource payload.
                 (512 + 0x490, '<H', 0xffff))  # Out-of-range UTF-16 name.
        for offset, fmt, value in cases:
            data = bytearray(original)
            struct.pack_into(fmt, data, offset, value)
            self.run_file(data, False)
        # Import descriptor list without a null terminator.
        data = bytearray(original)
        fixed = 112
        struct.pack_into('<I', data, 64 + 24 + fixed + 12, 20)
        self.run_file(data, False)
        # Name without a terminator before the end of its mapped section.
        data = bytearray(original)
        struct.pack_into('<Q', data, 512 + 0x240, 0x1ffe)
        data[-2:] = b'AB'
        self.run_file(data, False)

    # Allow multiple export names for one ordinal and report 129 imports.
    # Place directory data in section 17 to ensure mapping covers all sections.
    def test_pe_aliases_and_report_limits(self):
        data = pe_details(True)
        # Two export names may identify the same ordinal.
        struct.pack_into('<I', data, 512 + 24, 2)
        struct.pack_into('<I', data, 512 + 0x54, 0x1090)
        struct.pack_into('<H', data, 512 + 0x62, 0)
        self.assertIn('Exports: 4 entries', self.run_file(data, True).stdout)
        # A valid 129-entry thunk table must report every symbol without omissions.
        data = pe_details(True)
        struct.pack_into('<IIIII', data, 512 + 0x200, 0x1800, 0, 0, 0x1280, 0x1800)
        for index in range(129):
            struct.pack_into('<Q', data, 512 + 0x800 + index * 8, (1 << 63) | index)
        struct.pack_into('<Q', data, 512 + 0x800 + 129 * 8, 0)
        result = self.run_file(data, True)
        self.assertIn('Imports: 129 symbols', result.stdout)
        self.assertNotIn('omitted', result.stdout)
        # RVA resolution must include section 17, beyond the historical report cap.
        data = pe_details(True)
        table = 64 + 24 + 112 + 24
        section = bytearray(data[table:table + 40])
        struct.pack_into('<I', section, 20, 1024)
        header = bytearray(data[:table])
        struct.pack_into('<H', header, 64 + 6, 17)
        struct.pack_into('<I', header, 64 + 24 + 60, 1024)
        header += bytes(16 * 40) + section
        header += bytes(1024 - len(header))
        result = self.run_file(header + data[512:], True)
        self.assertIn('CreateFileA', result.stdout)
        self.assertNotIn('omitted', result.stdout)

    # Check file-backed versus zero-fill section output, invalid payload and
    # relocation ranges, and a section count above the former 128-entry cap.
    def test_mach_section_reports(self):
        for wide in (False, True):
            data = mach_sections(wide)
            result = self.run_file(data, True)
            for text in ('__DATA,__data', '__DATA,__bss', 'zero-fill (no file bytes)',
                         'Declared segment permissions: read write'):
                self.assertIn(text, result.stdout)
            # A real section must not point beyond the file.
            offset = (32 + 72 + 48) if wide else (28 + 56 + 40)
            invalid = bytearray(data)
            struct.pack_into('<I', invalid, offset, len(data))
            self.run_file(invalid, False)
            # Relocation records also need backing file bytes.
            invalid = bytearray(data)
            struct.pack_into('<II', invalid, offset + 8, len(data), 1)
            self.run_file(invalid, False)
        result = self.run_file(mach_sections(True, 129), True)
        self.assertNotIn('omitted', result.stdout)

    # Check text/version/string/image previews and malformed-content fallbacks.
    # Preview truncation must be explicit while the overall file remains reportable.
    def test_resource_payload_decoding(self):
        for payload in (b'<assembly>hello</assembly>',
                        b'\xff\xfe' + '<assembly>hello😀</assembly>'.encode('utf-16le'),
                        b'\xfe\xff' + '<assembly>hello</assembly>'.encode('utf-16be')):
            self.assertIn('Manifest text: <assembly>hello', self.run_file(resource_payload(payload), True).stdout)
        version = self.run_file(resource_payload(version_payload(), 16), True).stdout
        for text in ('File version: 1.2.3.4', 'Product version: 5.6.7.8', 'CompanyName=Coffin Test'):
            self.assertIn(text, version)
        strings = struct.pack('<H', 5) + 'hello'.encode('utf-16le') + bytes(30)
        self.assertIn('[16]=hello', self.run_file(resource_payload(strings, 6, 2), True).stdout)
        dib = struct.pack('<IiiHHIIIIII', 40, 16, 32, 1, 32, 0, 0, 0, 0, 0, 0)
        self.assertIn('DIB metadata: 16 x 32, 32 bits', self.run_file(resource_payload(dib, 2), True).stdout)
        for payload, kind in ((b'bad', 16), (b'\x01\0', 6), (b'bad', 2)):
            self.assertIn('Malformed or unsupported payload', self.run_file(resource_payload(payload, kind), True).stdout)
        result = self.run_file(resource_payload(('😀' * 800).encode()), True)
        self.assertIn('...', result.stdout)
        self.assertIn('Declared permissions:', result.stdout)

    # Verify exact raw bytes, private output modes, and rejection of existing or
    # symlink destinations. Non-PE input must not create an extraction directory.
    def test_resource_extraction(self):
        for image, expected in ((resource_payload(b'<assembly/>'), b'<assembly/>'),
                                (resource_payload(b'bad-version', 16), b'bad-version'),
                                (resource_payload(b''), b'')):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / 'input.exe'
                source.write_bytes(image)
                destination = root / 'resources'
                result = subprocess.run([BINARY, '--extract-resources', str(destination), str(source)],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                index = (destination / 'index.tsv').read_text().splitlines()
                name = index[1].split('\t')[0]
                self.assertEqual((destination / name).read_bytes(), expected)
                self.assertEqual((destination / name).stat().st_mode & 0o777, 0o600)
                # An existing directory must not be overwritten.
                result = subprocess.run([BINARY, '--extract-resources', str(destination), str(source)],
                                        capture_output=True)
                self.assertEqual(result.returncode, 1)
                self.assertEqual((destination / name).read_bytes(), expected)
                target = root / 'target'
                target.mkdir()
                link = root / 'link'
                link.symlink_to(target, target_is_directory=True)
                self.assertEqual(subprocess.run([BINARY, '--extract-resources', str(link), str(source)],
                                               capture_output=True).returncode, 1)
                self.assertEqual(list(target.iterdir()), [])
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / 'resources'
            result = subprocess.run([BINARY, '--extract-resources', str(out), str(ROOT / 'testmach')],
                                    capture_output=True)
            self.assertEqual(result.returncode, 1)
            self.assertFalse(out.exists())

    # Build 129 resource leaves sharing payload bytes and verify every entry is
    # extracted and indexed; old report limits must never truncate extraction.
    def test_extract_resources_beyond_report_limit(self):
        data = pe_details(True)
        data += bytes(8192 - (len(data) - 512))
        section = 64 + 24 + 112 + 24
        struct.pack_into('<I', data, section + 8, 8192)
        struct.pack_into('<I', data, section + 16, 8192)
        struct.pack_into('<I', data, 64 + 24 + 112 + 20, 4096)
        root = 512 + 0x400
        struct.pack_into('<I', data, root + 0x28, 1)  # Numeric resource name.
        struct.pack_into('<HH', data, root + 0x30 + 12, 0, 129)
        for index in range(129):
            record = 0x30 + 16 + 129 * 8 + index * 16
            struct.pack_into('<II', data, root + 0x40 + index * 8, 1033 + index, record)
            struct.pack_into('<IIII', data, root + record, 0x2f00, 4, 0, 0)
        data[512 + 0x1f00:512 + 0x1f04] = b'DATA'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, destination = root / 'input.exe', root / 'resources'
            source.write_bytes(data)
            result = subprocess.run([BINARY, '--extract-resources', str(destination), str(source)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('omitted', result.stdout)
            records = (destination / 'index.tsv').read_text().splitlines()[1:]
            self.assertEqual(len(records), 129)
            for record in records:
                self.assertEqual((destination / record.split('\t')[0]).read_bytes(), b'DATA')

    # Verify source/sample hashes, sample formats, and expected report features.
    # Execute only known-source samples compatible with this host, optionally using
    # installed Linux ARM emulators; arbitrary inspected files are never executed.
    def test_compiled_hello_samples(self):
        directory = ROOT / 'tests/samples'
        manifest = json.loads((directory / 'manifest.json').read_text())
        self.assertEqual(hashlib.sha256((directory / 'hello.c').read_bytes()).hexdigest(), manifest['source_sha256'])
        self.assertEqual(len(manifest['samples']), 9)
        for entry in manifest['samples']:
            with self.subTest(sample=entry['file']):
                path = ROOT / entry['file']
                data = path.read_bytes()
                self.assertEqual(len(data), entry['size'])
                self.assertEqual(hashlib.sha256(data).hexdigest(), entry['sha256'])
                self.assertIn(b'Hello from coffin!', data)
                result = self.run_file(data, True)
                name = entry['file']
                if 'elf32' in name or 'pe32' in name or name == 'hello-linux-arm32':
                    self.assertIn('Architecture: 32-bit', result.stdout)
                if 'elf64' in name or 'pe64' in name or name == 'hello-linux-arm64':
                    self.assertIn('Architecture: 64-bit', result.stdout)
                if name == 'hello-linux-arm32':
                    self.assertIn('Machine: 0x0028 (ARM)', result.stdout)
                    self.assertIn('ARM EABI version 5', result.stdout)
                if name == 'hello-linux-arm64':
                    self.assertIn('Machine: 0x00B7 (AArch64)', result.stdout)
                if 'pe' in name:
                    self.assertIn('KERNEL32.dll!WriteFile', result.stdout)
                if 'universal' in name:
                    self.assertIn('Architectures: 2', result.stdout)
                    self.assertIn('CPU 0x01000007', result.stdout)
                    self.assertIn('CPU 0x0100000C', result.stdout)
                # Run only the known-source fixture matching this host's architecture.
                native = (platform.system() == 'Darwin' and name == 'hello-mach-universal') or (
                    platform.system() == 'Linux' and platform.machine() in ('x86_64', 'amd64') and name == 'hello-elf64')
                machine = platform.machine().lower()
                if platform.system() == 'Linux':
                    native |= name == 'hello-linux-arm64' and machine in ('aarch64', 'arm64')
                    native |= name == 'hello-linux-arm32' and machine in ('armv7l', 'armv8l', 'arm')
                command = [str(path)] if native else None
                if not native and platform.system() == 'Linux' and name in ('hello-linux-arm32', 'hello-linux-arm64'):
                    emulator = shutil.which('qemu-arm' if name.endswith('32') else 'qemu-aarch64')
                    if emulator:
                        command = [emulator, str(path)]
                if command:
                    hello = subprocess.run(command, capture_output=True, text=True, timeout=5)
                    self.assertEqual(hello.returncode, 0, hello.stderr)
                    self.assertEqual(hello.stdout, 'Hello from coffin!\n')

    # Apply ELF32-specific offsets and entry sizes, reject malformed tables,
    # and accept the valid special case where both tables are absent.
    def test_elf32_bounds(self):
        original = (ROOT / 'hello-elf32').read_bytes()
        self.run_file(original[:51], False)
        for offset, fmt, value in ((28, '<I', 0xffffffff), (32, '<I', 0xffffffff),
                                   (42, '<H', 56), (46, '<H', 64)):
            data = bytearray(original)
            struct.pack_into(fmt, data, offset, value)
            self.run_file(data, False)
        # Valid ELF32 can omit both tables.
        data = bytearray(original[:52])
        struct.pack_into('<II', data, 28, 0, 0)
        struct.pack_into('<HHHHH', data, 42, 0, 0, 0, 0, 0)
        self.assertIn('Architecture: 32-bit', self.run_file(data, True).stdout)

    # Cover both table widths/orders, invalid offsets/alignment/CPU identity,
    # overlapping slices, reserved fields, and truncated architecture tables.
    def test_universal_mach_bounds(self):
        for wide in (False, True):
            for big in (False, True):
                data = universal_mach(wide, big)
                self.assertIn('Architectures: 2', self.run_file(data, True).stdout)
        original = universal_mach()
        # Out of range, table overlap, impossible alignment, mismatched CPU, truncated slice.
        for offset, value in ((16, 0xfffffff0), (16, 16), (24, 64), (8, 123), (20, 4)):
            data = bytearray(original)
            struct.pack_into('>I', data, offset, value)
            self.run_file(data, False)
        data = bytearray(original)
        # Point the second slice at the first slice (overlap).
        data[36:40] = data[16:20]
        self.run_file(data, False)
        data = universal_mach(True)
        struct.pack_into('>I', data, 36, 1)  # Reserved field must be zero.
        self.run_file(data, False)
        self.run_file(original[:30], False)

    # Exercise every ELF width/order/count combination and big-endian thin Mach-O.
    # An enormous extended count must fail before causing an unbounded allocation.
    def test_endianness_and_extended_numbering(self):
        for wide in (False, True):
            for big in (False, True):
                for extended in (False, True):
                    with self.subTest(wide=wide, big=big, extended=extended):
                        data = elf_variant(wide, big, extended)
                        result = self.run_file(data, True)
                        self.assertIn('Name: .text', result.stdout)
                        self.assertIn('Number of Program Headers: 1', result.stdout)
                        self.assertIn('Number of Section Headers: 3', result.stdout)
                        self.assertIn('Entry Point: 0x0000000000001000', result.stdout)
                        self.assertIn('big-endian' if big else 'little-endian', result.stdout)
                        self.run_file(data[:-1], False)
            self.assertIn('__DATA,__data', self.run_file(big_mach(wide), True).stdout)
        # Corrupt the extended count rather than allocating from untrusted metadata.
        data = bytearray(elf_variant(True, True, True))
        struct.pack_into('>Q', data, 64 + 56 + 32, 0xffffffffffffffff)
        self.run_file(data, False)

    # Inspect the reconstructed file's directory and embedded image offsets.
    # Missing group references should preserve raw extraction and mark reconstruction
    # unavailable, rather than inventing image data or failing unrelated resources.
    def test_icon_cursor_reconstruction(self):
        for cursor in (False, True):
            for missing in (False, True):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    source, output = root / 'input.exe', root / 'resources'
                    source.write_bytes(image_resources(cursor, missing))
                    result = subprocess.run([BINARY, '--extract-resources', str(output), str(source)],
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    records = (output / 'index.tsv').read_text().splitlines()[1:]
                    self.assertEqual(len(records), 3)
                    reconstructed = records[-1].split('\t')[-1]
                    if missing:
                        self.assertIn('unavailable', reconstructed)
                        self.assertTrue((output / records[-1].split('\t')[0]).exists())
                        continue
                    data = (output / reconstructed).read_bytes()
                    self.assertEqual(struct.unpack_from('<HHH', data), (0, 2 if cursor else 1, 2))
                    for index in range(2):
                        entry = struct.unpack_from('<BBBBHHII', data, 6 + index * 16)
                        self.assertEqual(entry[:2], (1, 1))
                        if cursor:
                            self.assertEqual(entry[4:6], (0, 0))
                        self.assertEqual(struct.unpack_from('<I', data, entry[7])[0], 40)
                        self.assertEqual(entry[7] + entry[6], len(data) if index == 1 else 6 + 32 + entry[6])

    # Use minimal accelerator/menu/dialog/message/HTML payloads with known values.
    # Truncated payloads should receive fallback previews while raw bytes remain usable.
    def test_expanded_resource_decoders(self):
        accelerator = struct.pack('<HHHH', 0x89, 65, 100, 0)
        self.assertIn('command=100 key=0x0041', self.run_file(resource_payload(accelerator, 9), True).stdout)
        menu = struct.pack('<HHHH', 0, 0, 0x80, 42) + 'Open\0'.encode('utf-16le')
        self.assertIn('[id=42] Open', self.run_file(resource_payload(menu, 4), True).stdout)
        extended_menu = struct.pack('<HHI', 1, 4, 0) + struct.pack('<IIIH', 0, 0, 77, 0x80) + 'Save\0'.encode('utf-16le')
        self.assertIn('[id=77', self.run_file(resource_payload(extended_menu, 4), True).stdout)
        dialog = struct.pack('<IIHhhhh', 0, 0, 0, 0, 0, 100, 100) + bytes(4) + 'Hello\0'.encode('utf-16le')
        self.assertIn('title=Hello', self.run_file(resource_payload(dialog, 5), True).stdout)
        text = 'Message\0'.encode('utf-16le')
        messages = struct.pack('<IIIIHH', 1, 42, 42, 16, len(text) + 4, 1) + text
        self.assertIn('[42]=Message', self.run_file(resource_payload(messages, 11), True).stdout)
        self.assertIn('HTML text: <b>Hello</b>', self.run_file(resource_payload(b'<b>Hello</b>', 23), True).stdout)
        for value, kind in ((accelerator[:-1], 9), (menu[:-1], 4), (dialog[:-1], 5), (messages[:-1], 11)):
            self.assertIn('Malformed or unsupported', self.run_file(resource_payload(value, kind), True).stdout)

    # Verify 17 program headers and 129 exports/sections print completely.
    # Assertions examine the last entries so a correct first row cannot mask truncation.
    def test_complete_tables(self):
        self.assertIn('Header 17:', self.run_file(elf_variant(programs=17), True).stdout)
        data = pe_details(True)
        struct.pack_into('<II', data, 512 + 20, 129, 0)
        struct.pack_into('<I', data, 512 + 28, 0x1800)
        for index in range(129):
            struct.pack_into('<I', data, 512 + 0x800 + index * 4, 0x1f00)
        result = self.run_file(data, True)
        self.assertIn('Exports: 129 entries', result.stdout)
        self.assertIn('Ordinal 135:', result.stdout)
        self.assertNotIn('omitted', result.stdout)
        result = self.run_file(mach_sections(True, 129), True)
        self.assertEqual(result.stdout.count('Declared segment permissions:'), 129)

    # Wrap a big-endian thin image in a universal container and ensure the nested
    # parser chooses the slice's byte order independently of the table.
    def test_mixed_endian_universal(self):
        body = big_mach(True)
        cpu, subtype = struct.unpack_from('>II', body, 4)
        header = struct.pack('>II5I', 0xcafebabe, 1, cpu, subtype, 32, len(body), 4)
        image = header + bytes(32 - len(header)) + body
        result = self.run_file(image, True)
        self.assertIn('Architectures: 1', result.stdout)
        self.assertIn('Byte Order: big-endian', result.stdout)

    # Verify standard/extended controls, fonts, signed coordinates, class ordinals,
    # wide IDs, and creation bytes. Truncating variable fields must yield a fallback.
    def test_dialog_control_decoding(self):
        for extended in (False, True):
            payload = dialog_controls(extended)
            result = self.run_file(resource_payload(payload, 5), True)
            for expected in ('font(size=9', 'Segoe UI', 'class=Button(#128)', 'class=Edit(#129)',
                             'title=Press', 'title=#55', 'rect=(-2,10,60,14)', 'creation-data=3 bytes 41 42 43'):
                self.assertIn(expected, result.stdout)
            self.assertIn('id=70000' if extended else 'id=100', result.stdout)
            self.assertNotIn('control bodies not decoded', result.stdout)
            for truncated in (payload[:-1], payload[:35], payload[:60]):
                self.assertIn('Malformed or unsupported', self.run_file(resource_payload(truncated, 5), True).stdout)

    # Check modern RVA and legacy VA descriptors, lookup-table fallback, invalid
    # addresses/attributes, and the requirement for a terminating null descriptor.
    def test_delay_load_imports(self):
        for wide, legacy in ((False, False), (True, False), (False, True)):
            image = delay_imports(wide, legacy)
            result = self.run_file(image, True)
            self.assertIn('Delay-load Imports: 2 symbols', result.stdout)
            self.assertIn('DELAY.dll!DelayedFunction (hint 7, delay-load)', result.stdout)
            self.assertIn('DELAY.dll!#42 (ordinal, delay-load)', result.stdout)
            fallback = bytearray(image)
            struct.pack_into('<I', fallback, 512 + 0xb10, 0)
            self.assertIn('DelayedFunction', self.run_file(fallback, True).stdout)
            for offset, value in ((512 + 0xb00, 2), (512 + 0xb04, 0xfffffff0), (512 + 0xb10, 0xfffffff0)):
                invalid = bytearray(image)
                struct.pack_into('<I', invalid, offset, value)
                self.run_file(invalid, False)
            # No descriptor terminator inside the declared directory.
            fixed = 112 if wide else 96
            struct.pack_into('<I', image, 64 + 24 + fixed + 13 * 8 + 4, 32)
            self.run_file(image, False)

    # Verify declared legacy encodings, invalid/unsupported-page fallbacks, and
    # --code-page handling when resource metadata leaves the encoding unspecified.
    def test_legacy_code_pages(self):
        for codepage, text, encoding in ((1252, 'Café €', 'cp1252'), (1251, 'Привет', 'cp1251'),
                                         (932, '日本語', 'cp932'), (936, '中文', 'gbk')):
            encoded = text.encode(encoding) + b'\0'
            message = struct.pack('<IIIIHH', 1, 42, 42, 16, len(encoded) + 4, 0) + encoded
            image = resource_payload(message, 11)
            struct.pack_into('<I', image, 512 + 0x450, codepage)
            self.assertIn(text, self.run_file(image, True).stdout)
        image = resource_payload(b'<b>Caf\xe9</b>', 23)
        struct.pack_into('<I', image, 512 + 0x450, 1252)
        self.assertIn('HTML text: <b>Café</b>', self.run_file(image, True).stdout)
        struct.pack_into('<I', image, 512 + 0x450, 99999)
        self.assertIn('unsupported code page 99999', self.run_file(image, True).stdout)
        image = resource_payload(b'\xff', 23)
        struct.pack_into('<I', image, 512 + 0x450, 65001)
        self.assertIn('invalid code page 65001 sequence', self.run_file(image, True).stdout)
        # An explicit CLI fallback resolves resources whose code-page field is zero.
        image = resource_payload(b'Caf\xe9', 23)
        struct.pack_into('<I', image, 512 + 0x450, 0)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'input.exe'
            path.write_bytes(image)
            result = subprocess.run([BINARY, '--code-page', '1252', str(path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('HTML text: Café', result.stdout)
            for value in ('0', '-1', 'abc', '4294967296'):
                self.assertEqual(subprocess.run([BINARY, '--code-page', value, str(path)], capture_output=True).returncode, 1)

    # Run arbitrary report options against a temporary byte image.
    # Unlike run_file, do not force verbose output or assume success.
    def report_file(self, data, *options):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'input'
            path.write_bytes(data)
            return subprocess.run([BINARY, *options, str(path)], capture_output=True, text=True)

    # Verify default, summary, and combined detail selectors across all formats.
    # Unsupported selectors and summary/detail conflicts must fail before reporting.
    def test_compact_reports_and_selection(self):
        for filename, selector, heading in (
                ('hello-pe64.exe', '--sections', 'PE sections ('),
                ('hello-elf64', '--program-headers', 'ELF program headers ('),
                ('hello-mach-universal', '--load-commands', 'Mach-O load commands:')):
            data = (ROOT / filename).read_bytes()
            normal = self.report_file(data)
            self.assertEqual(normal.returncode, 0, normal.stderr)
            self.assertEqual(normal.stderr, '')
            self.assertIn('Summary:', normal.stdout)
            self.assertIn('Structural observations:', normal.stdout)
            self.assertNotIn('Full field details:', normal.stdout)
            summary = self.report_file(data, '--summary')
            self.assertEqual(summary.returncode, 0, summary.stderr)
            self.assertNotIn(heading, summary.stdout)
            self.assertIn(hashlib.sha256(data).hexdigest(), summary.stdout)
            selected = self.report_file(data, selector)
            self.assertEqual(selected.returncode, 0, selected.stderr)
            self.assertIn(heading, selected.stdout)
            self.assertNotIn('Structural observations:', selected.stdout)
        data = pe_details(True)
        selected = self.report_file(data, '--imports', '--exports')
        self.assertIn('PE imports (', selected.stdout)
        self.assertIn('PE exports (', selected.stdout)
        self.assertNotIn('PE sections (', selected.stdout)
        self.assertNotIn('PE resources (', selected.stdout)
        for data, options in ((data, ['--program-headers']),
                              (elf_variant(), ['--imports']), (mach_sections(True), ['--resources']),
                              (data, ['--summary', '--sections'])):
            result = self.report_file(data, *options)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn('Analysis Report', result.stdout)

    # Ensure --no-preview hides decoded contents in compact, filtered, and verbose
    # views while retaining resource metadata such as type/name/language.
    def test_preview_suppression(self):
        image = resource_payload(b'<assembly>report-test</assembly>')
        for options in ([], ['--resources'], ['--verbose'], ['--verbose', '--resources']):
            result = self.report_file(image, *options)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('Manifest text:', result.stdout)
            suppressed = self.report_file(image, *options, '--no-preview')
            self.assertEqual(suppressed.returncode, 0, suppressed.stderr)
            self.assertNotIn('Manifest text:', suppressed.stdout)
            self.assertIn('MANIFEST(#24)', suppressed.stdout)

    # Construct explicit write/execute, high-entropy, and invalid-entry findings.
    # Moving entry addresses or changing ELF role checks when each finding applies.
    def test_structural_observations(self):
        data = pe_details(True)
        struct.pack_into('<I', data, 64 + 24 + 112 - 4, 0)
        section = 64 + 24 + 112 + 24
        struct.pack_into('<I', data, section + 36, 0xe0000020)
        struct.pack_into('<I', data, 64 + 24 + 16, 0x1000)
        data[512:] = bytes(range(256)) * 16
        result = self.report_file(data, '--summary')
        self.assertIn('[WX]', result.stdout)
        self.assertIn('[ENTROPY]', result.stdout)
        self.assertNotIn('[ENTRY]', result.stdout)
        struct.pack_into('<I', data, 64 + 24 + 16, 0x5000)
        self.assertIn('[ENTRY]', self.report_file(data, '--summary').stdout)
        elf = bytearray(elf_variant())
        struct.pack_into('<I', elf, 64 + 4, 7)
        struct.pack_into('<Q', elf, 24, 0x5000)
        result = self.report_file(elf, '--summary')
        self.assertIn('[WX]', result.stdout)
        self.assertIn('[ENTRY]', result.stdout)
        # Relocatable objects do not require a process entry point.
        struct.pack_into('<H', elf, 16, 1)
        self.assertNotIn('[ENTRY]', self.report_file(elf, '--summary').stdout)
        self.assertIn('not malware verdicts', result.stdout)

    # Insert LC_MAIN, adjust affected offsets, and check entry reporting.
    # Removing the containing segment's execute bit should trigger an entry finding.
    def test_mach_entry_report(self):
        data = bytearray(mach_sections(True))
        original_commands = struct.unpack_from('<I', data, 20)[0]
        payload = 32 + original_commands
        data[payload:payload] = struct.pack('<IIQQ', 0x80000028, 24, payload + 24, 0)
        struct.pack_into('<II', data, 16, 2, original_commands + 24)
        struct.pack_into('<Q', data, 32 + 48, len(data))
        struct.pack_into('<I', data, 32 + 60, 7)
        struct.pack_into('<I', data, 32 + 72 + 48, payload + 24)
        result = self.report_file(data)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('LC_MAIN', result.stdout)
        self.assertIn('Entry point: LC_MAIN slice file offset', result.stdout)
        self.assertIn('[WX]', result.stdout)
        self.assertNotIn('[ENTRY]', result.stdout)
        struct.pack_into('<I', data, 32 + 60, 3)
        self.assertIn('[ENTRY]', self.report_file(data, '--summary').stdout)

    # Reject empty, truncated-signature, and unknown files without unsafe reads.
    def test_short_files(self):
        for data in (b'', b'MZ00', b'\x7fELF', b'\xcf\xfa\xed\xfe', b'????'):
            self.run_file(data, False)


if __name__ == '__main__':
    unittest.main()

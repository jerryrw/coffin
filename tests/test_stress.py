"""Bounded adversarial tests: amplification, count boundaries, and ambiguous ranges.

Use summary output for large tables. Each process has a timeout; rejected cases
are run twice to check stable status/diagnostics and no partial report. Valid
controls guard against rejecting every unusual input just to satisfy the tests.
"""
import hashlib
import csv
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import unittest
from fixtures import elf_variant
from stress_fixtures import aliased_pe, elf_dynamic_aliases, elf_index_scans, mach_commands, universal_names, pe_resource_aliases, pe_resource_chain, pe_resource_graph

BINARY = str(Path(sys.argv.pop(1)).resolve())


class StressTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.source = Path(self.temporary.name) / 'input.bin'

    def inspect(self, data, status=0, options=('--summary',)):
        self.source.write_bytes(data)
        result = subprocess.run([BINARY, *options, str(self.source)],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, status, result.stderr)
        self.assertEqual('Analysis Report' in result.stdout, status == 0)
        self.assertNotRegex(result.stderr, r'Sanitizer|runtime error:')
        # Summaries must remain small even for six-figure tables. This bounds
        # observed output, independently of elapsed-time differences across CI.
        self.assertLess(len(result.stdout), 16384)
        if status == 0:
            self.assertIn(hashlib.sha256(data).hexdigest(), result.stdout)
        else:
            self.assertEqual(result.stdout, '')
        return result

    def reject(self, data, diagnostic, options=("--summary",)):
        first = self.inspect(data, 1, options)
        second = self.inspect(data, 1, options)
        self.assertIn(diagnostic, first.stderr)
        self.assertEqual(first.stderr, second.stderr)
        return first

    def test_command_count_boundary(self):
        self.assertIn('Counts: 100000 load commands', self.inspect(mach_commands(100000)).stdout)
        self.reject(mach_commands(100001), 'Parser resource limit exceeded: table entries or allocation bytes')

    def test_extended_elf_program_count_boundary(self):
        self.assertIn('Counts: 100000 program headers',
                      self.inspect(elf_variant(extended=True, programs=100000)).stdout)
        self.reject(elf_variant(extended=True, programs=100001),
                    'Parser resource limit exceeded: table entries or allocation bytes')

    def test_repeated_names_share_metadata_budget_across_slices(self):
        self.inspect(universal_names(1, 32, 4095))
        self.reject(universal_names(4, 4000, 4095), 'Parser resource limit exceeded: metadata reads')

    def test_repeated_raw_ranges_reuse_entropy_cache(self):
        data = aliased_pe(2048)
        for options, extra, ranges in ((('--headers', '--verbose'), 0, 1),
                                       (('--summary', '--verbose'), 4096, 2)):
            result = self.inspect(data, options=options)
            match = re.search(r'Entropy work: (\d+) bytes read \| (\d+) cached ranges', result.stdout)
            self.assertIsNotNone(match, result.stdout)
            self.assertEqual(tuple(map(int, match.groups())), (len(data) + extra, ranges))

    def test_overlapping_pe_rvas_are_ambiguous(self):
        self.inspect(aliased_pe(2))
        self.reject(aliased_pe(2, overlapping_rvas=True), 'Invalid')

    def test_overlapping_elf_loads_are_ambiguous_for_dynamic_addresses(self):
        self.assertIn('libstress.so', self.inspect(elf_dynamic_aliases(1), options=('--dependencies',)).stdout)
        self.reject(elf_dynamic_aliases(2), 'Invalid')

    def test_adjacent_universal_slices_and_one_byte_overlap(self):
        data = bytearray(universal_names(2, 1))
        self.inspect(data)
        # The first slice grows into the next by exactly one byte.
        size = struct.unpack_from('>I', data, 20)[0]
        struct.pack_into('>I', data, 20, size + 1)
        self.reject(data, 'Invalid')

    def test_extended_index_lookup_work_is_bounded(self):
        self.inspect(elf_index_scans(32))
        self.reject(elf_index_scans(3000), 'Parser resource limit exceeded:')


    def reject_resource(self, data, reason):
        # Parsing must fail before extraction creates any output. A second run
        # uses the same destination to catch stray output from the first failure.
        destination = Path(self.temporary.name) / 'rejected-resources'
        result = self.reject(data, reason,
                             ('--summary', '--extract-resources', str(destination)))
        self.assertEqual(result.stderr.splitlines()[0], reason)
        self.assertEqual(result.stderr.splitlines().count(reason), 1)
        self.assertFalse(destination.exists())

    def assert_resource_count(self, data, count):
        output = self.inspect(data).stdout
        found = re.search(r'^Counts:.*\| (\d+) resources$', output, re.M)
        self.assertIsNotNone(found, output)
        self.assertEqual(int(found.group(1)), count)

    def test_pe_resource_directory_depth_boundary(self):
        # Root counts as level one; depth indices 0 through 15 are accepted.
        for wide in (False, True):
            with self.subTest(wide=wide):
                self.assert_resource_count(pe_resource_graph([[]], wide), 0)
                for levels in (1, 3, 16):
                    self.assert_resource_count(pe_resource_chain(levels, wide), 1)
                output = self.inspect(pe_resource_chain(16, wide), options=('--resources',)).stdout
                self.assertIn('RCDATA(#10)' + '/#1' * 15, output)
                self.reject_resource(pe_resource_chain(17, wide),
                    'Parser resource limit exceeded: PE resource directory depth (16 levels)')

    def test_pe_resource_ancestor_cycles(self):
        for wide in (False, True):
            for levels, ancestor in ((1, 0), (3, 0), (3, 1), (3, 2)):
                with self.subTest(wide=wide, levels=levels, ancestor=ancestor):
                    self.reject_resource(pe_resource_chain(levels, wide, cycle_to=ancestor),
                                         'Invalid PE resource directory: ancestor cycle')

    def test_pe_resource_repeated_data_read_boundary(self):
        # Two directory edges + three headers + two reads per leaf = 5 + 2*N.
        # 2045 leaves need 4095 reads; leaf 2046 would need 4097, beyond 4096.
        for wide in (False, True):
            with self.subTest(wide=wide):
                self.assert_resource_count(pe_resource_aliases(leaves=2045, wide=wide), 2045)
                self.reject_resource(pe_resource_aliases(leaves=2046, wide=wide),
                    'Parser resource limit exceeded: PE resource directory reads (4096)')

    def test_pe_resource_shared_subtree_read_boundary(self):
        # Shared subtrees are not cycles. Each traversal must still be charged:
        # root/name headers and root edge need 3 reads, then 4 per name branch.
        for wide in (False, True):
            with self.subTest(wide=wide):
                output = self.inspect(pe_resource_aliases(branches=2, wide=wide),
                                      options=('--resources',)).stdout
                for name in (1, 2):
                    self.assertIn(f'RCDATA(#10)/#{name}/#1033', output)
                self.assert_resource_count(pe_resource_aliases(branches=1023, wide=wide), 1023)
                self.reject_resource(pe_resource_aliases(branches=1024, wide=wide),
                    'Parser resource limit exceeded: PE resource directory reads (4096)')

    def test_pe_resource_reference_amplification(self):
        for wide in (False, True):
            with self.subTest(wide=wide):
                self.assert_resource_count(pe_resource_aliases(branches=2, leaves=2, wide=wide), 4)
                # Only 145 directory entries, but repeated traversal needs 4131
                # reads. Charging unique offsets would miss this amplification.
                data = pe_resource_aliases(branches=16, leaves=128, wide=wide)
                self.assertLess(len(data), 2048)
                self.reject_resource(data,
                    'Parser resource limit exceeded: PE resource directory reads (4096)')

    def test_pe_resource_shared_references_extract_independently(self):
        for wide in (False, True):
            with self.subTest(wide=wide):
                destination = Path(self.temporary.name) / f'extracted-{wide}'
                self.inspect(pe_resource_aliases(branches=2, leaves=2, wide=wide),
                             options=('--summary', '--extract-resources', str(destination)))
                with (destination / 'index.tsv').open() as index:
                    rows = list(csv.DictReader(index, delimiter='\t'))
                self.assertEqual(len(rows), 4)
                self.assertEqual(len({row['file'] for row in rows}), 4)
                self.assertEqual(len({row['rva'] for row in rows}), 1)
                self.assertEqual({row['resource_path'] for row in rows},
                                 {f'RCDATA(#10)/#{name}/#{language}'
                                  for name in (1, 2) for language in (1033, 1034)})
                self.assertEqual(len(list(destination.iterdir())), 5)
                for row in rows:
                    self.assertEqual(row['size'], '4')
                    self.assertEqual((destination / row['file']).read_bytes(), b'DATA')


if __name__ == '__main__':
    unittest.main()

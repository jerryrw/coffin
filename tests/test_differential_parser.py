"""Regression coverage for differences between GNU and LLVM readelf output."""
import unittest
from test_differential import readelf_programs


class ReadelfProgramsTests(unittest.TestCase):
    def test_gnu_zero_alignment(self):
        output = '''
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  PHDR           0x000034 0x00400034 0x00400034 0x00080 0x00080 R   0x4
  LOAD           0x0000d0 0x004010d0 0x004010d0 0x00026 0x00026 R E 0x1000
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0
'''
        self.assertEqual(readelf_programs(output), [
            ('PHDR', 52, 0x400034, 128, 128, 'R'),
            ('LOAD', 208, 0x4010d0, 38, 38, 'RE'),
            ('GNU_STACK', 0, 0, 0, 0, 'RW')])
        self.assertEqual(readelf_programs(output.replace('RW  0\n', 'RW  0x0\n')),
                         readelf_programs(output))

    def test_empty_flags_and_64_bit_addresses(self):
        self.assertEqual(readelf_programs(
            '  LOAD 0x000000 0x0000000100400000 0x0000000100400000 0x20 0x40     0x1000'),
            [('LOAD', 0, 0x100400000, 32, 64, '')])


if __name__ == '__main__':
    unittest.main()

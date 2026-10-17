"""Independent, tiny ELF/Mach-O linkage tables for width/order/error tests."""
import struct


def elf_linkage(wide=True, big=False, stripped=False, gnu=False, extended_indices=False):
    e = '>' if big else '<'
    eh, ph, sh, sy = (64, 56, 64, 24) if wide else (52, 32, 40, 16)
    strings = b'\0libsample.so\0imported\0exported\0'
    def sym(name, value=0, section=0):
        values = (name, 0x12, 0, section, value, 4) if wide else (name, value, 4, 0x12, 0, section)
        return struct.pack(e + ('IBBHQQ' if wide else 'IIIBBH'), *values)
    symbols = bytes(sy) + sym(strings.index(b'imported')) + sym(strings.index(b'exported'), 0x1000, 0xffff if extended_indices else 1)
    def dyn(tag, value):
        return struct.pack(e + ('QQ' if wide else 'II'), tag, value)
    if stripped:
        string_offset = eh + 2 * ph
        symbol_offset = string_offset + len(strings)
        hash_offset = symbol_offset + len(symbols)
        hashes = (struct.pack(e + '4I', 1, 1, 1, 0) + bytes(8 if wide else 4) + struct.pack(e + '3I', 1, 2, 3)
                  if gnu else struct.pack(e + '6I', 1, 3, 0, 0, 0, 0))
        dynamic_offset = hash_offset + len(hashes)
        dynamic = b''.join(dyn(t, v) for t, v in [(1, 1), (5, 0x1000 + string_offset), (10, len(strings)),
                          (6, 0x1000 + symbol_offset), (11, sy), (0x6ffffef5 if gnu else 4, 0x1000 + hash_offset), (0, 0)])
        total = dynamic_offset + len(dynamic)
        def program(kind, offset, size):
            values = (kind, 4, offset, 0x1000 + offset, 0, size, size, 1) if wide else (kind, offset, 0x1000 + offset, 0, size, size, 4, 1)
            return struct.pack(e + ('IIQQQQQQ' if wide else '8I'), *values)
        programs = program(1, 0, total) + program(2, dynamic_offset, len(dynamic))
        payload = programs + strings + symbols + hashes + dynamic
        phoff, shoff, phnum, shnum = eh, 0, 2, 0
    else:
        section_count = 5 if extended_indices else 4
        string_offset = eh + section_count * sh
        symbol_offset = string_offset + len(strings)
        dynamic_offset = symbol_offset + len(symbols)
        dynamic = dyn(1, 1) + dyn(0, 0)
        def section(kind, offset, size, link=0, entry=0):
            return struct.pack(e + ('IIQQQQIIQQ' if wide else '10I'), 0, kind, 0, 0, offset, size, link, 0, 1, entry)
        payload = bytes(sh) + section(3, string_offset, len(strings)) + section(11, symbol_offset, len(symbols), 1, sy)
        payload += section(6, dynamic_offset, len(dynamic), 1, 16 if wide else 8)
        if extended_indices:
            payload += section(18, dynamic_offset + len(dynamic), 12, 2, 4)
        payload += strings + symbols + dynamic
        if extended_indices:
            payload += struct.pack(e + '3I', 0, 0, 3)
        phoff, shoff, phnum, shnum = 0, eh, 0, section_count
    ident = b'\x7fELF' + bytes([2 if wide else 1, 2 if big else 1, 1]) + bytes(9)
    header = struct.pack(e + ('16sHHIQQQIHHHHHH' if wide else '16sHHIIIIIHHHHHH'), ident, 3,
                         62 if wide else 3, 1, 0, phoff, shoff, 0, eh, ph if phnum else 0, phnum, sh if shnum else 0, shnum, 0)
    return header + payload


def mach_linkage(wide=True, big=False, bad=False):
    e = '>' if big else '<'
    header_size, symbol_size = (32, 16) if wide else (28, 12)
    name = b'/usr/lib/libExample.dylib\0'
    command_size = (24 + len(name) + 7) // 8 * 8
    dependency = struct.pack(e + '6I', 0x80000018, command_size, 24, 0, 0x10002, 0x10000)
    dependency += name + bytes(command_size - 24 - len(name))
    strings = b'\0_imported\0_alias\0_target\0'
    symbol_offset = header_size + command_size + 24
    string_offset = symbol_offset + 2 * symbol_size
    table = struct.pack(e + '6I', 2, 24, symbol_offset, 2, string_offset, len(strings))
    symbols = struct.pack(e + ('IBBHQ' if wide else 'IBBHI'), 1, 1, 0, 0x100, 0)
    symbols += struct.pack(e + ('IBBHQ' if wide else 'IBBHI'), strings.index(b'_alias'), 0xb, 0, 0, strings.index(b'_target'))
    header = struct.pack(e + ('8I' if wide else '7I'), 0xfeedfacf if wide else 0xfeedface,
                         0x1000007 if wide else 7, 3, 2, 2, command_size + 24, 0, *([0] if wide else []))
    return header + dependency + table + symbols + strings

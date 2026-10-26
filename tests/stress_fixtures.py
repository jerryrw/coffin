"""Synthetic inputs that amplify parser work; never execute these as programs.

Large cases are built in temporary directories by test_stress.py. Small variants
can be frozen in the permanent corpus with checksums and expected behavior.
"""
import struct


def mach_commands(count):
    header = struct.pack('<8I', 0xfeedfacf, 0x1000007, 0, 2, count, count * 8, 0, 0)
    # Unknown commands are retained as metadata; each still has a valid size.
    return header + struct.pack('<2I', 0x77777777, 8) * count


def universal_names(slices, symbols, name_size=0):
    entries, payload = [], bytearray()
    start = 8 + slices * 20
    for index in range(slices):
        header = struct.pack('<8I', 0xfeedfacf, 0x1000007, index, 2, 1, 24, 0, 0)
        names = b'A' * name_size + b'\0'
        command = struct.pack('<6I', 2, 24, 56, symbols, 56 + symbols * 16, len(names))
        # Every symbol references the same terminated string, multiplying reads
        # without multiplying source-file bytes. Subtypes distinguish the slices.
        thin = header + command + bytes(symbols * 16) + names
        entries.append(struct.pack('>5I', 0x1000007, index, start + len(payload), len(thin), 0))
        payload.extend(thin)
    return struct.pack('>2I', 0xcafebabe, slices) + b''.join(entries) + payload


def aliased_pe(sections, overlapping_rvas=False):
    dos = bytearray(64)
    dos[:2] = b'MZ'
    struct.pack_into('<I', dos, 60, 64)
    optional = bytearray(112)
    struct.pack_into('<H', optional, 0, 0x10b)
    struct.pack_into('<I', optional, 16, 0x1000)
    struct.pack_into('<I', optional, 28, 0x400000)
    offset = (64 + 24 + len(optional) + sections * 40 + 511) & ~511
    struct.pack_into('<I', optional, 60, offset)
    rva_base = (offset + 4095) & ~4095
    struct.pack_into('<I', optional, 16, rva_base)
    struct.pack_into('<I', optional, 92, 2)
    struct.pack_into('<II', optional, 104, rva_base, 20)  # Empty import descriptor.
    header = dos + b'PE\0\0' + struct.pack('<HHIIIHH', 0x14c, sections, 0, 0, 0, len(optional), 0x102) + optional
    for index in range(sections):
        # Raw file aliases are inspectable; overlapping RVA mappings are ambiguous.
        rva = rva_base if overlapping_rvas else rva_base + index * 0x1000
        header += struct.pack('<8sIIIIIIHHI', b'.text', 4096, rva, 4096, offset, 0, 0, 0, 0, 0x60000020)
    return header + bytes(offset - len(header)) + bytes(4096)


def elf_dynamic_aliases(loads):
    phnum = loads + 1
    strings = b'\0libstress.so\0'
    string_offset = 64 + phnum * 56
    dynamic_offset = string_offset + len(strings)
    dynamic = b''.join(struct.pack('<QQ', tag, value) for tag, value in
                       ((5, 0x1000 + string_offset), (10, len(strings)), (1, 1), (0, 0)))
    total = dynamic_offset + len(dynamic)
    ident = b'\x7fELF' + bytes([2, 1, 1]) + bytes(9)
    header = struct.pack('<16sHHIQQQIHHHHHH', ident, 3, 62, 1, 0, 64, 0, 0, 64, 56, phnum, 0, 0, 0)
    load = struct.pack('<IIQQQQQQ', 1, 4, 0, 0x1000, 0, total, total, 1)
    program = struct.pack('<IIQQQQQQ', 2, 4, dynamic_offset, 0x1000 + dynamic_offset, 0, len(dynamic), len(dynamic), 1)
    return header + load * loads + program + strings + dynamic


def elf_index_scans(tables):
    # Each symbol table needs its own companion-index lookup. Reusing the raw
    # symbol/index bytes makes the file small while table scans grow quadratically.
    count = 2 + tables * 2
    data = 64 + count * 64
    ident = b'\x7fELF' + bytes([2, 1, 1]) + bytes(9)
    header = struct.pack('<16sHHIQQQIHHHHHH', ident, 1, 62, 1, 0, 0, 64, 0, 64, 0, 0, 64, count, 0)
    def section(kind, offset, size, link=0, width=0):
        return struct.pack('<IIQQQQIIQQ', 0, kind, 0, 0, offset, size, link, 0, 1, width)
    entries = bytes(64) + section(3, data, 1)
    entries += b''.join(section(2, data + 1, 24, 1, 24) for _ in range(tables))
    entries += b''.join(section(18, data + 25, 4, index + 2, 4) for index in range(tables))
    symbol = struct.pack('<IBBHQQ', 0, 0x12, 0, 0xffff, 0, 0)
    return header + entries + b'\0' + symbol + bytes(4)


def pe_resource_graph(nodes, wide=False):
    """Wrap a resource-directory graph in one PE section.

    Each node is a list of (numeric ID, target) pairs. An integer target names
    another directory node; None names the one shared data entry and DATA payload.
    References are directory-relative, while that data entry stores a payload RVA.
    """
    from fixtures import pe_details
    offsets, end = [], 0
    for entries in nodes:
        offsets.append(end)
        end += 16 + 8 * len(entries)
    tree = bytearray(end + 16)
    for offset, entries in zip(offsets, nodes):
        struct.pack_into('<IIHHHH', tree, offset, 0, 0, 0, 0, 0, len(entries))
        for index, (identifier, target) in enumerate(entries):
            reference = end if target is None else 0x80000000 | offsets[target]
            struct.pack_into('<II', tree, offset + 16 + index * 8, identifier, reference)
    payload = b'DATA'
    struct.pack_into('<IIII', tree, end, 0x1000 + len(tree), len(payload), 0, 0)
    image = bytearray(pe_details(wide)[:512])
    fixed = 112 if wide else 96
    # Discard the original import/export tables and point the resource directory
    # at our section's first byte. Keep payload bytes outside the directory range.
    struct.pack_into('<6I', image, 88 + fixed, 0, 0, 0, 0, 0x1000, len(tree))
    section = 88 + fixed + 24
    struct.pack_into('<I', image, section + 8, len(tree) + len(payload))
    struct.pack_into('<I', image, section + 16, len(tree) + len(payload))
    return image + tree + payload


def pe_resource_chain(directories, wide=False, cycle_to=None):
    nodes = [[(10 if index == 0 else 1,
               index + 1 if index + 1 < directories else cycle_to)]
             for index in range(directories)]
    return pe_resource_graph(nodes, wide)


def pe_resource_aliases(branches=1, leaves=1, wide=False):
    # Different resource names share one language directory. Within that directory,
    # different language IDs also share one data entry and one on-disk payload.
    nodes = [[(10, 1)], [(index + 1, 2) for index in range(branches)],
             [(1033 + index, None) for index in range(leaves)]]
    return pe_resource_graph(nodes, wide)

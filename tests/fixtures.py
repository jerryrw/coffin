# Synthetic binary builders: Python writes tiny files with known field values.
# struct.pack creates bytes; pack_into replaces bytes in an existing bytearray.
# In format strings, < means little-endian, > big-endian, H a 16-bit integer,
# I a 32-bit integer, and Q a 64-bit integer. s describes fixed-width byte strings.
# These are parser inputs, not programs that the tests execute. Tests mutate
# individual fields in fresh copies to verify that invalid inputs are rejected.

"""Small synthetic executable images with known directory and section contents."""
import struct
from linkage_fixtures import elf_linkage, mach_linkage


# Build one file-backed PE section with imports, exports, and a resource tree.
# wide selects PE32+; RVA 0x1000 maps to file byte 512, so a payload offset x
# has RVA 0x1000 + x and file offset 512 + x. Keep these coordinates distinct.
def pe_details(wide=False):
    fixed = 112 if wide else 96
    optional = bytearray(fixed + 24)
    struct.pack_into('<H', optional, 0, 0x20b if wide else 0x10b)
    struct.pack_into('<I', optional, 60, 512)
    struct.pack_into('<I', optional, fixed - 4, 3)
    for index, (rva, size) in enumerate(((0x1000, 0x100), (0x1200, 40), (0x1400, 0x200))):
        struct.pack_into('<II', optional, fixed + index * 8, rva, size)
    data = bytearray(64)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 60, 64)
    data += b'PE\0\0' + struct.pack('<HHIIIHH', 0x8664 if wide else 0x14c,
                                     1, 0, 0, 0, len(optional), 0)
    data += optional + struct.pack('<8sIIIIIIHHI', b'.rdata', 4096, 4096, 4096, 512, 0, 0, 0, 0, 0x40000040)
    data += bytes(512 - len(data))
    payload = bytearray(4096)
    # One named export, one forwarded ordinal-only export, one direct ordinal-only export.
    struct.pack_into('<IIHHIIIIIII', payload, 0, 0, 0, 0, 0, 0x1080, 7, 3, 1, 0x1040, 0x1050, 0x1060)
    struct.pack_into('<III', payload, 0x40, 0x1800, 0x10a0, 0x1810)
    struct.pack_into('<I', payload, 0x50, 0x1090)
    struct.pack_into('<H', payload, 0x60, 0)
    for offset, value in ((0x80, b'sample.dll\0'), (0x90, b'Exported\0'), (0xa0, b'OTHER.Forwarded\0'),
                          (0x280, b'KERNEL32.dll\0'), (0x2a0, b'\x05\0CreateFileA\0')):
        payload[offset:offset + len(value)] = value
    struct.pack_into('<IIIII', payload, 0x200, 0x1240, 0, 0, 0x1280, 0x1260)
    thunk = struct.pack('<QQQ' if wide else '<III', 0x12a0, (1 << (63 if wide else 31)) | 12, 0)
    payload[0x240:0x240 + len(thunk)] = thunk
    payload[0x260:0x260 + len(thunk)] = thunk
    for offset in (0x400, 0x418, 0x430):
        struct.pack_into('<IIHHHH', payload, offset, 0, 0, 0, 0, 0, 1)
    struct.pack_into('<II', payload, 0x410, 10, 0x80000018)
    struct.pack_into('<II', payload, 0x428, 0x80000090, 0x80000030)
    struct.pack_into('<II', payload, 0x440, 1033, 0x48)
    struct.pack_into('<IIII', payload, 0x448, 0x1700, 4, 65001, 0)
    name = 'greeting😀'.encode('utf-16le')
    struct.pack_into('<H', payload, 0x490, len(name) // 2)
    payload[0x492:0x492 + len(name)] = name
    payload[0x700:0x704] = b'DATA'
    return data + payload


# Build a segment with one DATA payload and remaining zero-fill sections.
# The command's length includes every section header; the payload follows it.
# wide changes header/field widths without changing the intended test contents.
def mach_sections(wide=False, count=2):
    fixed, width, header_size = (72, 80, 32) if wide else (56, 68, 28)
    command_size = fixed + count * width
    file_size = header_size + command_size + 4
    header = struct.pack('<8I' if wide else '<7I', 0xfeedfacf if wide else 0xfeedface,
                         0x1000007 if wide else 7, 3, 2, 1, command_size, 0, *([0] if wide else []))
    segment = struct.pack('<II16s' + ('QQQQ' if wide else 'IIII') + 'IIII',
                          0x19 if wide else 1, command_size, b'__DATA', 0x1000,
                          0x1000 + count * 16, 0, file_size, 7, 3, count, 0)
    sections = bytearray()
    for index in range(count):
        zero = index > 0
        values = [b'__bss' if zero else b'__data', b'__DATA', 0x1000 + index * 16,
                  16 if zero else 4, 0 if zero else header_size + command_size,
                  2, 0, 0, 1 if zero else 0, 0, 0]
        if wide:
            values.append(0)
        sections += struct.pack('<16s16s' + ('QQ' if wide else 'II') + ('8I' if wide else '7I'), *values)
    return header + segment + sections + b'DATA'


# Return named, valid examples that reach deeper parser/decoder code.
# Random bytes often fail at the signature; mutating these inputs explores
# valid tables as well as their boundary and error cases.
def fuzz_seeds():
    return {
        'linkage-elf32-big': elf_linkage(False, True),
        'linkage-elf64-stripped-sysv': elf_linkage(True, False, True),
        'linkage-elf64-stripped-gnu': elf_linkage(True, True, True, True),
        'linkage-mach32-big': mach_linkage(False, True),
        'linkage-mach64': mach_linkage(),
        'directories-pe32': pe_details(False),
        'directories-pe64': pe_details(True),
        'sections-mach32': mach_sections(False),
        'sections-mach64': mach_sections(True),
        'universal-mach32': universal_mach(),
        'universal-mach64': universal_mach(True),
        'elf32-big': elf_variant(False, True),
        'elf64-big-extended': elf_variant(True, True, True),
        'mach32-big': big_mach(False),
        'mach64-big': big_mach(True),
        'resource-icons': image_resources(),
        'resource-cursors': image_resources(True),
        'delay-pe32': delay_imports(),
        'delay-pe64': delay_imports(True),
        'delay-legacy-pe32': delay_imports(False, True),
        'dialog-standard': resource_payload(dialog_controls(), 5),
        'dialog-extended': resource_payload(dialog_controls(True), 5),
        'legacy-message-cp1252': legacy_message(),
        'payload-manifest': resource_payload(b'<assembly>hello</assembly>'),
        'payload-version': resource_payload(version_payload(), 16),
        'payload-strings': resource_payload(struct.pack('<H', 5) + 'hello'.encode('utf-16le') + bytes(30), 6),
    }




# Replace the existing PE fixture's resource type/name and leaf payload.
# If necessary, enlarge the section's memory/raw sizes to contain the new bytes.
# The tree stays at the same offsets so tests can focus on payload decoding.
def resource_payload(payload, type_id=24, name_id=1):
    image = pe_details(True)
    struct.pack_into('<I', image, 512 + 0x410, type_id)
    struct.pack_into('<I', image, 512 + 0x428, name_id)
    struct.pack_into('<I', image, 512 + 0x44c, len(payload))
    if len(payload) > len(image) - (512 + 0x700):
        image += bytes(len(payload) - (len(image) - (512 + 0x700)))
        section = 64 + 24 + 112 + 24
        struct.pack_into('<II', image, section + 8, len(image) - 512, 0x1000)
        struct.pack_into('<I', image, section + 16, len(image) - 512)
    image[512 + 0x700:512 + 0x700 + len(payload)] = payload
    return image


# Construct nested VS_VERSION_INFO with known numeric and text versions.
# Lengths and four-byte padding are generated here, not copied from parser code.
def version_payload():
    # Build one version block, aligning its value and children to four bytes.
    # Python's -len(data) % 4 calculates how many padding bytes are needed.
    # Text value lengths count UTF-16 units; binary value lengths count bytes.
    def block(key, value, kind, children=()):
        data = bytearray(6) + key.encode('utf-16le') + b'\0\0'
        data += bytes(-len(data) % 4)
        data += value
        for child in children:
            data += bytes(-len(data) % 4)
            data += child
        struct.pack_into('<HHH', data, 0, len(data), len(value) // 2 if kind else len(value), kind)
        return data
    string = block('CompanyName', 'Coffin Test\0'.encode('utf-16le'), 1)
    table = block('040904B0', b'', 1, [string])
    strings = block('StringFileInfo', b'', 1, [table])
    fixed = struct.pack('<13I', 0xfeef04bd, 0x10000, 0x10002, 0x30004, 0x50006, 0x70008,
                        0x3f, 0, 0x40004, 1, 0, 0, 0)
    return block('VS_VERSION_INFO', fixed, 0, [strings])


# Wrap two thin images in a FAT32/FAT64 table in either byte order.
# Place each body on a 16-byte boundary and record that as alignment exponent 4.
# The wrapper byte order is independent of the thin-image byte orders.
def universal_mach(wide=False, big=True):
    slices = [mach_sections(False), mach_sections(True)]
    endian = '>' if big else '<'
    width = 32 if wide else 20
    data = bytearray(struct.pack(endian + 'II', 0xcafebabf if wide else 0xcafebabe, len(slices)))
    data += bytes(width * len(slices))
    for index, body in enumerate(slices):
        data += bytes(-len(data) % 16)
        offset = len(data)
        cpu, subtype = struct.unpack_from('<II', body, 4)
        fields = [cpu, subtype, offset, len(body), 4]
        if wide:
            fields.append(0)
        struct.pack_into(endian + ('IIQQII' if wide else 'IIIII'), data, 8 + index * width, *fields)
        data += body
    return data


# Build a tiny ELF image with a LOAD header, .text, and a name string table.
# wide, big, and extended independently choose width, byte order, and extended
# header numbering. programs can exceed historical display limits.
def elf_variant(wide=True, big=False, extended=False, programs=1):
    endian = '>' if big else '<'
    eh, ph, sh = (64, 56, 64) if wide else (52, 32, 40)
    sections = eh + ph * programs
    names = b'\0.text\0.shstrtab\0'
    name_offset = sections + 3 * sh
    text_offset = name_offset + len(names)
    ident = b'\x7fELF' + bytes([2 if wide else 1, 2 if big else 1, 1]) + bytes(9)
    header = struct.pack(endian + ('16sHHIQQQIHHHHHH' if wide else '16sHHIIIIIHHHHHH'),
                         ident, 2, 62 if wide else 3, 1, 0x1000, eh, sections, 0, eh,
                         ph, 0xffff if extended else programs, sh, 0 if extended else 3, 0xffff if extended else 2)
    program = struct.pack(endian + ('IIQQQQQQ' if wide else 'IIIIIIII'),
                          *([1, 5, text_offset, 0x1000, 0x1000, 4, 4, 4] if wide else
                            [1, text_offset, 0x1000, 0x1000, 4, 4, 5, 4]))
    # Serialize a section's normalized field values in the chosen ELF layout.
    # Packing explicit fields avoids host-language object layout assumptions.
    def section(values):
        return struct.pack(endian + ('IIQQQQIIQQ' if wide else '10I'), *values)
    zero = section([0, 0, 0, 0, 0, 3 if extended else 0, 2 if extended else 0, programs if extended else 0, 0, 0])
    text = section([1, 1, 6, 0x1000, text_offset, 4, 0, 0, 4, 0])
    strings = section([7, 3, 0, 0, name_offset, len(names), 0, 0, 1, 0])
    return header + program * programs + zero + text + strings + names + b'TEXT'


# Convert numeric fields in a known little-endian thin Mach-O to big-endian.
# Names and payload bytes stay untouched; they are not multibyte integers.
def big_mach(wide=False):
    data = bytearray(mach_sections(wide))
    header_size, fixed, width = (32, 72, 80) if wide else (28, 56, 68)
    # Read numbers using the old byte order and write the same numbers using the
    # new byte order. This changes representation without changing their values.
    def swap(offset, fmt):
        values = struct.unpack_from('<' + fmt, data, offset)
        struct.pack_into('>' + fmt, data, offset, *values)
    swap(0, '8I' if wide else '7I')
    swap(header_size, 'II')
    swap(header_size + 24, 'QQQQIIII' if wide else '8I')
    for i in range(2):
        swap(header_size + fixed + i * width + 32, 'QQ8I' if wide else '9I')
    return data


# Create two real monochrome image resources plus a group referring to them.
# Cursor resources add hotspot coordinates; a missing reference exercises the
# fallback where raw extraction succeeds but group reconstruction is unavailable.
def image_resources(cursor=False, missing=False):
    # Two real 1x1 monochrome DIBs, including XOR and AND masks.
    dib = struct.pack('<IiiHHIIIIII', 40, 1, 2, 1, 1, 0, 8, 0, 0, 2, 0)
    dib += bytes([0, 0, 0, 0, 255, 255, 255, 0]) + b'\x80\0\0\0' + bytes(4)
    child = (struct.pack('<HH', 0, 0) if cursor else b'') + dib
    kind = 1 if cursor else 3
    group_kind = 12 if cursor else 14
    group = struct.pack('<HHH', 0, 2 if cursor else 1, 2)
    for id in (1, 99 if missing else 2):
        if cursor:
            group += struct.pack('<HHHHIH', 1, 1, 1, 1, len(child), id)
        else:
            group += struct.pack('<BBBBHHIH', 1, 1, 2, 0, 1, 1, len(child), id)
    entries = [(kind, 1, child), (kind, 2, child), (group_kind, 1, group)]
    image = pe_details(True)
    # Replace the resource tree with two types, two image IDs, and one group.
    root_offset = 512 + 0x400
    tree = bytearray(0x200)
    cursor_offset = 16 + 2 * 8
    # Write a resource-directory header at a directory-relative byte offset.
    # Its count tells the parser how many eight-byte entries follow.
    def directory(offset, count):
        struct.pack_into('<IIHHHH', tree, offset, 0, 0, 0, 0, 0, count)
    directory(0, 2)
    for type_index, resource_type in enumerate((kind, group_kind)):
        resources = [(id, payload) for typ, id, payload in entries if typ == resource_type]
        type_dir = cursor_offset; cursor_offset += 16 + 8 * len(resources)
        directory(type_dir, len(resources))
        struct.pack_into('<II', tree, 16 + type_index * 8, resource_type, type_dir | 0x80000000)
        for index, (id, payload) in enumerate(resources):
            language = cursor_offset; cursor_offset += 24
            record = cursor_offset; cursor_offset += 16
            directory(language, 1)
            struct.pack_into('<II', tree, type_dir + 16 + index * 8, id, language | 0x80000000)
            struct.pack_into('<II', tree, language + 16, 1033, record)
            payload_relative = 0x700 + entries.index((resource_type, id, payload)) * 0x100
            struct.pack_into('<IIII', tree, record, 0x1000 + payload_relative, len(payload), 0, 0)
            image[512 + payload_relative:512 + payload_relative + len(payload)] = payload
    image[root_offset:root_offset + len(tree)] = tree
    return image


# Add a delay-import directory at index 13, preserving the existing section.
# legacy stores image-base-relative VAs; modern descriptors store RVAs. The
# thunks include one named symbol, one ordinal, and a zero terminator.
def delay_imports(wide=False, legacy=False):
    image = pe_details(wide)
    fixed = 112 if wide else 96
    optional = 64 + 24
    old_size = fixed + 24
    new_size = fixed + 14 * 8
    section = bytes(image[optional + old_size:optional + old_size + 40])
    image[optional + old_size:optional + new_size + 40] = bytes(new_size - old_size) + section
    struct.pack_into('<H', image, 64 + 20, new_size)
    struct.pack_into('<I', image, optional + fixed - 4, 14)
    struct.pack_into('<II', image, optional + fixed + 13 * 8, 0x1b00, 64)
    base = 0x400000 if legacy else (0x140000000 if wide else 0x400000)
    struct.pack_into('<Q' if wide else '<I', image, optional + (24 if wide else 28), base)
    address = lambda rva: base + rva if legacy else rva
    struct.pack_into('<8I', image, 512 + 0xb00, 0 if legacy else 1,
                     address(0x1c00), address(0x1c40), address(0x1c80), address(0x1ca0), 0, 0, 0)
    image[512 + 0xc00:512 + 0xc0a] = b'DELAY.dll\0'
    named = b'\x07\0DelayedFunction\0'
    image[512 + 0xd00:512 + 0xd00 + len(named)] = named
    thunk = struct.pack('<QQQ' if wide else '<III', address(0x1d00), (1 << (63 if wide else 31)) | 42, 0)
    image[512 + 0xc80:512 + 0xc80 + len(thunk)] = thunk
    image[512 + 0xca0:512 + 0xca0 + len(thunk)] = thunk
    return image


# Build standard/extended dialogs with fonts, two controls, and creation bytes.
# Include a negative coordinate and an extended ID above 65535 to catch signedness
# and width mistakes. Align each control header to four bytes.
def dialog_controls(extended=False):
    style = 0x40
    if extended:
        header = struct.pack('<HHIIIHhhhh', 1, 0xffff, 7, 0, style, 2, 0, 0, 160, 80)
    else:
        header = struct.pack('<IIHhhhh', style, 0, 2, 0, 0, 160, 80)
    data = bytearray(header + bytes(4) + 'Controls\0'.encode('utf-16le'))
    data += struct.pack('<HHBB', 9, 400, 0, 1) if extended else struct.pack('<H', 9)
    data += 'Segoe UI\0'.encode('utf-16le')
    for index in range(2):
        data += bytes(-len(data) % 4)
        if extended:
            data += struct.pack('<IIIhhhhI', 8, 0, 0x50010000, -2, 10, 60, 14, 70000 + index)
        else:
            data += struct.pack('<IIhhhhH', 0x50010000, 0, -2, 10, 60, 14, 100 + index)
        data += struct.pack('<HH', 0xffff, 0x80 + index)
        data += 'Press\0'.encode('utf-16le') if index == 0 else struct.pack('<HH', 0xffff, 55)
        extra = b'ABC' if index == 0 else b''
        size = len(extra) if extended else (len(extra) + 2 if extra else 0)
        data += struct.pack('<H', size) + extra
    return data


# Build one non-Unicode message containing bytes from code page 1252.
# Changing only the declared page tests how metadata affects interpretation.
def legacy_message(codepage=1252):
    encoded = 'Café €'.encode('cp1252') + b'\0'
    payload = struct.pack('<IIIIHH', 1, 42, 42, 16, len(encoded) + 4, 0) + encoded
    image = resource_payload(payload, 11)
    struct.pack_into('<I', image, 512 + 0x450, codepage)
    return image


if __name__ == '__main__':
    from pathlib import Path
    import sys
    target = Path(sys.argv[1])
    target.mkdir(parents=True, exist_ok=True)
    for name, data in fuzz_seeds().items():
        (target / name).write_bytes(data)

    # Frozen regressions join deterministic mutations without regenerating them.
    from regression_corpus import corpus_cases
    for case, _, data in corpus_cases():
        (target / ('regression-' + case['file'])).write_bytes(data)

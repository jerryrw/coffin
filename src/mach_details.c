/* Mach-O dependency commands and nlist symbol tables. All file offsets inside
 * these commands are slice-relative, including in a universal container.
 * Byte decoding handles both widths/orders without host SDK dependencies. */
#include "machparser.h"

/* Load-command sizes/ranges were validated by parse_thin. Walk the same byte
 * positions to decode the command kinds that carry libraries or a symbol table. */
int parse_mach_details(const InputFile *input, MachOInfo *info)
{
    uint64_t at = info->is_64bit ? 32 : 28, work = 0;
    unsigned tables = 0;
    for (int i = 0; i < info->load_cmd_count; ++i) {
        const MachOLoadCommand *c = &info->load_commands[i];
        unsigned char b[24];
        uint32_t kind = c->cmd & 0x7fffffff;
        if (kind == 0xc || kind == 0x18 || kind == 0x1f || kind == 0x20 || kind == 0x23 || kind == 0xd) {
            /* dylib_command contains a command-relative name offset, timestamp,
             * current version, and minimum compatible version. ID_DYLIB names
             * the image itself; keep its kind so it is not called a dependency. */
            Dependency d = {0}; d.kind = c->cmd;
            if (c->cmdsize < 24 || parser_read(input, info->slice_offset + at, b, 24) != STATUS_SUCCESS) return STATUS_ERROR;
            uint32_t name = read32_order(b + 8, info->big_endian);
            d.current_version = read32_order(b + 16, info->big_endian);
            d.compatibility_version = read32_order(b + 20, info->big_endian);
            if (name < 24 || name >= c->cmdsize || info->dependency_count >= LINKAGE_WORK_LIMIT ||
                read_display_string(input, info->slice_offset + at + name, c->cmdsize - name,
                                    d.name, sizeof(d.name), &work) != STATUS_SUCCESS ||
                reserve_array(input, (void **)&info->dependencies, &info->dependency_capacity,
                              info->dependency_count + 1, sizeof(d)) != STATUS_SUCCESS) return STATUS_ERROR;
            info->dependencies[info->dependency_count++] = d;
        } else if (c->cmd == 2) { /* LC_SYMTAB */
            if (++tables > 1 || c->cmdsize < 24 || parser_read(input, info->slice_offset + at, b, 24) != STATUS_SUCCESS) return STATUS_ERROR;
            uint32_t offset = read32_order(b + 8, info->big_endian), count = read32_order(b + 12, info->big_endian);
            uint32_t strings = read32_order(b + 16, info->big_endian), size = read32_order(b + 20, info->big_endian);
            unsigned width = info->is_64bit ? 16 : 12;
            if (count > LINKAGE_WORK_LIMIT || !file_range_valid(offset, (uint64_t)count * width, info->slice_size) ||
                !file_range_valid(strings, size, info->slice_size)) return STATUS_ERROR;
            for (unsigned j = 0; j < count; ++j) {
                BinarySymbol s = {0};
                if (parser_read(input, info->slice_offset + offset + (uint64_t)j * width, b, width) != STATUS_SUCCESS) return STATUS_ERROR;
                uint32_t name = read32_order(b, info->big_endian);
                s.type = b[4]; s.section = b[5]; s.description = read16_order(b + 6, info->big_endian);
                s.value = info->is_64bit ? read64_order(b + 8, info->big_endian) : read32_order(b + 8, info->big_endian);
                /* n_type retains debug/external/private bits. For ordinary
                 * N_SECT symbols, the one-based section index must exist. */
                if (!(s.type & 0xe0) && (s.type & 0xe) == 0xe && (!s.section || s.section > info->section_count)) return STATUS_ERROR;
                if (name >= size || read_display_string(input, info->slice_offset + strings + name,
                        size - name, s.name, sizeof(s.name), &work) != STATUS_SUCCESS) return STATUS_ERROR;
                /* N_INDR's value is a string-table index, not an address. */
                if (!(s.type & 0xe0) && (s.type & 0xe) == 0xa &&
                    (s.value >= size || read_display_string(input, info->slice_offset + strings + s.value,
                     size - s.value, s.indirect, sizeof(s.indirect), &work) != STATUS_SUCCESS)) return STATUS_ERROR;
                if (reserve_array(input, (void **)&info->symbols, &info->symbol_capacity,
                                  info->symbol_count + 1, sizeof(s)) != STATUS_SUCCESS) return STATUS_ERROR;
                info->symbols[info->symbol_count++] = s;
            }
        }
        at += c->cmdsize;
    }
    if (!tables) info->symbols_unavailable = 1;
    return STATUS_SUCCESS;
}

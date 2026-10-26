/* ELF linkage metadata, decoded independently of host structs and byte order.
 * Section tables provide exact symbol counts. Without sections, PT_DYNAMIC
 * supplies dependencies and DT_HASH/DT_GNU_HASH can supply the symbol count.
 * Nothing here loads a library or resolves a symbol at runtime. */
#include <string.h>
#include "elfparser.h"

/* Translate a virtual address only through file-backed PT_LOAD bytes. Two
 * matching segments are ambiguous, so do not silently choose one of them. */
static int virtual_range(const InputFile *input, const ELFInfo *info, uint64_t address, uint64_t length,
                          uint64_t *offset, uint64_t *available)
{
    if (parser_lookup_work(input, info->program_count) != STATUS_SUCCESS) return STATUS_ERROR;
    unsigned matches = 0;
    for (unsigned i = 0; i < info->program_count; ++i) {
        const ProgramHeader *p = &info->program_headers[i];
        if (p->p_type != 1 || address < p->p_vaddr) continue;
        uint64_t delta = address - p->p_vaddr;
        if (delta >= p->p_filesz || length > p->p_filesz - delta) continue;
        *offset = p->p_offset + delta; *available = p->p_filesz - delta;
        ++matches;
    }
    return matches == 1 ? STATUS_SUCCESS : STATUS_ERROR;
}

/* Resolve one DT_NEEDED string offset and append an owned display record. */
static int needed(const InputFile *input, ELFInfo *info, uint64_t strings,
                   uint64_t size, uint64_t index, uint64_t *work)
{
    Dependency d = {0}; d.kind = 1; /* DT_NEEDED */
    if (index >= size || read_display_string(input, strings + index, size - index,
            d.name, sizeof(d.name), work) != STATUS_SUCCESS ||
        info->dependency_count >= LINKAGE_WORK_LIMIT ||
        reserve_array(input, (void **)&info->dependencies, &info->dependency_capacity,
                      info->dependency_count + 1, sizeof(d)) != STATUS_SUCCESS) return STATUS_ERROR;
    info->dependencies[info->dependency_count++] = d;
    return STATUS_SUCCESS;
}

/* Decode ELF32/64 symbol records into one representation. The first all-zero
 * symbol is intentionally retained: its table index has meaning to relocations. */
static int symbol_table(const InputFile *input, ELFInfo *info, uint64_t offset,
                         uint64_t count, uint64_t strings, uint64_t string_size,
                         unsigned table, int dynamic, uint64_t *work)
{
    unsigned width = info->is_64bit ? 24 : 16;
    if (count > LINKAGE_WORK_LIMIT - info->symbol_count ||
        !file_range_valid(offset, count * width, input->size) ||
        !file_range_valid(strings, string_size, input->size)) return STATUS_ERROR;
    const SectionHeader *indices = NULL; int searched_indices = 0;
    for (uint64_t i = 0; i < count; ++i) {
        unsigned char b[24]; BinarySymbol s = {0};
        if (parser_read(input, offset + i * width, b, width) != STATUS_SUCCESS) return STATUS_ERROR;
        uint32_t name = read32_order(b, info->big_endian);
        unsigned fields = info->is_64bit ? 4 : 12;
        s.binding = b[fields] >> 4; s.type = b[fields] & 15;
        s.visibility = b[fields + 1] & 3;
        s.section = read16_order(b + fields + 2, info->big_endian);
        s.value = info->is_64bit ? read64_order(b + 8, info->big_endian) : read32_order(b + 4, info->big_endian);
        s.size = info->is_64bit ? read64_order(b + 16, info->big_endian) : read32_order(b + 8, info->big_endian);
        s.table = table; s.dynamic = dynamic;
        /* SHN_XINDEX stores the real section index in a companion array. */
        if (s.section == 0xffff && table < info->section_count) {
            if (!searched_indices) {
                /* Search once per table, not once per symbol. Charge the scan
                 * against the same bounded metadata work allowance as strings. */
                if (parser_lookup_work(input, info->section_count) != STATUS_SUCCESS) return STATUS_ERROR;
                if (info->section_count > 16u * 1024u * 1024u - *work) {
                    fprintf(stderr, "Parser resource limit exceeded: ELF extended-index scan work\n");
                    return STATUS_ERROR;
                }
                *work += info->section_count;
                for (unsigned j = 0; j < info->section_count; ++j) {
                    const SectionHeader *h = &info->section_headers[j];
                    if (h->sh_type != 18 || h->sh_link != table) continue;
                    if (indices) return STATUS_ERROR;
                    indices = h;
                }
                searched_indices = 1;
            }
            unsigned char index[4];
            if (!indices || indices->sh_entsize != 4 || indices->sh_size / 4 != count || indices->sh_size % 4 ||
                parser_read(input, indices->sh_offset + i * 4, index, 4) != STATUS_SUCCESS) return STATUS_ERROR;
            s.section = read32_order(index, info->big_endian);
            if (s.section >= info->section_count) return STATUS_ERROR;
        }
        if (name >= string_size || read_display_string(input, strings + name, string_size - name,
                s.name, sizeof(s.name), work) != STATUS_SUCCESS ||
            reserve_array(input, (void **)&info->symbols, &info->symbol_capacity,
                          info->symbol_count + 1, sizeof(s)) != STATUS_SUCCESS) return STATUS_ERROR;
        info->symbols[info->symbol_count++] = s;
    }
    return STATUS_SUCCESS;
}

/* GNU hash buckets identify first symbols and chains end when bit zero is set.
 * Examine the chain beginning at the largest bucket to find the highest index.
 * Bound every bucket/chain step; a missing end marker is a malformed table. */
static int dynamic_count(const InputFile *input, const ELFInfo *info, uint64_t address,
                          int gnu, uint64_t *count)
{
    uint64_t offset, available; unsigned char b[16];
    if (virtual_range(input, info, address, gnu ? 16 : 8, &offset, &available) != STATUS_SUCCESS ||
        parser_read(input, offset, b, gnu ? 16 : 8) != STATUS_SUCCESS) return STATUS_ERROR;
    uint32_t buckets = read32_order(b, info->big_endian);
    uint32_t second = read32_order(b + 4, info->big_endian);
    if (buckets > LINKAGE_WORK_LIMIT || second > LINKAGE_WORK_LIMIT) return STATUS_ERROR;
    if (!gnu) {
        if (8 + ((uint64_t)buckets + second) * 4 > available) return STATUS_ERROR;
        *count = second; return STATUS_SUCCESS;
    }
    uint32_t bloom = read32_order(b + 8, info->big_endian);
    uint64_t bucket_at = 16 + (uint64_t)bloom * (info->is_64bit ? 8 : 4);
    if (!bloom || bucket_at > available || (uint64_t)buckets * 4 > available - bucket_at) return STATUS_ERROR;
    uint32_t last = 0;
    for (unsigned i = 0; i < buckets; ++i) {
        if (parser_read(input, offset + bucket_at + i * 4ULL, b, 4) != STATUS_SUCCESS) return STATUS_ERROR;
        uint32_t value = read32_order(b, info->big_endian);
        if (value && value < second) return STATUS_ERROR;
        if (value > last) last = value;
    }
    *count = second;
    if (!last) return STATUS_SUCCESS;
    uint64_t chain_at = bucket_at + (uint64_t)buckets * 4;
    for (uint64_t i = last; i < LINKAGE_WORK_LIMIT; ++i) {
        uint64_t at = chain_at + (i - second) * 4;
        if (!file_range_valid(at, 4, available) ||
            parser_read(input, offset + at, b, 4) != STATUS_SUCCESS) return STATUS_ERROR;
        if (read32_order(b, info->big_endian) & 1) { *count = i + 1; return STATUS_SUCCESS; }
    }
    return STATUS_ERROR;
}

/* Read each dynamic table twice: tags may appear in any order, so first locate
 * its string/symbol/hash tables, then interpret the DT_NEEDED string offsets. */
static int dynamic_table(const InputFile *input, ELFInfo *info, uint64_t offset,
                          uint64_t size, const SectionHeader *strings, int recover_symbols,
                          uint64_t *work)
{
    unsigned width = info->is_64bit ? 16 : 8;
    if (size % width || size / width > LINKAGE_WORK_LIMIT) return STATUS_ERROR;
    uint64_t str = 0, strsize = 0, sym = 0, syment = 0, hash = 0, gnuhash = 0, end = 0;
    unsigned char b[16];
    for (uint64_t at = 0; at < size; at += width) {
        if (parser_read(input, offset + at, b, width) != STATUS_SUCCESS) return STATUS_ERROR;
        uint64_t tag = info->is_64bit ? read64_order(b, info->big_endian) : read32_order(b, info->big_endian);
        uint64_t value = info->is_64bit ? read64_order(b + 8, info->big_endian) : read32_order(b + 4, info->big_endian);
        if (!tag) { end = at + width; break; }
        switch (tag) { case 5: str = value; break; case 10: strsize = value; break;
        case 6: sym = value; break; case 11: syment = value; break;
        case 4: hash = value; break; case 0x6ffffef5: gnuhash = value; break; }
    }
    if (!end) return STATUS_ERROR;
    uint64_t str_offset = 0, available;
    if (strings) { str_offset = strings->sh_offset; strsize = strings->sh_size; }
    else if (strsize && virtual_range(input, info, str, strsize, &str_offset, &available) != STATUS_SUCCESS) return STATUS_ERROR;
    for (uint64_t at = 0; at + width < end; at += width) {
        if (parser_read(input, offset + at, b, width) != STATUS_SUCCESS) return STATUS_ERROR;
        uint64_t tag = info->is_64bit ? read64_order(b, info->big_endian) : read32_order(b, info->big_endian);
        uint64_t value = info->is_64bit ? read64_order(b + 8, info->big_endian) : read32_order(b + 4, info->big_endian);
        if (tag == 1 && needed(input, info, str_offset, strsize, value, work) != STATUS_SUCCESS) return STATUS_ERROR;
    }
    if (recover_symbols && sym) {
        if (!hash && !gnuhash) { info->symbols_unavailable = 1; return STATUS_SUCCESS; }
        uint64_t count, sym_offset;
        if (syment != (info->is_64bit ? 24u : 16u) ||
            dynamic_count(input, info, hash ? hash : gnuhash, !hash, &count) != STATUS_SUCCESS ||
            virtual_range(input, info, sym, count * syment, &sym_offset, &available) != STATUS_SUCCESS ||
            symbol_table(input, info, sym_offset, count, str_offset, strsize, UINT32_MAX, 1, work) != STATUS_SUCCESS) return STATUS_ERROR;
    }
    return STATUS_SUCCESS;
}

/* Visit validated section tables first; program headers provide a fallback
 * when section-based dynamic metadata is absent. Total table work is bounded. */
int parse_elf_details(const InputFile *input, ELFInfo *info)
{
    uint64_t work = 0, records = 0; unsigned dynamics = 0;
    for (unsigned i = 0; i < info->section_count; ++i) {
        const SectionHeader *s = &info->section_headers[i];
        if (s->sh_type != 2 && s->sh_type != 11 && s->sh_type != 6) continue;
        unsigned entry = s->sh_type == 6 ? (info->is_64bit ? 16 : 8) : (info->is_64bit ? 24 : 16);
        records += s->sh_size / entry;
        if (records > LINKAGE_WORK_LIMIT) return STATUS_ERROR;
        if (s->sh_link >= info->section_count) return STATUS_ERROR;
        const SectionHeader *strings = &info->section_headers[s->sh_link];
        if (strings->sh_type != 3) return STATUS_ERROR;
        if (s->sh_type == 6) {
            if (s->sh_entsize != (info->is_64bit ? 16u : 8u) ||
                dynamic_table(input, info, s->sh_offset, s->sh_size, strings, 0, &work) != STATUS_SUCCESS) return STATUS_ERROR;
            ++dynamics;
        } else {
            unsigned width = info->is_64bit ? 24 : 16;
            if (s->sh_entsize != width || s->sh_size % width ||
                symbol_table(input, info, s->sh_offset, s->sh_size / width, strings->sh_offset,
                             strings->sh_size, i, s->sh_type == 11, &work) != STATUS_SUCCESS) return STATUS_ERROR;
        }
    }
    if (!dynamics) {
        for (unsigned i = 0; i < info->program_count; ++i) {
            const ProgramHeader *p = &info->program_headers[i];
            if (p->p_type == 2 && (++dynamics > 1 || dynamic_table(input, info, p->p_offset,
                    p->p_filesz, NULL, info->symbol_count == 0, &work) != STATUS_SUCCESS)) return STATUS_ERROR;
        }
    }
    if (!info->symbol_count) info->symbols_unavailable = 1;
    return STATUS_SUCCESS;
}

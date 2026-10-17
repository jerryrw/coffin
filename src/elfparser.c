/*
 * Read Executable and Linkable Format (ELF), used by the Linux samples.
 * ELF has a main header, program headers describing loader regions, and section
 * headers describing items such as code, symbols, and strings. Some files have
 * no sections. Both 32/64-bit layouts and both byte orders are supported.
 * The E16/E32/E64 macros below use the local variable big to select byte order.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define E16(p) read16_order((p), big)
#define E32(p) read32_order((p), big)
#define E64(p) read64_order((p), big)
#include "elfparser.h"

/*
 * Decode one on-disk section header into our common in-memory representation.
 * wide selects ELF64 versus ELF32; big selects byte order. Wider storage in the
 * result lets the rest of the program handle both layouts with one set of fields.
 */
static SectionHeader decode_section(const unsigned char *p, int wide, int big)
{
    SectionHeader h = {0};
    h.sh_name = E32(p); h.sh_type = E32(p + 4);
    if (wide) {
        h.sh_flags = E64(p + 8); h.sh_addr = E64(p + 16);
        h.sh_offset = E64(p + 24); h.sh_size = E64(p + 32);
        h.sh_link = E32(p + 40); h.sh_info = E32(p + 44);
        h.sh_addralign = E64(p + 48); h.sh_entsize = E64(p + 56);
    } else {
        h.sh_flags = E32(p + 8); h.sh_addr = E32(p + 12);
        h.sh_offset = E32(p + 16); h.sh_size = E32(p + 20);
        h.sh_link = E32(p + 24); h.sh_info = E32(p + 28);
        h.sh_addralign = E32(p + 32); h.sh_entsize = E32(p + 36);
    }
    return h;
}

/*
 * Validate the ELF header, allocate result arrays, then decode tables and names.
 * Each table is range-checked before iteration. Counts describe initialized
 * entries, so a caller never needs to use uninitialized array capacity.
 */
int parse_elf_file(const InputFile *input, ELFInfo *info)
{
    unsigned char bytes[64];
    memset(info, 0, sizeof(*info));
    escape_display(info->filename, sizeof(info->filename), (const unsigned char *)input->path, strlen(input->path));
    info->file_size = input->size;
    strcpy(info->sha256hashstring, input->sha256);
    strcpy(info->md5hashstring, input->md5);
    if (parser_read(input, 0, bytes, 16) != STATUS_SUCCESS ||
        memcmp(bytes, "\177ELF", 4) != 0) goto invalid;
    if ((bytes[4] != 1 && bytes[4] != 2) || (bytes[5] != 1 && bytes[5] != 2)) {
        fprintf(stderr, "Unsupported ELF variant: invalid ELF class or byte order\n");
        return STATUS_ERROR;
    }
    int big = bytes[5] == 2;
    info->big_endian = big;
    info->is_64bit = bytes[4] == 2;
    size_t header_size = info->is_64bit ? 64 : 52;
    size_t program_size = info->is_64bit ? 56 : 32;
    size_t section_size = info->is_64bit ? 64 : 40;
    size_t sizes_offset = info->is_64bit ? 52 : 40;
    if (parser_read(input, 0, bytes, header_size) != STATUS_SUCCESS ||
        bytes[6] != 1 || E32(bytes + 20) != 1 || E16(bytes + sizes_offset) != header_size)
        goto invalid;
    info->flags = E32(bytes + (info->is_64bit ? 48 : 36));
    info->e_type = E16(bytes + 16); info->e_machine = E16(bytes + 18);
    info->e_entry = info->is_64bit ? E64(bytes + 24) : E32(bytes + 24);
    uint64_t phoff = info->is_64bit ? E64(bytes + 32) : E32(bytes + 28);
    uint64_t shoff = info->is_64bit ? E64(bytes + 40) : E32(bytes + 32);
    uint16_t phsize = E16(bytes + sizes_offset + 2), shsize = E16(bytes + sizes_offset + 6);
    unsigned names_index = E16(bytes + sizes_offset + 10);
    info->e_phnum = E16(bytes + sizes_offset + 4); info->e_shnum = E16(bytes + sizes_offset + 8);
    /*
     * ELF reserves sentinel counts for "extended numbering." The actual values
     * then live in section header zero: size = section count, link = name-table
     * index, info = program-header count. Zero is metadata, not a payload section.
     */
    if (info->e_phnum == 0xffff || names_index == 0xffff || (!info->e_shnum && shoff)) {
        if (!shoff || shsize != section_size ||
            parser_read(input, shoff, bytes, section_size) != STATUS_SUCCESS) goto invalid;
        SectionHeader zero = decode_section(bytes, info->is_64bit, big);
        if (zero.sh_type != 0 || zero.sh_size > UINT32_MAX) goto invalid;
        if (!info->e_shnum) info->e_shnum = (unsigned)zero.sh_size;
        if (!info->e_shnum) goto invalid;
        if (names_index == 0xffff) names_index = zero.sh_link;
        if (info->e_phnum == 0xffff) info->e_phnum = zero.sh_info;
    }
    if ((info->e_phnum && (phoff < header_size || phsize != program_size)) ||
        (info->e_shnum && (shoff < header_size || shsize != section_size)) ||
        (names_index && names_index >= info->e_shnum) ||
        !file_range_valid(phoff, (uint64_t)info->e_phnum * phsize, input->size) ||
        !file_range_valid(shoff, (uint64_t)info->e_shnum * shsize, input->size)) goto invalid;
    /*
     * Validate table byte counts in 64-bit arithmetic before allocating arrays.
     * The helper receives the ADDRESS of each array pointer so it can replace it.
     * Allocate name storage separately because one display name belongs to each section.
     */
    if (reserve_array(input, (void **)&info->program_headers, &info->program_capacity, info->e_phnum, sizeof(*info->program_headers)) != STATUS_SUCCESS ||
        reserve_array(input, (void **)&info->section_headers, &info->section_capacity, info->e_shnum, sizeof(*info->section_headers)) != STATUS_SUCCESS ||
        reserve_array(input, (void **)&info->section_names, &info->name_capacity, info->e_shnum, sizeof(*info->section_names)) != STATUS_SUCCESS) goto invalid;
    if (info->e_shnum) memset(info->section_names, 0, (size_t)info->e_shnum * sizeof(*info->section_names));
    for (unsigned i = 0; i < info->e_phnum; ++i) {
        ProgramHeader h = {0};
        if (parser_read(input, phoff + (uint64_t)i * program_size, bytes, program_size) != STATUS_SUCCESS)
            goto invalid;
        if (info->is_64bit) {
            h.p_type = E32(bytes); h.p_flags = E32(bytes + 4);
            h.p_offset = E64(bytes + 8); h.p_vaddr = E64(bytes + 16);
            h.p_paddr = E64(bytes + 24); h.p_filesz = E64(bytes + 32);
            h.p_memsz = E64(bytes + 40); h.p_align = E64(bytes + 48);
        } else {
            h.p_type = E32(bytes); h.p_offset = E32(bytes + 4);
            h.p_vaddr = E32(bytes + 8); h.p_paddr = E32(bytes + 12);
            h.p_filesz = E32(bytes + 16); h.p_memsz = E32(bytes + 20);
            h.p_flags = E32(bytes + 24); h.p_align = E32(bytes + 28);
        }
        if (h.p_filesz && !file_range_valid(h.p_offset, h.p_filesz, input->size)) goto invalid;
        info->program_headers[info->program_count++] = h;
    }
    SectionHeader names = {0};
    if (names_index) {
        if (parser_read(input, shoff + (uint64_t)names_index * section_size, bytes, section_size) != STATUS_SUCCESS)
            goto invalid;
        names = decode_section(bytes, info->is_64bit, big);
        if (names.sh_type != 3 || !file_range_valid(names.sh_offset, names.sh_size, input->size))
            goto invalid;
    }
    size_t name_bytes = 0;
    for (unsigned i = 0; i < info->e_shnum; ++i) {
        if (parser_read(input, shoff + (uint64_t)i * section_size, bytes, section_size) != STATUS_SUCCESS)
            goto invalid;
        SectionHeader h = decode_section(bytes, info->is_64bit, big);
        /*
         * SHT_NULL (0) is metadata; SHT_NOBITS (8), such as .bss, reserves memory
         * without storing those bytes on disk. Neither needs a file payload range.
         */
        if (h.sh_type != 0 && h.sh_type != 8 && h.sh_size &&
            !file_range_valid(h.sh_offset, h.sh_size, input->size)) goto invalid;
        if (names_index && h.sh_name >= names.sh_size) goto invalid;
        info->section_headers[info->section_count++] = h;
        if (names_index) {
            /* Bound display length; validate a terminator within the string table. */
            uint64_t remaining = names.sh_size - h.sh_name;
            uint64_t pos = names.sh_offset + h.sh_name;
            size_t stored = 0;
            int terminated = 0;
            size_t scanned = 0;
            /*
             * A section name is an index into a string table, not an inline name.
             * Scan for its terminating zero within limits, even when the display buffer
             * is already full. A shortened display must not hide an invalid file string.
             */
            while (remaining && !terminated) {
                size_t chunk = remaining < sizeof(bytes) ? (size_t)remaining : sizeof(bytes);
                scanned += chunk; name_bytes += chunk;
                if (scanned > 4096 || name_bytes > 16u * 1024u * 1024u) goto invalid;
                if (parser_read(input, pos, bytes, chunk) != STATUS_SUCCESS) goto invalid;
                for (size_t j = 0; j < chunk; ++j) {
                    if (!bytes[j]) { terminated = 1; break; }
                    if (stored < sizeof(info->section_names[i]) - 1)
                        info->section_names[i][stored++] = (char)bytes[j];
                }
                remaining -= chunk; pos += chunk;
            }
            if (!terminated) goto invalid;
            char display[256];
            escape_display(display, sizeof(display), (const unsigned char *)info->section_names[i], stored);
            strcpy(info->section_names[i], display);
            if (stored == sizeof(info->section_names[i]) - 1)
                strcpy(info->section_names[i] + stored - 3, "...");
        }
    }
    if (parse_elf_details(input, info) != STATUS_SUCCESS) goto invalid;
    return STATUS_SUCCESS;
invalid:
    free_elf_info(info);
    fprintf(stderr, "Invalid or truncated ELF headers, tables, or section names\n");
    return STATUS_ERROR;
}

/*
 * Render the expanded --verbose listing from already decoded values.
 * The casts paired with %llu/%llX make 64-bit printf arguments match their
 * format specifiers even when uint64_t is a different unsigned typedef.
 */
void print_elf_info(const ELFInfo *elf_info)
{
    printf("ELF File Analysis Report\n");
    printf("========================\n");
    printf("Filename: %s\n", elf_info->filename);
    printf("File Size: %zu bytes\n", elf_info->file_size);
    printf("SHA256 Hash: %s\n", elf_info->sha256hashstring);
    printf("MD5 Hash: %s\n", elf_info->md5hashstring);

    printf("Architecture: %s\n", elf_info->is_64bit ? "64-bit" : "32-bit");
    printf("Byte Order: %s\n", elf_info->big_endian ? "big-endian" : "little-endian");
    printf("\nELF Header:\n");
    printf("  Type: 0x%04X\n", elf_info->e_type);
    const char *machine = "Unknown";
    switch (elf_info->e_machine) {
    case 3: machine = "x86"; break;
    case 40: machine = "ARM"; break;
    case 62: machine = "x86-64"; break;
    case 183: machine = "AArch64"; break;
    }
    printf("  Machine: 0x%04X (%s)\n", elf_info->e_machine, machine);
    printf("  Flags: 0x%08X", elf_info->flags);
    if (elf_info->e_machine == 40)
        printf(" (ARM EABI version %u%s%s)", elf_info->flags >> 24,
               elf_info->flags & 0x400 ? ", hard-float ABI" : "",
               elf_info->flags & 0x200 ? ", soft-float ABI" : "");
    printf("\n");
    printf("  Entry Point: 0x%016llX\n", (unsigned long long)elf_info->e_entry);
    printf("  Number of Program Headers: %u\n", elf_info->e_phnum);
    printf("  Number of Section Headers: %u\n", elf_info->e_shnum);

    printf("\nProgram Headers:\n");
    for (unsigned i = 0; i < elf_info->program_count; ++i)
    {
        printf("  Header %u:\n", i + 1);
        printf("    Type: 0x%08X\n", elf_info->program_headers[i].p_type);
        printf("    Flags: 0x%08X (", elf_info->program_headers[i].p_flags);
        print_permissions(elf_info->program_headers[i].p_flags, 4, 2, 1);
        printf(")\n");
        printf("    Offset: 0x%016llX\n", (unsigned long long)elf_info->program_headers[i].p_offset);
        printf("    Virtual Address: 0x%016llX\n", (unsigned long long)elf_info->program_headers[i].p_vaddr);
        printf("    Physical Address: 0x%016llX\n", (unsigned long long)elf_info->program_headers[i].p_paddr);
        printf("    File Size: %llu\n", (unsigned long long)elf_info->program_headers[i].p_filesz);
        printf("    Memory Size: %llu\n", (unsigned long long)elf_info->program_headers[i].p_memsz);
        printf("    Alignment: %llu\n", (unsigned long long)elf_info->program_headers[i].p_align);
    }

    printf("\nSection Headers:\n");
    for (unsigned i = 0; i < elf_info->section_count; ++i)
    {
        printf("  Section %u:\n", i + 1);
        printf("    Name: %s\n", elf_info->section_names[i][0] ? elf_info->section_names[i] : "<unnamed>");
        printf("    Name Index: %u\n", elf_info->section_headers[i].sh_name);
        printf("    Type: 0x%08X\n", elf_info->section_headers[i].sh_type);
        uint64_t flags = elf_info->section_headers[i].sh_flags;
        printf("    Flags: 0x%016llX (%s%s%s)\n", (unsigned long long)flags,
               flags & 1 ? "write " : "", flags & 2 ? "alloc " : "", flags & 4 ? "execute" : "");
        printf("    Address: 0x%016llX\n", (unsigned long long)elf_info->section_headers[i].sh_addr);
        printf("    Offset: 0x%016llX\n", (unsigned long long)elf_info->section_headers[i].sh_offset);
        printf("    Size: %llu\n", (unsigned long long)elf_info->section_headers[i].sh_size);
        printf("    Link: %u\n", elf_info->section_headers[i].sh_link);
        printf("    Info: %u\n", elf_info->section_headers[i].sh_info);
        printf("    Address Align: %llu\n", (unsigned long long)elf_info->section_headers[i].sh_addralign);
        printf("    Entry Size: %llu\n", (unsigned long long)elf_info->section_headers[i].sh_entsize);
    }
}

/*
 * Free the program-header, section-header, and name arrays owned by info.
 * Reset them so cleanup is safe after partial parsing or an earlier cleanup.
 */
void free_elf_info(ELFInfo *info)
{
    free(info->dependencies); free(info->symbols);
    info->dependencies = NULL; info->symbols = NULL;
    info->dependency_count = info->dependency_capacity = info->symbol_count = info->symbol_capacity = 0;
    free(info->program_headers); free(info->section_headers); free(info->section_names);
    info->program_headers = NULL; info->section_headers = NULL; info->section_names = NULL;
    info->program_count = info->section_count = 0;
    info->program_capacity = info->section_capacity = info->name_capacity = 0;
}

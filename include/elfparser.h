/*
 * ELF field definitions and normalized parser results.
 * These are in-memory structures, not packed disk overlays. ELF32 and ELF64 both
 * use the wide integer fields here after explicit byte decoding. Program headers
 * describe loader regions; section headers describe code/data/metadata entries.
 * ELFInfo owns the arrays it points to; free_elf_info releases those arrays.
 */

#ifndef ELFPARSER_H
#define ELFPARSER_H

#include <stdint.h>
#include "common.h"

// ELF Header structure (simplified, based on standard ELF)
typedef struct
{
    uint8_t e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} ElfHeader;

// Program Header structure
typedef struct
{
    uint32_t p_type;
    uint32_t p_flags;
    /*
     * Disk offset and virtual/physical addresses are separate coordinate systems.
     */
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    /*
     * p_memsz may exceed p_filesz: remaining memory is not stored file content.
     */
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} ProgramHeader;

// Section Header structure
typedef struct
{
    /*
     * Index into the section-name string table, not a pointer or inline string.
     */
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    /*
     * Usually payload size; for NOBITS it is memory size, and section zero can
     * carry extended-count metadata. Consult sh_type before reading file bytes.
     */
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} SectionHeader;

// ELF Info structure
typedef struct
{
    char filename[256];
    size_t file_size;
    char sha256hashstring[65];
    char md5hashstring[33];
    int is_64bit, big_endian;
    uint32_t flags;
    uint16_t e_type;
    uint16_t e_machine;
    uint64_t e_entry;
    /*
     * Resolved counts include any extended-numbering values from section zero.
     */
    unsigned e_phnum, e_shnum;
    ProgramHeader *program_headers;
    SectionHeader *section_headers;
    /*
     * Count tracks populated elements; capacity tracks allocation, not valid data.
     */
    unsigned program_count, section_count;
    unsigned program_capacity, section_capacity, name_capacity;
    /*
     * Pointer to an ARRAY of 256 chars, one name per section. Parentheses matter:
     * char *section_names[256] would instead mean an array of 256 pointers.
     */
    char (*section_names)[256];
} ELFInfo;

/*
 * parse initializes the result; cleanup releases arrays and is safe repeatedly.
 * print borrows the result and does not change it.
 */
// Function declarations
void free_elf_info(ELFInfo *info);
int parse_elf_file(const InputFile *input, ELFInfo *elf_info);
void print_elf_info(const ELFInfo *elf_info);

#endif // ELFPARSER_H

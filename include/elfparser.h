#ifndef ELFPARSER_H
#define ELFPARSER_H

#include <stdint.h>

// ELF Header structure (simplified, based on standard ELF)
typedef struct __attribute__((packed))
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
typedef struct __attribute__((packed))
{
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} ProgramHeader;

// Section Header structure
typedef struct __attribute__((packed))
{
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
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
    uint16_t e_type;
    uint16_t e_machine;
    uint64_t e_entry;
    uint16_t e_phnum;
    uint16_t e_shnum;
    ProgramHeader program_headers[16]; // Assuming max 16
    SectionHeader section_headers[16]; // Assuming max 16
    int program_count;
    int section_count;
} ELFInfo;

// Function declarations
int parse_elf_file(const char *filepath, ELFInfo *elf_info);
void print_elf_info(const ELFInfo *elf_info);

#endif // ELFPARSER_H
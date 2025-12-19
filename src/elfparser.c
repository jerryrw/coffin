#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "sha256.h"
#include "md5.h"
#include "elfparser.h"
#include "common.h"

// Function to parse ELF file
int parse_elf_file(const char *filepath, ELFInfo *elf_info)
{
    fprintf(stderr, "DEBUG: parse_elf_file called with filepath=%s\n", filepath);
    
    uint8_t sha256hash[32];
    char sha256string[65] = {0};
    uint8_t md5hash[16];
    char md5string[33] = {0};

    FILE *file = fopen(filepath, "rb");
    if (!file)
    {
        fprintf(stderr, "Cannot open file: %s\n", filepath);
        return -1;
    }
    fprintf(stderr, "DEBUG: File opened successfully\n");

    // Calculate SHA256 hash
    fprintf(stderr, "DEBUG: About to calculate SHA256\n");
    if (calculate_file_sha256(filepath, sha256hash) == 0)
    {
        fprintf(stderr, "DEBUG: SHA256 calculated\n");
        size_t off = 0;
        for (int i = 0; i < 32; ++i)
        {
            int n = snprintf(sha256string + off, sizeof(sha256string) - off, "%02x", sha256hash[i]);
            if (n <= 0)
                break;
            off += (size_t)n;
            if (off >= sizeof(sha256string) - 1)
                break;
        }
        strncpy(elf_info->sha256hashstring, sha256string, sizeof(elf_info->sha256hashstring) - 1);
        elf_info->sha256hashstring[sizeof(elf_info->sha256hashstring) - 1] = '\0';
    }
    else
    {
        fprintf(stderr, "DEBUG: SHA256 calculation failed\n");
    }

    // Calculate MD5 hash
    fprintf(stderr, "DEBUG: About to calculate MD5\n");
    if (calculate_file_md5(filepath, md5hash) == 0)
    {
        fprintf(stderr, "DEBUG: MD5 calculated\n");
        size_t off = 0;
        for (int i = 0; i < 16; ++i)
        {
            int n = snprintf(md5string + off, sizeof(md5string) - off, "%02x", md5hash[i]);
            if (n <= 0)
                break;
            off += (size_t)n;
            if (off >= sizeof(md5string) - 1)
                break;
        }
        strncpy(elf_info->md5hashstring, md5string, sizeof(elf_info->md5hashstring) - 1);
        elf_info->md5hashstring[sizeof(elf_info->md5hashstring) - 1] = '\0';
    }
    else
    {
        fprintf(stderr, "DEBUG: MD5 calculation failed\n");
    }

    // Get file size
    fprintf(stderr, "DEBUG: About to seek\n");
    fseek(file, 0, SEEK_END);
    elf_info->file_size = ftell(file);
    rewind(file);
    fprintf(stderr, "DEBUG: File size=%zu\n", elf_info->file_size);

    // Store filename
    strncpy(elf_info->filename, filepath, sizeof(elf_info->filename) - 1);

    // Read ELF Header
    ElfHeader elf_header;
    fprintf(stderr, "DEBUG: About to read ELF header, sizeof(ElfHeader)=%zu\n", sizeof(ElfHeader));
    if (fread(&elf_header, sizeof(ElfHeader), 1, file) != 1)
    {
        fprintf(stderr, "Failed to read ELF header\n");
        fclose(file);
        return -1;
    }
    fprintf(stderr, "DEBUG: ELF header read successfully\n");
    fprintf(stderr, "DEBUG: e_ident[0]=0x%02X, e_ident[1]=%c, e_ident[2]=%c, e_ident[3]=%c\n",
            elf_header.e_ident[0], elf_header.e_ident[1], elf_header.e_ident[2], elf_header.e_ident[3]);

    // Check ELF magic (explicit bytes to avoid escape/encoding issues)
    if (elf_header.e_ident[0] != 0x7f ||
        elf_header.e_ident[1] != 'E' ||
        elf_header.e_ident[2] != 'L' ||
        elf_header.e_ident[3] != 'F')
    {
        fprintf(stderr, "Not a valid ELF file\n");
        fclose(file);
        return -1;
    }
    fprintf(stderr, "DEBUG: ELF magic verified\n");

    // Debug: print raw header values
    fprintf(stderr, "DEBUG: e_type=0x%04X, e_machine=0x%04X, e_entry=0x%016llX\n",
            elf_header.e_type, elf_header.e_machine, elf_header.e_entry);
    fprintf(stderr, "DEBUG: e_phoff=%llu, e_shoff=%llu, e_phnum=%d, e_shnum=%d\n",
            elf_header.e_phoff, elf_header.e_shoff, elf_header.e_phnum, elf_header.e_shnum);

    // Detect if 32-bit or 64-bit and endianness
    int is_64bit = (elf_header.e_ident[4] == 2);         // EI_CLASS: 1=32-bit, 2=64-bit
    int is_little_endian = (elf_header.e_ident[5] == 1); // EI_DATA: 1=little-endian, 2=big-endian

    fprintf(stderr, "DEBUG: is_64bit=%d, is_little_endian=%d\n", is_64bit, is_little_endian);

    if (!is_64bit)
    {
        fprintf(stderr, "32-bit ELF not yet fully supported\n");
        fclose(file);
        return -1;
    }

    // For now, assume 64-bit little-endian; manual byte-swapping if needed
    if (!is_little_endian)
    {
        fprintf(stderr, "Big-endian ELF not yet supported\n");
        fclose(file);
        return -1;
    }

    // Store ELF header info
    elf_info->e_type = elf_header.e_type;
    elf_info->e_machine = elf_header.e_machine;
    elf_info->e_entry = elf_header.e_entry;
    elf_info->e_phnum = elf_header.e_phnum;
    elf_info->e_shnum = elf_header.e_shnum;

    // Read Program Headers
    elf_info->program_count = 0;
    fseek(file, elf_header.e_phoff, SEEK_SET);
    for (int i = 0; i < elf_header.e_phnum && i < 16; ++i)
    {
        if (fread(&elf_info->program_headers[i], sizeof(ProgramHeader), 1, file) != 1)
        {
            break;
        }
        elf_info->program_count++;
    }

    // Read Section Headers
    elf_info->section_count = 0;
    fseek(file, elf_header.e_shoff, SEEK_SET);
    for (int i = 0; i < elf_header.e_shnum && i < 16; ++i)
    {
        if (fread(&elf_info->section_headers[i], sizeof(SectionHeader), 1, file) != 1)
        {
            break;
        }
        elf_info->section_count++;
    }

    fclose(file);
    return 1;
}

// Print ELF file information
void print_elf_info(const ELFInfo *elf_info)
{
    printf("ELF File Analysis Report\n");
    printf("========================\n");
    printf("Filename: %s\n", elf_info->filename);
    printf("File Size: %zu bytes\n", elf_info->file_size);
    printf("SHA256 Hash: %s\n", elf_info->sha256hashstring);
    printf("MD5 Hash: %s\n", elf_info->md5hashstring);

    printf("\nELF Header:\n");
    printf("  Type: 0x%04X\n", elf_info->e_type);
    printf("  Machine: 0x%04X\n", elf_info->e_machine);
    printf("  Entry Point: 0x%016llX\n", elf_info->e_entry);
    printf("  Number of Program Headers: %d\n", elf_info->e_phnum);
    printf("  Number of Section Headers: %d\n", elf_info->e_shnum);

    printf("\nProgram Headers:\n");
    for (int i = 0; i < elf_info->program_count; ++i)
    {
        printf("  Header %d:\n", i + 1);
        printf("    Type: 0x%08X\n", elf_info->program_headers[i].p_type);
        printf("    Flags: 0x%08X\n", elf_info->program_headers[i].p_flags);
        printf("    Offset: 0x%016llX\n", elf_info->program_headers[i].p_offset);
        printf("    Virtual Address: 0x%016llX\n", elf_info->program_headers[i].p_vaddr);
        printf("    Physical Address: 0x%016llX\n", elf_info->program_headers[i].p_paddr);
        printf("    File Size: %llu\n", elf_info->program_headers[i].p_filesz);
        printf("    Memory Size: %llu\n", elf_info->program_headers[i].p_memsz);
        printf("    Alignment: %llu\n", elf_info->program_headers[i].p_align);
    }

    printf("\nSection Headers:\n");
    for (int i = 0; i < elf_info->section_count; ++i)
    {
        printf("  Section %d:\n", i + 1);
        printf("    Name Index: %u\n", elf_info->section_headers[i].sh_name);
        printf("    Type: 0x%08X\n", elf_info->section_headers[i].sh_type);
        printf("    Flags: 0x%016llX\n", elf_info->section_headers[i].sh_flags);
        printf("    Address: 0x%016llX\n", elf_info->section_headers[i].sh_addr);
        printf("    Offset: 0x%016llX\n", elf_info->section_headers[i].sh_offset);
        printf("    Size: %llu\n", elf_info->section_headers[i].sh_size);
        printf("    Link: %u\n", elf_info->section_headers[i].sh_link);
        printf("    Info: %u\n", elf_info->section_headers[i].sh_info);
        printf("    Address Align: %llu\n", elf_info->section_headers[i].sh_addralign);
        printf("    Entry Size: %llu\n", elf_info->section_headers[i].sh_entsize);
    }
}
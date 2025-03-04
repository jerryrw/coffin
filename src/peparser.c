#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "peparser.h"

// Function to parse PE file
int parse_pe_file(const char *filepath, PEInfo *pe_info)
{
    FILE *file = fopen(filepath, "rb");
    if (!file)
    {
        fprintf(stderr, "Cannot open file: %s\n", filepath);
        return 0;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    pe_info->file_size = ftell(file);
    rewind(file);

    // Store filename
    strncpy(pe_info->filename, filepath, sizeof(pe_info->filename) - 1);

    // Read DOS Header
    DOS_Header dos_header;
    if (fread(&dos_header, sizeof(DOS_Header), 1, file) != 1)
    {
        fprintf(stderr, "Failed to read DOS header\n");
        fclose(file);
        return 0;
    }

    // Check DOS signature
    if (dos_header.e_magic != DOS_SIGNATURE)
    {
        fprintf(stderr, "Not a valid DOS executable\n");
        fclose(file);
        return 0;
    }

    // Seek to PE header
    fseek(file, dos_header.e_lfanew, SEEK_SET);

    // Read PE Signature
    uint16_t pe_signature;
    if (fread(&pe_signature, sizeof(uint16_t), 1, file) != 1)
    {
        fprintf(stderr, "Failed to read PE signature\n");
        fclose(file);
        return 0;
    }

    // Verify PE Signature
    if (pe_signature != PE_SIGNATURE)
    {
        fprintf(stderr, "Invalid PE signature\n");
        fclose(file);
        return 0;
    }

    // Read COFF Header
    COFF_Header coff_header;
    if (fread(&coff_header, sizeof(COFF_Header), 1, file) != 1)
    {
        fprintf(stderr, "Failed to read COFF header\n");
        fclose(file);
        return 0;
    }

    // Store COFF Header information
    pe_info->machine = coff_header.Machine;
    pe_info->timestamp = coff_header.TimeDateStamp;
    pe_info->number_of_sections = coff_header.NumberOfSections;
    pe_info->characteristics = coff_header.Characteristics;

    // Determine if 32-bit or 64-bit
    uint16_t optional_magic;
    if (fread(&optional_magic, sizeof(uint16_t), 1, file) != 1)
    {
        fprintf(stderr, "Failed to read Optional header magic\n");
        fclose(file);
        return 0;
    }

    // Seek back to read full optional header
    fseek(file, -sizeof(uint16_t), SEEK_CUR);

    // Store magic and bit-ness
    pe_info->magic = optional_magic;
    pe_info->is_64bit = (optional_magic == PE32PLUS_MAGIC);

    // Read appropriate optional header based on architecture
    if (!pe_info->is_64bit)
    {
        // 32-bit
        Optional_Header32 optional_header;
        if (fread(&optional_header, sizeof(Optional_Header32), 1, file) != 1)
        {
            fprintf(stderr, "Failed to read 32-bit Optional header\n");
            fclose(file);
            return 0;
        }

        pe_info->size_of_code = optional_header.SizeOfCode;
        pe_info->entry_point = optional_header.AddressOfEntryPoint;
        pe_info->image_base = optional_header.ImageBase;
    }
    else
    {
        // 64-bit
        Optional_Header64 optional_header;
        if (fread(&optional_header, sizeof(Optional_Header64), 1, file) != 1)
        {
            fprintf(stderr, "Failed to read 64-bit Optional header\n");
            fclose(file);
            return 0;
        }

        pe_info->size_of_code = optional_header.SizeOfCode;
        pe_info->entry_point = optional_header.AddressOfEntryPoint;
        pe_info->image_base = optional_header.ImageBase;
    }

    // Parse Sections
    pe_info->section_count = 0;
    for (int i = 0; i < pe_info->number_of_sections && i < 16; i++)
    {
        Section_Header section_header;
        if (fread(&section_header, sizeof(Section_Header), 1, file) != 1)
        {
            fprintf(stderr, "Failed to read section header\n");
            fclose(file);
            return 0;
        }

        // Store section info
        strncpy(pe_info->sections[i].name,
                section_header.Name,
                8);
        pe_info->sections[i].name[8] = '\0';

        pe_info->sections[i].virtual_size = section_header.VirtualSize;
        pe_info->sections[i].virtual_address = section_header.VirtualAddress;
        pe_info->sections[i].raw_size = section_header.SizeOfRawData;
        pe_info->sections[i].characteristics = section_header.Characteristics;

        pe_info->section_count++;
    }

    fclose(file);
    return 1;
}

// Print PE file information
void print_pe_info(const PEInfo *pe_info)
{
    printf("PE File Analysis Report\n");
    printf("=====================\n");
    printf("Filename: %s\n", pe_info->filename);
    printf("File Size: %zu bytes\n", pe_info->file_size);
    printf("Architecture: %s\n", pe_info->is_64bit ? "64-bit" : "32-bit");

    printf("\nCOFF Header:\n");
    printf("  Machine: 0x%04X (%s)\n", pe_info->machine,
           pe_info->machine == IMAGE_FILE_MACHINE_I386 ? "x86" : pe_info->machine == IMAGE_FILE_MACHINE_AMD64 ? "x64"
                                                                                                              : "Unknown");
    printf("  Timestamp: %u\n", pe_info->timestamp);
    printf("  Number of Sections: %d\n", pe_info->number_of_sections);
    printf("  Characteristics: 0x%04X\n", pe_info->characteristics);

    printf("\nOptional Header:\n");
    printf("  Magic: 0x%04X\n", pe_info->magic);
    printf("  Size of Code: %u\n", pe_info->size_of_code);
    printf("  Entry Point: 0x%08X\n", pe_info->entry_point);
    printf("  Image Base: 0x%08X\n", pe_info->image_base); // TODO fix this?

    printf("\nSections:\n");
    for (int i = 0; i < pe_info->section_count; i++)
    {
        printf("  Section %d:\n", i + 1);
        printf("    Name: %s\n", pe_info->sections[i].name);
        printf("    Virtual Size: %u\n", pe_info->sections[i].virtual_size);
        printf("    Virtual Address: 0x%08X\n", pe_info->sections[i].virtual_address);
        printf("    Raw Size: %u\n", pe_info->sections[i].raw_size);
        printf("    Characteristics: 0x%08X\n", pe_info->sections[i].characteristics);
    }
}

// int main(int argc, char *argv[]) {
//     if (argc < 2) {
//         fprintf(stderr, "Usage: %s <executable_path>\n", argv[0]);
//         return 1;
//     }

//     PEInfo pe_info = {0};

//     if (parse_pe_file(argv[1], &pe_info)) {
//         print_pe_info(&pe_info);
//     }

//     return 0;
// }
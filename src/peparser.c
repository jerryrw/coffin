#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "sha256.h"
#include "md5.h"
#include "peparser.h"
#include "common.h"

// Function to parse PE file
int parse_pe_file(const char *filepath, PEInfo *pe_info)

{

    uint8_t sha256hash[32]; // for the SHA256
    // char sha256string[64] = {NULL};
    char sha256string[64] = {0};
    uint8_t md5hash[16]; // 256 bits = 32 bytes change this to 128 bits 16 bytes for MD5
    // char md5string[32] = {NULL};
    char md5string[32] = {0};

    FILE *file = fopen(filepath, "rb");
    if (!file)
    {
        fprintf(stderr, "Cannot open file: %s\n", filepath);
        return -1;
    }

    // calculate the sha256 hash
    if (calculate_file_sha256(filepath, sha256hash) == 0)
    {
        for (int i = 0; i < 32; ++i) // change this 32 to 16 for MD5
        {
            sprintf(sha256string, "%s%02x", sha256string, sha256hash[i]);
        }
        strncpy(pe_info->sha256hashstring, sha256string, sizeof(sha256string));
    }

    // calculate the MD5 hash
    if (calculate_file_md5(filepath, md5hash) == 0)
    {
        for (int i = 0; i < 16; ++i) // change this to 16 for MD5
        {
            sprintf(md5string, "%s%02x", md5string, md5hash[i]);
        }
        // store the md5 hash string
        strncpy(pe_info->md5hashstring, md5string, sizeof(md5string));
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
        return STATUS_ERROR;
    }

    // Check DOS signature
    if (dos_header.e_magic != DOS_SIGNATURE)
    {
        fprintf(stderr, "Not a valid DOS executable\n");
        fclose(file);
        return STATUS_ERROR;
    }

    // Seek to PE header
    // printf ("Seeking to the PE header\n");
    fseek(file, dos_header.e_lfanew, SEEK_SET);

    // Read PE Signature
    // printf ("Reading PE signature\n");
    uint16_t pe_signature;
    if (fread(&pe_signature, sizeof(uint16_t), 1, file) != 1) // this is the root cause of a file missalignment
                                                              //  PE signature is 4 bytes not 2
    {
        fprintf(stderr, "Failed to read PE signature\n");
        fclose(file);
        return 0;
    }

    // Verify PE Signature
    // printf ("Verifying Signature\n");
    if (pe_signature != PE_SIGNATURE)
    {
        fprintf(stderr, "Invalid PE signature\n");
        fclose(file);
        return 0;
    }
    // move past the \0\0 of the PE signature
    // printf ("Advancing two bytes\n");
    fseek(file, 2, SEEK_CUR);

    // Read COFF Header
    // printf ("Reading COFF header\n");
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

    // printf ("Optional Header Size %x\n", coff_header.SizeOfOptionalHeader);
    //  Determine if 32-bit or 64-bit
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
        // printf ("RVA number %d\n",optional_header.NumberOfRVAAndSizes);
        pe_info->number_of_rva_directories = optional_header.NumberOfRVAAndSizes;
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
        // printf ("RVA number %d\n",optional_header.NumberOfRVAAndSizes);
        pe_info->number_of_rva_directories = optional_header.NumberOfRVAAndSizes;
    }

    // TODO -----------------------------------
    //  add code for accessing the RVA directory
    RVA_Directories rva_dirs;
    fread(&rva_dirs, sizeof(RVA_Data_Directory) * pe_info->number_of_rva_directories, 1, file);

    // TODO -----------------------------------

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
        pe_info->sections[i].PointerToRawData = section_header.PointerToRawData;
        pe_info->sections[i].raw_size = section_header.SizeOfRawData;
        pe_info->sections[i].characteristics = section_header.Characteristics;

        pe_info->section_count++;
    }

    fclose(file); // end of header information, section data is after this
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
    printf("SHA256 Hash value: %s\n", pe_info->sha256hashstring);
    printf("MD5 hash value: %s\n", pe_info->md5hashstring);

    printf("\nCOFF Header:\n");
    printf("  Machine: 0x%04X (%s)\n", pe_info->machine,
           pe_info->machine == IMAGE_FILE_MACHINE_I386 ? "x86" : pe_info->machine == IMAGE_FILE_MACHINE_AMD64 ? "x64"
                                                                                                              : "Unknown");
    printf("  Timestamp: %u\n", pe_info->timestamp); // TODO convert this into a human readable time format
    printf("  Number of Sections: %d\n", pe_info->number_of_sections);
    printf("  Characteristics: 0x%04X\n", pe_info->characteristics);

    printf("\nOptional Header:\n");
    printf("  Magic: 0x%04X\n", pe_info->magic);
    printf("  Size of Code: %u\n", pe_info->size_of_code);
    printf("  Entry Point: 0x%08X\n", pe_info->entry_point);
    printf("  Image Base: 0x%08X\n", pe_info->image_base);

    printf("\nSections:\n");
    for (int i = 0; i < pe_info->section_count; i++)
    {
        printf("  Section %d:\n", i + 1);
        printf("    Name: %s\n", pe_info->sections[i].name);
        printf("    Virtual Size: %u\n", pe_info->sections[i].virtual_size);
        printf("    Virtual Address: 0x%08X\n", pe_info->sections[i].virtual_address);
        printf("    Pointer to raw data: 0x%08X\n", pe_info->sections[i].PointerToRawData);
        printf("    Raw Size: %u\n", pe_info->sections[i].raw_size);
        printf("    Entropy: %f\n", pe_info->sections[i].entropy);
        printf("    Characteristics: 0x%08X\n", pe_info->sections[i].characteristics); // TODO -make this human readable
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
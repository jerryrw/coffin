/*
 * Read the outer structure of a Windows Portable Executable (PE) file.
 * PE starts with a DOS header, whose e_lfanew field points to the PE signature.
 * A COFF header and an "optional" header follow; the latter is required here.
 * Sections describe both disk storage and memory layout. Detailed import, export,
 * and resource parsing lives in pe_details.c; presentation lives in report.c.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "peparser.h"

/*
 * Fill info from checked byte arrays rather than fread-ing whole C structs.
 * memset makes every pointer NULL so cleanup works on partially parsed input.
 * On failure this routine frees its arrays; the caller may safely clean up again.
 */
int parse_pe_file(const InputFile *input, PEInfo *info)
{
    unsigned char dos[64], coff[20], optional[112], section[40], signature[4];
    memset(info, 0, sizeof(*info));
    escape_display(info->filename, sizeof(info->filename), (const unsigned char *)input->path, strlen(input->path));
    info->file_size = input->size;
    strcpy(info->sha256hashstring, input->sha256);
    strcpy(info->md5hashstring, input->md5);
    if (parser_read(input, 0, dos, sizeof(dos)) != STATUS_SUCCESS ||
        decode16(dos) != DOS_SIGNATURE) goto invalid;
    /*
     * DOS byte offset 60 holds e_lfanew, the file offset of the PE signature.
     * Use 64-bit arithmetic for later additions even though this field is 32-bit.
     */
    uint64_t pe = decode32(dos + 60);
    if (pe < sizeof(dos) || pe > INT32_MAX ||
        parser_read(input, pe, signature, sizeof(signature)) != STATUS_SUCCESS ||
        decode32(signature) != PE_SIGNATURE ||
        parser_read(input, pe + 4, coff, sizeof(coff)) != STATUS_SUCCESS)
        goto invalid;
    info->machine = decode16(coff);
    info->number_of_sections = decode16(coff + 2);
    info->timestamp = decode32(coff + 4);
    info->characteristics = decode16(coff + 18);
    uint16_t optional_size = decode16(coff + 16);
    uint64_t optional_offset = pe + 24;
    if (optional_size < 2 || !file_range_valid(optional_offset, optional_size, input->size) ||
        parser_read(input, optional_offset, optional, 2) != STATUS_SUCCESS)
        goto invalid;
    info->magic = decode16(optional);
    if (info->magic != PE32_MAGIC && info->magic != PE32PLUS_MAGIC) {
        fprintf(stderr, "Unsupported PE optional-header magic: 0x%04X\n", info->magic);
        return STATUS_ERROR;
    }
    info->is_64bit = info->magic == PE32PLUS_MAGIC;
    /*
     * The ternary operator chooses a value: condition ? if_true : if_false.
     * PE32+ has a wider image base and a different fixed optional-header length;
     * section RVAs and raw file offsets remain 32-bit in either variant.
     */
    size_t fixed = info->is_64bit ? 112 : 96;
    if (optional_size < fixed ||
        parser_read(input, optional_offset, optional, fixed) != STATUS_SUCCESS)
        goto invalid;
    info->size_of_code = decode32(optional + 4);
    info->entry_point = decode32(optional + 16);
    info->image_base = info->is_64bit ? decode64(optional + 24) : decode32(optional + 28);
    info->number_of_rva_directories = decode32(optional + fixed - 4);
    if (info->number_of_rva_directories > 16 ||
        info->number_of_rva_directories > (optional_size - fixed) / 8) goto invalid;
    info->size_of_headers = decode32(optional + 60);
    unsigned char directory[8];
    for (unsigned i = 0; i < info->number_of_rva_directories; ++i) {
        if (parser_read(input, optional_offset + fixed + i * 8, directory, 8) != STATUS_SUCCESS)
            goto invalid;
        info->directories[i].VirtualAddress = decode32(directory);
        info->directories[i].Size = decode32(directory + 4);
    }
    /*
     * The declared optional-header size may include extra padding. Skip all of
     * it to locate the section table, rather than assuming a C struct's size.
     */
    uint64_t sections = optional_offset + optional_size;
    info->section_table_offset = sections;
    if (!file_range_valid(sections, (uint64_t)info->number_of_sections * 40, input->size))
        goto invalid;
    for (unsigned i = 0; i < info->number_of_sections; ++i) {
        if (parser_read(input, sections + (uint64_t)i * 40, section, sizeof(section)) != STATUS_SUCCESS)
            goto invalid;
        uint32_t raw_size = decode32(section + 16), raw_offset = decode32(section + 20);
        if (raw_size && !file_range_valid(raw_offset, raw_size, input->size)) goto invalid;
        if (reserve_array(input, (void **)&info->sections, &info->section_capacity, i + 1, sizeof(*info->sections)) != STATUS_SUCCESS)
            goto invalid;
        memset(&info->sections[i], 0, sizeof(info->sections[i]));
        /*
         * Disk names occupy exactly eight bytes and need not end in zero.
         * The destination allows four display characters per escaped byte plus zero.
         */
        escape_display(info->sections[i].name, sizeof(info->sections[i].name), section, 8);
        info->sections[i].virtual_size = decode32(section + 8);
        info->sections[i].virtual_address = decode32(section + 12);
        info->sections[i].raw_size = raw_size;
        info->sections[i].PointerToRawData = raw_offset;
        info->sections[i].characteristics = decode32(section + 36);
        info->section_count++;
    }
    if (parse_pe_details(input, info) != STATUS_SUCCESS) goto invalid;
    return STATUS_SUCCESS;
invalid:
    free_pe_info(info);
    fprintf(stderr, "Invalid or truncated PE headers or section data\n");
    return STATUS_ERROR;
}

/*
 * Print the older, expanded field listing used by an unfiltered --verbose report.
 * The compact/default rendering is in report.c. gmtime formats timestamps in UTC;
 * if the platform cannot represent the date, retain the numeric timestamp.
 */
void print_pe_info(const PEInfo *pe_info, int previews)
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
    time_t stamp = (time_t)pe_info->timestamp;
    struct tm *utc = gmtime(&stamp);
    char date[32];
    if (utc && strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S UTC", utc))
        printf("  Timestamp: %u (%s)\n", pe_info->timestamp, date);
    else printf("  Timestamp: %u\n", pe_info->timestamp);
    printf("  Number of Sections: %d\n", pe_info->number_of_sections);
    printf("  Characteristics: 0x%04X (%s%s%s)\n", pe_info->characteristics,
           pe_info->characteristics & 0x2 ? "executable " : "",
           pe_info->characteristics & 0x2000 ? "DLL " : "",
           pe_info->characteristics & 0x100 ? "32-bit-machine" : "");

    printf("\nOptional Header:\n");
    printf("  Magic: 0x%04X\n", pe_info->magic);
    printf("  Size of Code: %u\n", pe_info->size_of_code);
    printf("  Entry Point: 0x%08X (RVA)\n", pe_info->entry_point);
    printf("  Image Base: 0x%0*llX (VA)\n", pe_info->is_64bit ? 16 : 8, (unsigned long long)pe_info->image_base);

    printf("\nSections:\n");
    for (int i = 0; i < pe_info->section_count; i++)
    {
        printf("  Section %d:\n", i + 1);
        printf("    Name: %s\n", pe_info->sections[i].name);
        printf("    Virtual Size: %u\n", pe_info->sections[i].virtual_size);
        printf("    Virtual Address: 0x%08X (RVA)\n", pe_info->sections[i].virtual_address);
        printf("    Pointer to raw data: 0x%08X\n", pe_info->sections[i].PointerToRawData);
        printf("    Raw Size: %u\n", pe_info->sections[i].raw_size);
        if (!pe_info->sections[i].raw_size) puts("    Entropy: N/A (no file bytes)");
        else printf("    Entropy: %f bits/byte (raw file bytes, including padding)\n", pe_info->sections[i].entropy);
        printf("    Declared permissions: ");
        print_permissions(pe_info->sections[i].characteristics, 0x40000000, 0x80000000, 0x20000000);
        printf("\n");
        printf("    Characteristics: 0x%08X\n", pe_info->sections[i].characteristics);
    }
    print_pe_details(pe_info, previews);
}

/*
 * Release the arrays owned by PEInfo, not the PEInfo object itself.
 * free(NULL) is allowed. Clearing pointers and counts makes repeated cleanup safe;
 * the InputFile stream remains the caller's responsibility.
 */
void free_pe_info(PEInfo *info)
{
    free(info->sections); free(info->imports); free(info->exports); free(info->resources);
    info->sections = NULL; info->imports = NULL; info->exports = NULL; info->resources = NULL;
    info->section_count = 0; info->import_count = info->export_count = info->resource_count = 0;
    info->section_capacity = info->import_capacity = info->export_capacity = info->resource_capacity = 0;
}

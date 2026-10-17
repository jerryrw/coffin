/*
 * Windows PE vocabulary, parsed results, and parser/resource APIs.
 * A typedef gives a struct a convenient name; the struct groups related fields.
 * The layout-shaped types below document the format but are NOT read directly
 * from disk: compiler padding and host byte order could differ. Parsing decodes
 * fixed byte offsets into normalized results instead. RVA means image-relative
 * virtual address; raw offsets refer to disk. Result arrays belong to PEInfo.
 */

// https://stackoverflow.com/questions/76815878/understanding-sizeofheaders
// https://0xrick.github.io/win-internals/pe4/
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
// https://tech-zealots.com/malware-analysis/pe-portable-executable-structure-malware-analysis-part-2/
// https://tech-zealots.com/malware-analysis/journey-towards-import-address-table-of-an-executable-file/
// https://0xrick.github.io/win-internals/pe8/

#ifndef PEPARSER_H
#define PEPARSER_H

#include <stdint.h>
#include "common.h" // Shared InputFile and STATUS_* definitions

// PE File Constants
#define PE_SIGNATURE 0x4550  // "PE\0\0"
#define DOS_SIGNATURE 0x5A4D // "MZ"

// Machine Types
#define IMAGE_FILE_MACHINE_I386 0x014C
#define IMAGE_FILE_MACHINE_AMD64 0x8664

// Magic Numbers for Optional Header
#define PE32_MAGIC 0x010B
#define PE32PLUS_MAGIC 0x020B

/*
 * DOS compatibility fields describe the old executable stub. The PE parser
 * uses e_magic and e_lfanew; it does not run the DOS program.
 */
// Structure definitions to match PE file structure
typedef struct
{
    uint16_t e_magic;    // Magic number
    uint16_t e_cblp;     // Bytes on last page of file
    uint16_t e_cp;       // Pages in file
    uint16_t e_crlc;     // Relocations
    uint16_t e_cparhdr;  // Size of header in paragraphs
    uint16_t e_minalloc; // Minimum extra paragraphs needed
    uint16_t e_maxalloc; // Maximum extra paragraphs needed
    uint16_t e_ss;       // Initial (relative) SS value
    uint16_t e_sp;       // Initial SP value
    uint16_t e_csum;     // Checksum
    uint16_t e_ip;       // Initial IP value
    uint16_t e_cs;       // Initial (relative) CS value
    uint16_t e_lfarlc;   // File address of relocation table
    uint16_t e_ovno;     // Overlay number
    uint16_t e_res[4];   // Reserved words
    uint16_t e_oemid;    // OEM identifier (for e_oeminfo)
    uint16_t e_oeminfo;  // OEM information
    uint16_t e_res2[10]; // Reserved words
    int32_t e_lfanew;    // File address of new exe header
} DOS_Header;

typedef struct
{
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} COFF_Header;

/*
 * Each directory advertises a location and byte size. Most locations are RVAs;
 * the certificate-table convention is a file offset and is not decoded here.
 */
// for the RVA data array
typedef struct
{
    uint32_t VirtualAddress;
    uint32_t Size;
} RVA_Data_Directory;

// RVA Directories
typedef struct
{
    RVA_Data_Directory ExportTable;
    RVA_Data_Directory ImportTable;
    RVA_Data_Directory ResourceTable;
    RVA_Data_Directory ExceptionTable;
    RVA_Data_Directory CertificateTable;
    RVA_Data_Directory BaseRelocationTable;
    RVA_Data_Directory Debug;
    RVA_Data_Directory Architecture; // must be 0
    RVA_Data_Directory GlobalPointer;
    RVA_Data_Directory TLSTable;
    RVA_Data_Directory LoadConfigTable;
    RVA_Data_Directory BoundImport;
    RVA_Data_Directory IAT;
    RVA_Data_Directory DelayImportDescriptor;
    RVA_Data_Directory CLRRuntimeHeader;
    RVA_Data_Directory Reserved; // must be 0
} RVA_Directories;

/*
 * The "optional header" is historical terminology: executable images need it.
 * PE32 and PE32+ have different field widths and omit BaseOfData in PE32+.
 */
// Optional Header for 32-bit
typedef struct
{
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData; // Not present in 64-bit
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    // added
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsytemVersion;
    uint16_t MinorSubsytemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DLLCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRVAAndSizes;

} Optional_Header32;

// Optional Header for 64-bit
typedef struct
{
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    // added
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsytemVersion;
    uint16_t MinorSubsytemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DLLCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRVAAndSizes;

} Optional_Header64;

typedef struct
{
    /*
     * This on-disk name may fill all eight bytes without a string terminator.
     */
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} Section_Header;

typedef struct {
    /*
     * Bounded, terminal-escaped display strings. by_ordinal selects ordinal instead
     * of name; hint is only a name-lookup hint. delay_load records descriptor kind.
     */
    char dll[256], name[256];
    uint16_t ordinal, hint;
    int by_ordinal, delay_load;
} PEImport;

typedef struct {
    /*
     * An export may have no name, or forward to a DLL!symbol instead of local code.
     * Several names can alias one ordinal; ordinal is widened to avoid base+index wrap.
     */
    char name[256], forwarder[256];
    uint64_t ordinal;
    uint32_t rva;
} PEExport;

typedef struct {
    /*
     * Display path and preview are bounded strings; file_offset/size locate the
     * original payload. IDs retain numeric type/name/language for image resolution.
     */
    char path[768];
    uint32_t rva, size, codepage, type_id, name_id, language_id;
    char decoded[2048];
    uint64_t file_offset;
} PEResource;

typedef struct
{
    char name[33]; // Up to eight escaped bytes plus a null terminator
    /*
     * Memory bytes and raw file bytes are different extents. virtual_address is
     * an RVA; PointerToRawData is an absolute disk offset.
     */
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t PointerToRawData;
    uint32_t raw_size;
    uint32_t characteristics;
    /*
     * Raw-byte entropy in bits/byte; NAN marks a section with no measured bytes.
     */
    double entropy;
} PESection;

// Comprehensive PE File Information Structure
// this is where the data to be printed lives
typedef struct
{
    char filename[256];
    size_t file_size;

    // Identification
    uint16_t machine;
    int is_64bit;
    char sha256hashstring[256];
    char md5hashstring[256];

    // COFF Header Information
    uint32_t timestamp;
    uint16_t number_of_sections;
    uint16_t characteristics;

    // Optional Header Information
    uint16_t magic;
    uint32_t size_of_code;
    uint32_t entry_point;
    uint64_t image_base;
    uint32_t number_of_rva_directories;
    /*
     * Owned heap arrays: count is initialized entries; capacity is allocated slots.
     * reserve_array can grow storage, so callers must not keep pointers across growth.
     */
    PESection *sections;
    unsigned section_capacity;
    int section_count;
    uint64_t section_table_offset;
    uint32_t size_of_headers;
    RVA_Data_Directory directories[16];
    PEImport *imports;
    PEExport *exports;
    PEResource *resources;
    unsigned import_capacity, export_capacity, resource_capacity;
    unsigned import_count, export_count, resource_count;
    unsigned import_total, export_total, resource_total, delay_import_count;
    char export_dll[256];
} PEInfo;

/*
 * On reconstruction success, the caller owns *data and must free it. On error
 * outputs are NULL/zero. decode_resource_payload writes only a bounded preview.
 */
int reconstruct_resource_image(const InputFile *input, const PEInfo *info, unsigned index, unsigned char **data, size_t *size);
int decode_resource_payload(const InputFile *input, PEResource *resource);
/*
 * Collect returns an owned copy; extraction writes to a new private directory.
 */
int collect_pe_resources(const InputFile *input, const PEInfo *info, PEResource **resources);
int extract_pe_resources(const InputFile *input, const PEInfo *info, const char *directory);
/*
 * Free owned arrays, not info or the borrowed input. Parse initializes info
 * and leaves it safe to free even when parsing fails.
 */
void free_pe_info(PEInfo *info);
int parse_pe_file(const InputFile *input, PEInfo *pe_info);
int parse_pe_details(const InputFile *input, PEInfo *info);
void print_pe_details(const PEInfo *info, int previews);
void print_pe_info(const PEInfo *pe_info, int previews);

#endif

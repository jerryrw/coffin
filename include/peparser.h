// https://stackoverflow.com/questions/76815878/understanding-sizeofheaders
// https://0xrick.github.io/win-internals/pe4/
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
// https://tech-zealots.com/malware-analysis/pe-portable-executable-structure-malware-analysis-part-2/
// https://tech-zealots.com/malware-analysis/journey-towards-import-address-table-of-an-executable-file/
// https://0xrick.github.io/win-internals/pe8/

#ifndef PEPARSER_H
#define PEPARSER_H
// PE File Constants
#define PE_SIGNATURE 0x4550  // "PE\0\0"
#define DOS_SIGNATURE 0x5A4D // "MZ"

// Machine Types
#define IMAGE_FILE_MACHINE_I386 0x014C
#define IMAGE_FILE_MACHINE_AMD64 0x8664

// Magic Numbers for Optional Header
#define PE32_MAGIC 0x010B
#define PE32PLUS_MAGIC 0x020B

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

// Comprehensive PE File Information Structure
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
    // Sections
    struct
    {
        char name[9]; // 8 chars + null terminator
        uint32_t virtual_size;
        uint32_t virtual_address;
        uint32_t raw_size;
        uint32_t characteristics;
    } sections[16]; // Assuming max 16 sections
    int section_count;
} PEInfo;

int parse_pe_file(const char *filepath, PEInfo *pe_info);
void print_pe_info(const PEInfo *pe_info);

#endif
#ifndef MACHPARSER_H
#define MACHPARSER_H

#include <stdint.h>

#define MACHO_MAGIC 0xfeedface
#define MACHO_MAGIC_64 0xfeedfacf

// Load Command Types
#define LC_SEGMENT 0x1
#define LC_SEGMENT_64 0x19

// Mach-O Header (32-bit)
typedef struct __attribute__((packed))
{
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
} MachOHeader32;

// Mach-O Header (64-bit)
typedef struct __attribute__((packed))
{
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
} MachOHeader64;

// Load Command header
typedef struct __attribute__((packed))
{
    uint32_t cmd;
    uint32_t cmdsize;
} LoadCommand;

// Segment Command (32-bit)
typedef struct __attribute__((packed))
{
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint32_t vmaddr;
    uint32_t vmsize;
    uint32_t fileoff;
    uint32_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
} Segment;

// Segment Command (64-bit)
typedef struct __attribute__((packed))
{
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
} Segment64;

// Mach-O Info structure
typedef struct
{
    char filename[256];
    size_t file_size;
    char sha256hashstring[65];
    char md5hashstring[33];
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    int is_64bit;

    struct
    {
        uint32_t cmd;
        uint32_t cmdsize;
        union
        {
            Segment segment;
            Segment64 segment64;
        } data;
    } load_commands[16];
    int load_cmd_count;
} MachOInfo;

// Function declarations
int parse_mach_file(const char *filepath, MachOInfo *mach_info);
void print_mach_info(const MachOInfo *mach_info);

#endif // MACHPARSER_H
/*
 * Mach-O metadata and ownership declarations for thin and universal files.
 * Disk layouts are decoded explicitly instead of reading these C structures whole.
 * A pointer is an address of another object; *Info owns its dynamic arrays, while
 * InputFile is borrowed. A universal MachOInfo also owns an array of thin results.
 * An offset inside a slice must be added to slice_offset before reading the file.
 */

#ifndef MACHPARSER_H
#define MACHPARSER_H

#include <stdint.h>
#include "common.h"

#define MACHO_MAGIC 0xfeedface
#define MACHO_MAGIC_64 0xfeedfacf

// Load Command Types
#define LC_SEGMENT 0x1
#define LC_SEGMENT_64 0x19

// Mach-O Header (32-bit)
typedef struct
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
typedef struct
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
typedef struct
{
    uint32_t cmd;
    uint32_t cmdsize;
} LoadCommand;

// Segment Command (32-bit)
typedef struct
{
    uint32_t cmd;
    uint32_t cmdsize;
    /*
     * Raw segment names can occupy all 16 bytes; print with a bounded %.16s.
     */
    char segname[16];
    uint32_t vmaddr;
    uint32_t vmsize;
    uint32_t fileoff;
    uint32_t filesize;
    /*
     * maxprot is the declared maximum; initprot is the initial permission mask.
     * These describe loader metadata, not the state of a running process.
     */
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
} Segment;

// Segment Command (64-bit)
typedef struct
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

typedef struct {
    /*
     * Normalized names have one extra byte for a guaranteed C string terminator.
     */
    char name[17], segment[17];
    uint64_t address, size;
    uint32_t offset, alignment, flags, relocation_offset, relocation_count, protection;
    /*
     * A true zero-fill flag means size is a memory extent with no file payload.
     */
    int zerofill;
} MachOSection;

typedef struct
{
    uint32_t cmd;
    uint32_t cmdsize;
    /*
     * A union shares storage between alternatives. cmd determines which member
     * (segment or segment64) was written and may safely be read.
     */
    union
    {
        Segment segment;
        Segment64 segment64;
    } data;
} MachOLoadCommand;

// Mach-O Info structure
typedef struct MachOInfo
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
    int is_64bit, big_endian;

    MachOLoadCommand *load_commands;
    unsigned command_capacity, section_capacity;
    int load_cmd_count;
    MachOSection *sections;
    unsigned section_count, section_total;
    /*
     * A pointer to the same struct type permits a tree of results. This array
     * is owned by the universal parent; thin images leave it NULL.
     */
    struct MachOInfo *slices;
    unsigned slice_count;
    uint64_t slice_offset, slice_size;
    /*
     * LC_MAIN supplies a slice file offset; translating through a segment can
     * also produce a VA. The has_* flags distinguish absence from a numeric zero.
     */
    uint64_t entry_file_offset, entry_address;
    int has_entry, has_entry_address;
} MachOInfo;

/*
 * Parse initializes the result and cleanup releases all arrays recursively.
 * These functions borrow the open InputFile; they do not close it.
 */
// Function declarations
int parse_mach_file(const InputFile *input, MachOInfo *mach_info);
void free_mach_info(MachOInfo *info);
void print_mach_info(const MachOInfo *mach_info);

#endif // MACHPARSER_H

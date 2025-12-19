#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "sha256.h"
#include "md5.h"
#include "machparser.h"
#include "common.h"

// Function to parse Mach-O file
int parse_mach_file(const char *filepath, MachOInfo *mach_info)
{
    fprintf(stderr, "DEBUG: parse_mach_file called with filepath=%s\n", filepath);

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
        strncpy(mach_info->sha256hashstring, sha256string, sizeof(mach_info->sha256hashstring) - 1);
        mach_info->sha256hashstring[sizeof(mach_info->sha256hashstring) - 1] = '\0';
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
        strncpy(mach_info->md5hashstring, md5string, sizeof(mach_info->md5hashstring) - 1);
        mach_info->md5hashstring[sizeof(mach_info->md5hashstring) - 1] = '\0';
    }

    // Get file size
    fprintf(stderr, "DEBUG: About to seek\n");
    fseek(file, 0, SEEK_END);
    mach_info->file_size = ftell(file);
    rewind(file);
    fprintf(stderr, "DEBUG: File size=%zu\n", mach_info->file_size);

    // Store filename
    strncpy(mach_info->filename, filepath, sizeof(mach_info->filename) - 1);

    // Read Mach-O Header - read magic first to determine size
    uint32_t magic;
    if (fread(&magic, sizeof(uint32_t), 1, file) != 1)
    {
        fprintf(stderr, "Failed to read Mach-O magic\n");
        fclose(file);
        return -1;
    }
    rewind(file);

    fprintf(stderr, "DEBUG: magic=0x%08X\n", magic);

    // Check Mach-O magic
    if (magic != MACHO_MAGIC && magic != MACHO_MAGIC_64)
    {
        fprintf(stderr, "Not a valid Mach-O file (magic: 0x%08X)\n", magic);
        fclose(file);
        return -1;
    }

    // Determine if 32-bit or 64-bit
    int is_64bit = (magic == MACHO_MAGIC_64);
    fprintf(stderr, "DEBUG: is_64bit=%d\n", is_64bit);

    uint32_t cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags;
    
    if (is_64bit)
    {
        MachOHeader64 mach_header;
        if (fread(&mach_header, sizeof(MachOHeader64), 1, file) != 1)
        {
            fprintf(stderr, "Failed to read 64-bit Mach-O header\n");
            fclose(file);
            return -1;
        }
        cputype = mach_header.cputype;
        cpusubtype = mach_header.cpusubtype;
        filetype = mach_header.filetype;
        ncmds = mach_header.ncmds;
        sizeofcmds = mach_header.sizeofcmds;
        flags = mach_header.flags;
    }
    else
    {
        MachOHeader32 mach_header;
        if (fread(&mach_header, sizeof(MachOHeader32), 1, file) != 1)
        {
            fprintf(stderr, "Failed to read 32-bit Mach-O header\n");
            fclose(file);
            return -1;
        }
        cputype = mach_header.cputype;
        cpusubtype = mach_header.cpusubtype;
        filetype = mach_header.filetype;
        ncmds = mach_header.ncmds;
        sizeofcmds = mach_header.sizeofcmds;
        flags = mach_header.flags;
    }

    fprintf(stderr, "DEBUG: Mach-O header read successfully\n");

    // Store Mach-O header info
    mach_info->magic = magic;
    mach_info->cputype = cputype;
    mach_info->cpusubtype = cpusubtype;
    mach_info->filetype = filetype;
    mach_info->ncmds = ncmds;
    mach_info->sizeofcmds = sizeofcmds;
    mach_info->flags = flags;
    mach_info->is_64bit = is_64bit;

    fprintf(stderr, "DEBUG: cputype=0x%08X, filetype=0x%08X, ncmds=%d\n",
            cputype, filetype, ncmds);

    // Read Load Commands
    mach_info->load_cmd_count = 0;
    uint32_t offset = is_64bit ? sizeof(MachOHeader64) : sizeof(MachOHeader32);

    for (int i = 0; i < ncmds && i < 16; ++i)
    {
        LoadCommand cmd;
        fseek(file, offset, SEEK_SET);
        if (fread(&cmd, sizeof(LoadCommand), 1, file) != 1)
        {
            break;
        }

        mach_info->load_commands[i].cmd = cmd.cmd;
        mach_info->load_commands[i].cmdsize = cmd.cmdsize;

        // Read specific command data based on type
        if (cmd.cmd == LC_SEGMENT || cmd.cmd == LC_SEGMENT_64)
        {
            fseek(file, offset, SEEK_SET);
            if (is_64bit)
            {
                Segment64 seg;
                if (fread(&seg, sizeof(Segment64), 1, file) == 1)
                {
                    mach_info->load_commands[i].data.segment64 = seg;
                }
            }
            else
            {
                Segment seg;
                if (fread(&seg, sizeof(Segment), 1, file) == 1)
                {
                    mach_info->load_commands[i].data.segment = seg;
                }
            }
        }

        offset += cmd.cmdsize;
        mach_info->load_cmd_count++;
    }

    fclose(file);
    return 1;
}

// Print Mach-O file information
void print_mach_info(const MachOInfo *mach_info)
{
    printf("Mach-O File Analysis Report\n");
    printf("===========================\n");
    printf("Filename: %s\n", mach_info->filename);
    printf("File Size: %zu bytes\n", mach_info->file_size);
    printf("SHA256 Hash: %s\n", mach_info->sha256hashstring);
    printf("MD5 Hash: %s\n", mach_info->md5hashstring);

    printf("\nMach-O Header:\n");
    printf("  Magic: 0x%08X\n", mach_info->magic);
    printf("  Architecture: %s\n", mach_info->is_64bit ? "64-bit" : "32-bit");
    printf("  CPU Type: 0x%08X\n", mach_info->cputype);
    printf("  CPU Subtype: 0x%08X\n", mach_info->cpusubtype);
    printf("  File Type: 0x%08X\n", mach_info->filetype);
    printf("  Number of Commands: %d\n", mach_info->ncmds);
    printf("  Size of Commands: %u\n", mach_info->sizeofcmds);
    printf("  Flags: 0x%08X\n", mach_info->flags);

    printf("\nLoad Commands:\n");
    for (int i = 0; i < mach_info->load_cmd_count; ++i)
    {
        printf("  Command %d:\n", i + 1);
        printf("    Type: 0x%08X\n", mach_info->load_commands[i].cmd);
        printf("    Size: %u\n", mach_info->load_commands[i].cmdsize);
    }
}
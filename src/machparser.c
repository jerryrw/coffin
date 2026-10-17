/*
 * Read Apple Mach-O files and universal containers holding several Mach-O images.
 * A thin image describes one architecture. Its load commands describe segments,
 * sections, and other metadata. A universal table points to separate thin slices.
 * Slice offsets start at their thin image; container offsets start at the file.
 * M32/M64 decode using the thin image's own byte order, not the computer's.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define M32(p) read32_order((p), big)
#define M64(p) read64_order((p), big)
#include "machparser.h"

/*
 * Read a slice-relative range only if it fits the slice, then translate it
 * into a container offset. Checking the complete file alone would allow one
 * architecture to read bytes belonging to another architecture.
 */
static int slice_read(const InputFile *input, uint64_t base, size_t slice_size,
                      uint64_t offset, void *out, size_t size)
{
    if (!file_range_valid(offset, size, slice_size)) return STATUS_ERROR;
    return parser_read(input, base + offset, out, size);
}

/*
 * Parse one architecture starting at base within input. For a standalone
 * Mach-O, base is zero; for a universal file, it is the slice's container offset.
 * Validate command lengths before advancing, then validate nested section ranges.
 */
static int parse_thin(const InputFile *input, MachOInfo *info, uint64_t base, size_t slice_size)
{
    unsigned char bytes[80];
    memset(info, 0, sizeof(*info));
    escape_display(info->filename, sizeof(info->filename), (const unsigned char *)input->path, strlen(input->path));
    info->file_size = slice_size;
    info->slice_offset = base; info->slice_size = slice_size;
    if (slice_read(input, base, slice_size, 0, bytes, 4) != STATUS_SUCCESS) goto invalid;
    uint32_t raw_magic = decode32(bytes);
    int big = raw_magic == 0xcefaedfe || raw_magic == 0xcffaedfe;
    info->big_endian = big;
    info->magic = read32_order(bytes, big);
    if (info->magic != MACHO_MAGIC && info->magic != MACHO_MAGIC_64) {
        fprintf(stderr, "Unsupported Mach-O variant: unrecognized Mach-O slice magic\n");
        return STATUS_ERROR;
    }
    info->is_64bit = info->magic == MACHO_MAGIC_64;
    uint64_t offset = info->is_64bit ? 32 : 28;
    if (slice_read(input, base, slice_size, 0, bytes, (size_t)offset) != STATUS_SUCCESS) goto invalid;
    info->cputype = M32(bytes + 4); info->cpusubtype = M32(bytes + 8);
    info->filetype = M32(bytes + 12); info->ncmds = M32(bytes + 16);
    info->sizeofcmds = M32(bytes + 20); info->flags = M32(bytes + 24);
    if (!file_range_valid(offset, info->sizeofcmds, slice_size) ||
        info->ncmds > info->sizeofcmds / 8) goto invalid;
    /*
     * A load command includes its own size. All commands must fit the declared
     * command area, satisfy 32/64-bit alignment, and consume that area exactly.
     * Without a positive minimum size, a malformed command could prevent progress.
     */
    uint64_t end = offset + info->sizeofcmds;
    for (uint32_t i = 0; i < info->ncmds; ++i) {
        if (!file_range_valid(offset, 8, end) ||
            slice_read(input, base, slice_size, offset, bytes, 8) != STATUS_SUCCESS) goto invalid;
        uint32_t cmd = M32(bytes), size = M32(bytes + 4);
        if (size < 8 || size % (info->is_64bit ? 8 : 4) ||
            !file_range_valid(offset, size, end)) goto invalid;
        if (cmd == 0x80000028u) { /* LC_MAIN: entryoff is relative to the thin image. */
            if (info->has_entry || size < 24 || slice_read(input, base, slice_size, offset, bytes, 24) != STATUS_SUCCESS)
                goto invalid;
            info->entry_file_offset = M64(bytes + 8);
            if (!file_range_valid(info->entry_file_offset, 1, slice_size)) goto invalid;
            info->has_entry = 1;
        }
        Segment seg = {0}; Segment64 seg64 = {0};
        if (cmd == LC_SEGMENT || cmd == LC_SEGMENT_64) {
            size_t fixed = cmd == LC_SEGMENT_64 ? 72 : 56;
            if ((cmd == LC_SEGMENT_64) != info->is_64bit || size < fixed ||
                slice_read(input, base, slice_size, offset, bytes, fixed) != STATUS_SUCCESS) goto invalid;
            uint64_t fileoff, filesize, count;
            if (info->is_64bit) {
                seg64.cmd = cmd; seg64.cmdsize = size;
                escape_display(seg64.segname, sizeof(seg64.segname), bytes + 8, 16);
                seg64.vmaddr = M64(bytes + 24); seg64.vmsize = M64(bytes + 32);
                seg64.fileoff = M64(bytes + 40); seg64.filesize = M64(bytes + 48);
                seg64.maxprot = M32(bytes + 56); seg64.initprot = M32(bytes + 60);
                seg64.nsects = M32(bytes + 64); seg64.flags = M32(bytes + 68);
                fileoff = seg64.fileoff; filesize = seg64.filesize; count = seg64.nsects;
            } else {
                seg.cmd = cmd; seg.cmdsize = size;
                escape_display(seg.segname, sizeof(seg.segname), bytes + 8, 16);
                seg.vmaddr = M32(bytes + 24); seg.vmsize = M32(bytes + 28);
                seg.fileoff = M32(bytes + 32); seg.filesize = M32(bytes + 36);
                seg.maxprot = M32(bytes + 40); seg.initprot = M32(bytes + 44);
                seg.nsects = M32(bytes + 48); seg.flags = M32(bytes + 52);
                fileoff = seg.fileoff; filesize = seg.filesize; count = seg.nsects;
            }
            if (count > (size - fixed) / (info->is_64bit ? 80 : 68) ||
                (filesize && !file_range_valid(fileoff, filesize, slice_size))) goto invalid;
            uint64_t segment_address = info->is_64bit ? seg64.vmaddr : seg.vmaddr;
            uint64_t segment_size = info->is_64bit ? seg64.vmsize : seg.vmsize;
            if (segment_size > UINT64_MAX - segment_address) goto invalid;
            for (uint64_t j = 0; j < count; ++j) {
                size_t width = info->is_64bit ? 80 : 68;
                if (slice_read(input, base, slice_size, offset + fixed + j * width, bytes, width) != STATUS_SUCCESS)
                    goto invalid;
                MachOSection section = {0};
                escape_display(section.name, sizeof(section.name), bytes, 16);
                escape_display(section.segment, sizeof(section.segment), bytes + 16, 16);
                size_t fields = info->is_64bit ? 48 : 40;
                section.address = info->is_64bit ? M64(bytes + 32) : M32(bytes + 32);
                section.size = info->is_64bit ? M64(bytes + 40) : M32(bytes + 36);
                section.offset = M32(bytes + fields); section.alignment = M32(bytes + fields + 4);
                section.relocation_offset = M32(bytes + fields + 8);
                section.relocation_count = M32(bytes + fields + 12);
                section.flags = M32(bytes + fields + 16);
                /*
                 * Only the low eight bits encode the section type; higher bits are attributes.
                 * Zero-fill section types have memory extent but no corresponding payload bytes.
                 */
                uint32_t type = section.flags & 0xff;
                section.zerofill = type == 1 || type == 0xc || type == 0x12;
                section.protection = info->is_64bit ? seg64.initprot : seg.initprot;
                if (section.address < segment_address ||
                    !file_range_valid(section.address - segment_address, section.size, segment_size) ||
                    section.alignment >= (info->is_64bit ? 64u : 32u) ||
                    (!section.zerofill && section.size &&
                     (!file_range_valid(section.offset, section.size, slice_size) ||
                      section.offset < fileoff ||
                      !file_range_valid(section.offset - fileoff, section.size, filesize))) ||
                    (section.relocation_count &&
                     !file_range_valid(section.relocation_offset,
                                       (uint64_t)section.relocation_count * 8, slice_size))) goto invalid;
                if (reserve_array(input, (void **)&info->sections, &info->section_capacity,
                                  info->section_count + 1, sizeof(section)) != STATUS_SUCCESS) goto invalid;
                info->sections[info->section_count++] = section;
                ++info->section_total;
            }
        }
        {
            if (reserve_array(input, (void **)&info->load_commands, &info->command_capacity,
                              i + 1, sizeof(*info->load_commands)) != STATUS_SUCCESS) goto invalid;
            memset(&info->load_commands[i], 0, sizeof(*info->load_commands));
            info->load_commands[i].cmd = cmd; info->load_commands[i].cmdsize = size;
            if (cmd == LC_SEGMENT) info->load_commands[i].data.segment = seg;
            if (cmd == LC_SEGMENT_64) info->load_commands[i].data.segment64 = seg64;
            info->load_cmd_count++;
        }
        offset += size;
    }
    if (offset != end) goto invalid;
    /*
     * LC_MAIN gives a file offset. Find the containing segment to translate that
     * offset to a virtual address: segment VA + (entry offset - segment file offset).
     * The subtraction and overflow check keep this translation within uint64_t.
     */
    if (info->has_entry) {
        for (int i = 0; i < info->load_cmd_count; ++i) {
            const MachOLoadCommand *command = &info->load_commands[i];
            if (command->cmd != LC_SEGMENT && command->cmd != LC_SEGMENT_64) continue;
            uint64_t fileoff = command->cmd == LC_SEGMENT_64 ? command->data.segment64.fileoff : command->data.segment.fileoff;
            uint64_t filesize = command->cmd == LC_SEGMENT_64 ? command->data.segment64.filesize : command->data.segment.filesize;
            uint64_t address = command->cmd == LC_SEGMENT_64 ? command->data.segment64.vmaddr : command->data.segment.vmaddr;
            if (info->entry_file_offset >= fileoff && info->entry_file_offset - fileoff < filesize &&
                info->entry_file_offset - fileoff <= UINT64_MAX - address) {
                info->entry_address = address + info->entry_file_offset - fileoff;
                info->has_entry_address = 1; break;
            }
        }
    }
    if (parse_mach_details(input, info) != STATUS_SUCCESS) goto invalid;
    return STATUS_SUCCESS;
invalid:
    free_mach_info(info);
    fprintf(stderr, "Invalid or truncated Mach-O header or load commands\n");
    return STATUS_ERROR;
}

/*
 * Decode a universal-table 32-bit field in the table's own byte order.
 * The table and its contained thin images need not use the same byte order.
 */
static uint32_t fat32(const unsigned char *p, int big)
{
    return big ? ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]) : decode32(p);
}

/*
 * Decode the wider offset/size fields used in a FAT64 architecture table.
 * As with fat32, no alignment-sensitive pointer cast is needed.
 */
static uint64_t fat64(const unsigned char *p, int big)
{
    return big ? ((uint64_t)fat32(p, 1) << 32 | fat32(p + 4, 1)) : decode64(p);
}

/*
 * Free each child slice before freeing the parent array, then clear pointers.
 * The recursive shape mirrors ownership: a universal result owns thin results;
 * a thin result owns load-command and section arrays.
 */
void free_mach_info(MachOInfo *info)
{
    for (unsigned i = 0; i < info->slice_count; ++i) free_mach_info(&info->slices[i]);
    free(info->dependencies); free(info->symbols);
    info->dependencies = NULL; info->symbols = NULL;
    info->dependency_count = info->dependency_capacity = info->symbol_count = info->symbol_capacity = 0;
    free(info->load_commands); free(info->sections);
    info->load_commands = NULL; info->sections = NULL;
    info->command_capacity = info->section_capacity = 0;
    info->load_cmd_count = 0; info->section_count = info->section_total = 0;
    free(info->slices);
    info->slices = NULL; info->slice_count = 0;
}

/*
 * Distinguish a standalone thin file from a universal architecture table.
 * For containers, validate every slice and check that its CPU matches its table
 * entry. parse_thin intentionally rejects nested universal containers.
 */
int parse_mach_file(const InputFile *input, MachOInfo *info)
{
    unsigned char bytes[32];
    memset(info, 0, sizeof(*info));
    if (parser_read(input, 0, bytes, 8) != STATUS_SUCCESS) goto invalid;
    uint32_t magic = decode32(bytes);
    int fat = magic == 0xbebafeca || magic == 0xcafebabe || magic == 0xbfbafeca || magic == 0xcafebabf;
    if (!fat) {
        int status = parse_thin(input, info, 0, input->size);
        if (status != STATUS_SUCCESS) return status;
    } else {
        int big = magic == 0xbebafeca || magic == 0xbfbafeca;
        int wide = magic == 0xbfbafeca || magic == 0xcafebabf;
        unsigned count = fat32(bytes + 4, big);
        size_t width = wide ? 32 : 20;
        uint64_t table_end = 8 + (uint64_t)count * width;
        /* Real universal binaries contain few architectures; bound allocations and validation. */
        if (!count || count > 64 || table_end > input->size) goto invalid;
        info->slices = calloc(count, sizeof(*info->slices));
        if (!info->slices) goto invalid;
        info->slice_count = count;
        for (unsigned i = 0; i < count; ++i) {
            if (parser_read(input, 8 + (uint64_t)i * width, bytes, width) != STATUS_SUCCESS)
                goto invalid;
            uint32_t cpu = fat32(bytes, big), subtype = fat32(bytes + 4, big);
            uint64_t offset = wide ? fat64(bytes + 8, big) : fat32(bytes + 8, big);
            uint64_t size = wide ? fat64(bytes + 16, big) : fat32(bytes + 12, big);
            uint32_t alignment = fat32(bytes + (wide ? 24 : 16), big);
            /*
             * Alignment is an exponent: alignment 4 means a multiple of 2^4 bytes.
             * Check the exponent before shifting 1 by it. Also exclude the architecture
             * table, out-of-file ranges, nonzero reserved fields, and empty slices.
             */
            if (!size || size > SIZE_MAX || offset < table_end || alignment >= 64 ||
                (offset & ((UINT64_C(1) << alignment) - 1)) ||
                (wide && fat32(bytes + 28, big)) ||
                !file_range_valid(offset, size, input->size)) goto invalid;
            /*
             * Compare with already parsed slices to reject overlapping file ranges or
             * duplicate CPU/subtype entries. With at most 64 slices, this simple pairwise
             * check is bounded and easier to follow than a separate interval data structure.
             */
            for (unsigned j = 0; j < i; ++j) {
                MachOInfo *other = &info->slices[j];
                if ((offset < other->slice_offset + other->slice_size && other->slice_offset < offset + size) ||
                    (cpu == other->cputype && subtype == other->cpusubtype)) goto invalid;
            }
            MachOInfo *slice = &info->slices[i];
            if (parse_thin(input, slice, offset, (size_t)size) != STATUS_SUCCESS ||
                slice->cputype != cpu || slice->cpusubtype != subtype) goto invalid;
        }
        info->file_size = input->size;
        escape_display(info->filename, sizeof(info->filename), (const unsigned char *)input->path, strlen(input->path));
    }
    strcpy(info->sha256hashstring, input->sha256);
    strcpy(info->md5hashstring, input->md5);
    return STATUS_SUCCESS;
invalid:
    free_mach_info(info);
    fprintf(stderr, "Invalid or truncated Mach-O input or universal architecture table (maximum 64 slices)\n");
    return STATUS_ERROR;
}

/*
 * Render full field details, visiting each slice if this is a universal file.
 * Raw 16-byte segment names have already become escaped, terminated strings.
 */
void print_mach_info(const MachOInfo *mach_info)
{
    if (mach_info->slice_count) {
        printf("Universal Mach-O File Analysis Report\nFilename: %s\nFile Size: %zu bytes\n", mach_info->filename, mach_info->file_size);
        printf("SHA256 Hash: %s\nMD5 Hash: %s\nArchitectures: %u\n", mach_info->sha256hashstring, mach_info->md5hashstring, mach_info->slice_count);
        for (unsigned i = 0; i < mach_info->slice_count; ++i) {
            const MachOInfo *slice = &mach_info->slices[i];
            printf("\nSlice %u: CPU 0x%08X, subtype 0x%08X, container offset 0x%llX, size %llu\n",
                   i + 1, slice->cputype, slice->cpusubtype, (unsigned long long)slice->slice_offset,
                   (unsigned long long)slice->slice_size);
            print_mach_info(slice);
        }
        return;
    }
    printf("Mach-O File Analysis Report\n");
    printf("===========================\n");
    printf("Filename: %s\n", mach_info->filename);
    printf("File Size: %zu bytes\n", mach_info->file_size);
    if (mach_info->sha256hashstring[0]) {
        printf("SHA256 Hash: %s\n", mach_info->sha256hashstring);
        printf("MD5 Hash: %s\n", mach_info->md5hashstring);
    }

    printf("\nMach-O Header:\n");
    printf("  Magic: 0x%08X\n", mach_info->magic);
    printf("  Architecture: %s\n", mach_info->is_64bit ? "64-bit" : "32-bit");
    printf("  Byte Order: %s\n", mach_info->big_endian ? "big-endian" : "little-endian");
    printf("  CPU Type: 0x%08X\n", mach_info->cputype);
    printf("  CPU Subtype: 0x%08X\n", mach_info->cpusubtype);
    printf("  File Type: 0x%08X\n", mach_info->filetype);
    printf("  Number of Commands: %u\n", mach_info->ncmds);
    printf("  Size of Commands: %u\n", mach_info->sizeofcmds);
    printf("  Flags: 0x%08X (%s%s%s)\n", mach_info->flags,
           mach_info->flags & 1 ? "no-undefined-symbols " : "",
           mach_info->flags & 4 ? "dynamic-link " : "",
           mach_info->flags & 0x200000 ? "PIE" : "");

    printf("\nLoad Commands:\n");
    for (int i = 0; i < mach_info->load_cmd_count; ++i)
    {
        printf("  Command %d:\n", i + 1);
        printf("    Type: 0x%08X\n", mach_info->load_commands[i].cmd);
        printf("    Size: %u\n", mach_info->load_commands[i].cmdsize);
        uint32_t cmd = mach_info->load_commands[i].cmd;
        if (cmd == LC_SEGMENT || cmd == LC_SEGMENT_64) {
            const char *name = cmd == LC_SEGMENT_64 ? mach_info->load_commands[i].data.segment64.segname :
                                                    mach_info->load_commands[i].data.segment.segname;
            uint32_t prot = cmd == LC_SEGMENT_64 ? mach_info->load_commands[i].data.segment64.initprot :
                                                  mach_info->load_commands[i].data.segment.initprot;
            printf("    Segment: %s\n    Declared permissions: ", name);
            print_permissions(prot, 1, 2, 4);
            printf("\n");
        }
    }
    printf("\nMach-O Sections: %u entries\n", mach_info->section_total);
    for (unsigned i = 0; i < mach_info->section_count; ++i) {
        const MachOSection *section = &mach_info->sections[i];
        printf("  %s,%s:\n", section->segment, section->name);
        printf("    Address: 0x%llX\n    Size: %llu\n",
               (unsigned long long)section->address, (unsigned long long)section->size);
        if (section->zerofill) printf("    Storage: zero-fill (no file bytes)\n");
        else printf("    Slice File Offset: 0x%016llX\n", (unsigned long long)section->offset);
        printf("    Alignment: 2^%u\n    Flags: 0x%08X\n", section->alignment, section->flags);
        printf("    Relocations: %u at 0x%08X\n", section->relocation_count, section->relocation_offset);
        printf("    Declared segment permissions: ");
        print_permissions(section->protection, 1, 2, 4);
        printf("\n");
    }
}

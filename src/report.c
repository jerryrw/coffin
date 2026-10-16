/*
 * Presentation layer: format validated parser results as human-readable reports.
 * Parsing and entropy calculation happen before these functions are called.
 * Selectors are bits in a mask: | combines choices and & tests whether one is set.
 * Compact tables use file offsets, RVAs, or VAs with explicit labels so these
 * three different coordinate systems are not accidentally treated as equivalent.
 */

#include <stdio.h>
#include <string.h>
#include <math.h>
#include "report.h"

/*
 * Decide whether a detail group should be printed. A summary suppresses details;
 * otherwise no explicit selection means "all," and a nonzero mask means only
 * chosen groups. Logical !, &&, || combine conditions; bitwise & tests a flag.
 */
static int wants(const ReportOptions *o, unsigned section)
{
    return !o->summary && (!o->selected || (o->selected & section));
}

/*
 * Reject selectors that the chosen file format cannot provide.
 * ~supported flips its bits; selected & ~supported isolates unsupported requests.
 */
int report_validate(const ReportOptions *options, unsigned supported)
{
    if (options->selected & ~supported) {
        fprintf(stderr, "A report selector is unsupported for this file format\n");
        return STATUS_ERROR;
    }
    return STATUS_SUCCESS;
}

/*
 * Translate ELF or Mach-O CPU numbers into labels. The mach switch selects
 * the numbering system, since the same numeric value can mean different things
 * in different file formats. Unknown values retain raw numbers in report fields.
 */
static const char *cpu(unsigned machine, int mach)
{
    if (mach) {
        switch (machine) {
        case 7: return "x86"; case 0x01000007: return "x86-64";
        case 12: return "ARM"; case 0x0100000c: return "AArch64";
        case 18: return "PowerPC"; case 0x01000012: return "PowerPC64";
        }
    } else {
        switch (machine) {
        case 3: case 0x14c: return "x86";
        case 62: case 0x8664: return "x86-64";
        case 40: case 0x1c0: case 0x1c4: return "ARM";
        case 183: case 0xaa64: return "AArch64";
        case 20: return "PowerPC"; case 21: return "PowerPC64";
        case 8: return "MIPS"; case 243: return "RISC-V";
        }
    }
    return "Unknown";
}

/*
 * Translate PE machine IDs separately from ELF IDs to avoid numeric collisions.
 * This label supplements the raw machine value rather than replacing it.
 */
static const char *pe_cpu(unsigned machine)
{
    switch (machine) {
    case 0x14c: return "x86"; case 0x8664: return "x86-64";
    case 0x1c0: return "ARM"; case 0x1c2: return "Thumb"; case 0x1c4: return "ARM Thumb-2";
    case 0xaa64: return "AArch64"; case 0xa641: return "ARM64EC"; case 0xa64e: return "ARM64X";
    }
    return "Unknown";
}

/*
 * Name the ELF file role: relocatable object, executable, shared image, etc.
 * These roles affect interpretation; for example, a relocatable object need not
 * have a process entry point.
 */
static const char *elf_type(unsigned type)
{
    switch (type) { case 0: return "NONE"; case 1: return "REL"; case 2: return "EXEC"; case 3: return "DYN"; case 4: return "CORE"; }
    return "UNKNOWN";
}
/*
 * Name a program-header type, including machine-specific numeric assignments.
 * A LOAD record describes bytes and memory that a loader would map.
 */
static const char *program_type(unsigned type, unsigned machine)
{
    switch (type) {
    case 0: return "NULL"; case 1: return "LOAD"; case 2: return "DYNAMIC"; case 3: return "INTERP";
    case 4: return "NOTE"; case 6: return "PHDR"; case 7: return "TLS";
    case 0x6474e550: return "GNU_EH_FRAME"; case 0x6474e551: return "GNU_STACK";
    case 0x6474e552: return "GNU_RELRO"; case 0x70000001: return machine == 40 ? "ARM_EXIDX" : "UNKNOWN";
    }
    return "UNKNOWN";
}
/*
 * Name a section type while preserving machine-specific distinctions.
 * NOBITS reserves memory without storing a payload; PROGBITS stores bytes.
 */
static const char *section_type(uint32_t type, unsigned machine)
{
    switch (type) {
    case 0: return "NULL"; case 1: return "PROGBITS"; case 2: return "SYMTAB"; case 3: return "STRTAB";
    case 4: return "RELA"; case 5: return "HASH"; case 6: return "DYNAMIC"; case 7: return "NOTE";
    case 8: return "NOBITS"; case 9: return "REL"; case 11: return "DYNSYM";
    case 14: return "INIT_ARRAY"; case 15: return "FINI_ARRAY"; case 17: return "GROUP";
    case 0x70000001: return machine == 40 ? "ARM_EXIDX" : (machine == 62 ? "X86_64_UNWIND" : "UNKNOWN");
    case 0x70000003: return machine == 40 ? "ARM_ATTRIBUTES" : (machine == 243 ? "RISCV_ATTRIBUTES" : "UNKNOWN");
    }
    return "UNKNOWN";
}
/*
 * Translate the Mach-O file role (object, executable, library, and others).
 * The role is distinct from CPU architecture and section contents.
 */
static const char *mach_type(unsigned type)
{
    switch (type) { case 1: return "OBJECT"; case 2: return "EXECUTE"; case 4: return "CORE";
    case 6: return "DYLIB"; case 7: return "DYLINKER"; case 8: return "BUNDLE"; case 0xb: return "DSYM"; }
    return "UNKNOWN";
}
/*
 * Name known Mach-O load-command IDs. High-bit command IDs remain unsigned
 * and retain that bit; it is part of the command identifier.
 */
static const char *command_type(uint32_t type)
{
    switch (type) {
    case 1: return "LC_SEGMENT"; case 2: return "LC_SYMTAB"; case 5: return "LC_UNIXTHREAD";
    case 0xb: return "LC_DYSYMTAB"; case 0xc: return "LC_LOAD_DYLIB"; case 0xd: return "LC_ID_DYLIB";
    case 0xe: return "LC_LOAD_DYLINKER"; case 0x19: return "LC_SEGMENT_64"; case 0x1b: return "LC_UUID";
    case 0x1d: return "LC_CODE_SIGNATURE"; case 0x22: return "LC_DYLD_INFO"; case 0x80000022: return "LC_DYLD_INFO_ONLY";
    case 0x8000001c: return "LC_RPATH"; case 0x80000028: return "LC_MAIN"; case 0x32: return "LC_BUILD_VERSION";
    case 0x80000033: return "LC_DYLD_EXPORTS_TRIE"; case 0x80000034: return "LC_DYLD_CHAINED_FIXUPS";
    case 0x26: return "LC_FUNCTION_STARTS"; case 0x29: return "LC_DATA_IN_CODE";
    }
    return "UNKNOWN";
}
/*
 * Extract the low-byte Mach-O section type and return a readable name.
 * Other bits are attributes and are printed as part of the complete raw flags.
 */
static const char *mach_section(uint32_t flags)
{
    switch (flags & 255) {
    case 0: return "REGULAR"; case 1: return "ZEROFILL"; case 2: return "CSTRING_LITERALS";
    case 3: return "4BYTE_LITERALS"; case 4: return "8BYTE_LITERALS"; case 5: return "LITERAL_POINTERS";
    case 6: return "NON_LAZY_SYMBOL_POINTERS"; case 7: return "LAZY_SYMBOL_POINTERS";
    case 8: return "SYMBOL_STUBS"; case 9: return "MOD_INIT_FUNC_POINTERS"; case 0xc: return "GB_ZEROFILL";
    case 0x12: return "THREAD_LOCAL_ZEROFILL";
    }
    return "UNKNOWN";
}
/*
 * Print a fixed-width RWX triplet using the format-specific masks supplied
 * by the caller. A dash means the corresponding declared flag is absent.
 */
static void permissions(uint32_t flags, uint32_t r, uint32_t w, uint32_t x)
{
    printf("%c%c%c", flags & r ? 'R' : '-', flags & w ? 'W' : '-', flags & x ? 'X' : '-');
}
/*
 * Print the common file identity and full-file hashes at the start of a report.
 * %zu formats size_t. These are stored results, not new file reads.
 */
static void identity(const InputFile *input, const char *format)
{
    printf("%s File Analysis Report\n", format);
    printf("File: %s\nSize: %zu bytes\nSHA-256: %s\nMD5: %s\n", input->path, input->size, input->sha256, input->md5);
}
/*
 * Render a numeric measurement or N/A for NAN (no measured bytes).
 * The field width keeps table columns aligned even when measurements are missing.
 */
static void entropy_value(double value)
{
    if (isnan(value)) printf("    N/A");
    else printf("%7.4f", value);
}
/*
 * Print whole-container entropy and optional nonoverlapping file windows.
 * The context was populated before reporting, so values and byte counts belong
 * to the same checked ranges; printing cannot trigger extra measurement work.
 */
static void entropy_overview(const InputFile *input, const ReportOptions *o)
{
    printf("Whole-file entropy: "); entropy_value(o->entropy->whole);
    printf(" bits/byte across %zu file bytes\n", input->size);
    puts("Entropy uses on-disk byte frequencies, including padding; virtual zero-fill is excluded from section measurements.");
    puts("High entropy alone does not establish randomness, compression, encryption, or maliciousness.");
    if (o->entropy->window_size) {
        printf("\nEntropy windows (non-overlapping, up to %llu bytes; final window may be shorter):\n",
               (unsigned long long)o->entropy->window_size);
        puts("  File offset        | File bytes | Entropy (bits/byte)");
        for (unsigned i = 0; i < o->entropy->window_count; ++i) {
            uint64_t offset = i * o->entropy->window_size;
            uint64_t size = input->size - offset;
            if (size > o->entropy->window_size) size = o->entropy->window_size;
            printf("  0x%016llX | %10llu | ", (unsigned long long)offset, (unsigned long long)size);
            entropy_value(o->entropy->windows[i]); puts("");
        }
    }
}
/*
 * Test an address against a half-open interval [start, start + size).
 * Subtract after checking address >= start to avoid overflow in start + size.
 */
static int contains(uint64_t start, uint64_t size, uint64_t address)
{
    return address >= start && address - start < size;
}
/*
 * Summaries always include observations. Other reports include them by default
 * or when explicitly selected, independently of the detail-table wants helper.
 */
static int show_observations(const ReportOptions *o)
{
    return o->summary || !o->selected || (o->selected & REPORT_OBSERVATIONS);
}
/*
 * Explain either an empty finding list or the limits of structural findings.
 * An absence of these implemented checks is not a safety verdict.
 */
static void observations_end(unsigned count)
{
    if (!count) puts("  No findings from the implemented structural checks.");
    puts("  These observations describe file structure; they are not malware verdicts.");
}

/*
 * Look for declared write+execute sections, a nonzero entry outside executable
 * regions, and sufficiently large high-entropy raw sections. The memory extent
 * uses the greater of virtual/raw size; entropy uses only the raw file bytes.
 */
static void pe_observations(const PEInfo *info)
{
    unsigned count = 0; int executable_entry = 0;
    puts("\nStructural observations:");
    for (int i = 0; i < info->section_count; ++i) {
        const PESection *s = &info->sections[i];
        uint32_t extent = s->virtual_size > s->raw_size ? s->virtual_size : s->raw_size;
        if ((s->characteristics & 0x20000000) && contains(s->virtual_address, extent, info->entry_point)) executable_entry = 1;
        if ((s->characteristics & 0xa0000000) == 0xa0000000) {
            printf("  [WX] PE section %s at RVA 0x%08X declares write and execute permissions (flags 0x%08X).\n", s->name, s->virtual_address, s->characteristics); ++count;
        }
        if (s->raw_size >= 256 && s->entropy >= 7.5) {
            printf("  [ENTROPY] PE section %s: %.4f bits/byte across %u file bytes (threshold 7.5, minimum 256 bytes).\n", s->name, s->entropy, s->raw_size); ++count;
        }
    }
    if (info->entry_point && !executable_entry) {
        printf("  [ENTRY] Entry point RVA 0x%08X is outside declared executable sections.\n", info->entry_point); ++count;
    }
    observations_end(count);
}

/*
 * Print a PE summary, optional observations, and the selected compact tables.
 * Walk only populated entries, never unused capacity. An unfiltered verbose
 * request appends the older full-field renderer; filtered requests stay focused.
 */
void report_pe(const InputFile *input, const PEInfo *info, const ReportOptions *o)
{
    identity(input, "PE");
    entropy_overview(input, o);
    printf("Summary: %s / %s / %s / little-endian\n", info->is_64bit ? "PE32+" : "PE32", pe_cpu(info->machine), info->is_64bit ? "64-bit" : "32-bit");
    printf("Entry point: RVA 0x%08X | Image base: VA 0x%0*llX\n", info->entry_point, info->is_64bit ? 16 : 8, (unsigned long long)info->image_base);
    printf("Counts: %d sections | %u imports | %u delay-load imports | %u exports | %u resources\n", info->section_count,
           info->import_count - info->delay_import_count, info->delay_import_count, info->export_count, info->resource_count);
    if (show_observations(o)) pe_observations(info);
    if (o->summary) return;
    if (wants(o, REPORT_HEADERS)) {
        printf("\nPE headers: Machine=0x%04X (%s), Optional magic=0x%04X, Timestamp=%u\n", info->machine, pe_cpu(info->machine), info->magic, info->timestamp);
        printf("COFF flags: 0x%04X (%s%s%s)\n", info->characteristics, info->characteristics & 2 ? "EXECUTABLE " : "",
               info->characteristics & 0x2000 ? "DLL " : "", info->characteristics & 0x100 ? "32BIT_MACHINE" : "");
        if (o->verbose) printf("Size of code: %u | Size of headers: %u | Data directories: %u\n", info->size_of_code, info->size_of_headers, info->number_of_rva_directories);
    }
    if (wants(o, REPORT_SECTIONS)) {
        puts("\nPE sections (RVA is image-relative; File offset is on disk; permissions are declared):");
        puts("  #  Name      | RVA        | File offset        | File bytes | Memory bytes | RWX | Entropy | Raw flags / content");
        for (int i = 0; i < info->section_count; ++i) {
            const PESection *s = &info->sections[i];
            printf("%3d  %-8s | 0x%08X | 0x%016llX | %10u | %12u | ", i + 1, s->name, s->virtual_address,
                   (unsigned long long)s->PointerToRawData, s->raw_size, s->virtual_size);
            permissions(s->characteristics, 0x40000000, 0x80000000, 0x20000000);
            printf(" | "); entropy_value(s->entropy);
            printf(" | 0x%08X %s%s%s\n", s->characteristics,
                   s->characteristics & 0x20 ? "CODE " : "", s->characteristics & 0x40 ? "INITIALIZED_DATA " : "",
                   s->characteristics & 0x80 ? "UNINITIALIZED_DATA" : "");
        }
    }
    if (wants(o, REPORT_IMPORTS)) {
        puts("\nPE imports (symbols are lookup-table names or ordinals):");
        /*
         * Measure the displayed strings before printing so columns align without
         * shortening names. %-*s means a left-aligned string whose width comes from
         * the next argument; %0*llX similarly supplies a numeric width at runtime.
         */
        unsigned dll_width = 3, symbol_width = 6;
        for (unsigned i = 0; i < info->import_count; ++i) {
            const PEImport *s = &info->imports[i];
            if (strlen(s->dll) > dll_width) dll_width = (unsigned)strlen(s->dll);
            if (strlen(s->name) > symbol_width) symbol_width = (unsigned)strlen(s->name);
        }
        printf("  %-*s | %-*s | Hint/ordinal | Binding\n", dll_width, "DLL", symbol_width, "Symbol");
        for (unsigned i = 0; i < info->import_count; ++i) {
            const PEImport *s = &info->imports[i]; char ordinal[32];
            snprintf(ordinal, sizeof(ordinal), "#%u", s->ordinal);
            printf("  %-*s | %-*s | %12u | %s%s\n", dll_width, s->dll, symbol_width,
                   s->by_ordinal ? ordinal : s->name, s->by_ordinal ? s->ordinal : s->hint,
                   s->delay_load ? "delay-load" : "ordinary", s->by_ordinal ? " / ordinal" : " / name");
        }
    }
    if (wants(o, REPORT_EXPORTS)) {
        printf("\nPE exports (%s):\n", info->export_dll[0] ? info->export_dll : "unnamed image");
        puts("  Ordinal | RVA        | Name / forwarder");
        for (unsigned i = 0; i < info->export_count; ++i) {
            const PEExport *s = &info->exports[i];
            printf("  %7llu | 0x%08X | %s", (unsigned long long)s->ordinal, s->rva, s->name[0] ? s->name : "<ordinal-only>");
            if (s->forwarder[0]) printf(" -> %s", s->forwarder);
            puts("");
        }
    }
    if (wants(o, REPORT_RESOURCES)) {
        puts("\nPE resources (payload locations on disk):");
        puts("  # | RVA        | File offset        | Bytes      | Code page | Type/name/language");
        for (unsigned i = 0; i < info->resource_count; ++i) {
            const PEResource *s = &info->resources[i];
            printf("%3u | 0x%08X | 0x%016llX | %10u | %9u | %s\n", i + 1, s->rva, (unsigned long long)s->file_offset, s->size, s->codepage, s->path);
            if (!o->no_preview && s->decoded[0]) printf("      Preview: %s\n", s->decoded);
        }
    }
    if (o->verbose && !o->selected) { puts("\nFull field details:"); print_pe_info(info, !o->no_preview); }
}

/*
 * Check executable LOAD regions and writable/executable section declarations.
 * Only executable/shared ELF roles receive process-entry checks: a relocatable
 * object's address fields do not describe a loaded process in the same way.
 */
static void elf_observations(const ELFInfo *info)
{
    unsigned count = 0; int executable_entry = 0;
    puts("\nStructural observations:");
    for (unsigned i = 0; i < info->program_count; ++i) {
        const ProgramHeader *p = &info->program_headers[i];
        if (p->p_type != 1) continue;
        if ((p->p_flags & 1) && contains(p->p_vaddr, p->p_memsz, info->e_entry)) executable_entry = 1;
        if ((p->p_flags & 3) == 3) {
            printf("  [WX] ELF LOAD header %u at VA 0x%0*llX declares write and execute permissions (flags 0x%08X).\n", i + 1,
                   info->is_64bit ? 16 : 8, (unsigned long long)p->p_vaddr, p->p_flags); ++count;
        }
    }
    for (unsigned i = 0; i < info->section_count; ++i) {
        const SectionHeader *s = &info->section_headers[i];
        if ((s->sh_flags & 5) == 5) {
            printf("  [WX] ELF section %s declares write and execute flags (0x%016llX).\n",
                   info->section_names[i][0] ? info->section_names[i] : "<unnamed>", (unsigned long long)s->sh_flags); ++count;
        }
    }
    if ((info->e_type == 2 || info->e_type == 3) && info->e_entry && !executable_entry) {
        printf("  [ENTRY] Entry point VA 0x%0*llX is outside declared executable LOAD regions.\n", info->is_64bit ? 16 : 8, (unsigned long long)info->e_entry); ++count;
    }
    observations_end(count);
}

/*
 * Print normalized ELF results with address widths appropriate to ELF32/ELF64.
 * Compute name-column width once, then show each parsed row. NULL/NOBITS rows
 * have no file payload, even when their size fields contain metadata or memory size.
 */
void report_elf(const InputFile *input, const ELFInfo *info, const ReportOptions *o)
{
    int width = info->is_64bit ? 16 : 8;
    identity(input, "ELF");
    entropy_overview(input, o);
    printf("Summary: ELF%u / %s / %s / %s\n", info->is_64bit ? 64 : 32, cpu(info->e_machine, 0),
           elf_type(info->e_type), info->big_endian ? "big-endian" : "little-endian");
    printf("Entry point: VA 0x%0*llX\nCounts: %u program headers | %u sections\n", width, (unsigned long long)info->e_entry, info->program_count, info->section_count);
    if (show_observations(o)) elf_observations(info);
    if (o->summary) return;
    if (wants(o, REPORT_HEADERS)) {
        printf("\nELF headers: Machine=0x%04X (%s), Type=0x%04X (%s), Flags=0x%08X\n", info->e_machine, cpu(info->e_machine, 0), info->e_type, elf_type(info->e_type), info->flags);
        if (info->e_machine == 40) printf("ARM EABI version %u%s%s\n", info->flags >> 24,
               info->flags & 0x400 ? ", hard-float ABI" : "", info->flags & 0x200 ? ", soft-float ABI" : "");
    }
    if (wants(o, REPORT_PROGRAMS)) {
        puts("\nELF program headers (VA is a virtual address; permissions are declared):");
        printf("  # | %-23s | %-18s | %-*s | File bytes | Memory bytes | RWX | Raw flags\n", "Type / raw value", "File offset", width + 2, "VA");
        for (unsigned i = 0; i < info->program_count; ++i) {
            const ProgramHeader *p = &info->program_headers[i]; char type[64];
            snprintf(type, sizeof(type), "%s/0x%08X", program_type(p->p_type, info->e_machine), p->p_type);
            printf("%3u | %-23s | 0x%016llX | 0x%0*llX | %10llu | %12llu | ", i + 1, type,
                   (unsigned long long)p->p_offset, width, (unsigned long long)p->p_vaddr,
                   (unsigned long long)p->p_filesz, (unsigned long long)p->p_memsz);
            permissions(p->p_flags, 4, 2, 1); printf(" | 0x%08X\n", p->p_flags);
            if (o->verbose) printf("      Physical address: 0x%0*llX | Alignment: %llu\n", width, (unsigned long long)p->p_paddr, (unsigned long long)p->p_align);
        }
    }
    if (wants(o, REPORT_SECTIONS)) {
        unsigned name_width = 4;
        for (unsigned i = 0; i < info->section_count; ++i) {
            unsigned n = (unsigned)strlen(info->section_names[i]);
            if (n > name_width) name_width = n;
        }
        if (name_width < 9) name_width = 9;
        puts("\nELF sections (NOBITS/NULL rows do not describe payload bytes in the file):");
        printf("  # | %-*s | %-24s | %-18s | %-*s | Bytes      | WAX | Entropy | Raw flags\n", name_width, "Name", "Type / raw value", "File offset", width + 2, "VA");
        for (unsigned i = 0; i < info->section_count; ++i) {
            const SectionHeader *s = &info->section_headers[i]; char type[64];
            snprintf(type, sizeof(type), "%s/0x%08X", section_type(s->sh_type, info->e_machine), s->sh_type);
            printf("%3u | %-*s | %-24s | ", i + 1, name_width, info->section_names[i][0] ? info->section_names[i] : "<unnamed>", type);
            if (s->sh_type == 0 || s->sh_type == 8) printf("%-18s", "--"); else printf("0x%016llX", (unsigned long long)s->sh_offset);
            printf(" | 0x%0*llX | %10llu | %c%c%c | ", width, (unsigned long long)s->sh_addr, (unsigned long long)s->sh_size,
                   s->sh_flags & 1 ? 'W' : '-', s->sh_flags & 2 ? 'A' : '-', s->sh_flags & 4 ? 'X' : '-');
            entropy_value(s->sh_type == 0 || s->sh_type == 8 ? NAN : entropy_lookup(o->entropy, s->sh_offset, s->sh_size));
            printf(" | 0x%016llX\n", (unsigned long long)s->sh_flags);
            if (o->verbose) printf("      Name index: %u | Link: %u | Info: %u | Alignment: %llu | Entry bytes: %llu\n", s->sh_name, s->sh_link, s->sh_info,
                                   (unsigned long long)s->sh_addralign, (unsigned long long)s->sh_entsize);
        }
    }
    if (o->verbose && !o->selected) { puts("\nFull field details:"); print_elf_info(info); }
}

/*
 * Check segment-declared write+execute permissions and LC_MAIN's file offset.
 * The permission masks differ from ELF and PE; this check uses Mach-O's initprot.
 * It does not attempt to discover permissions changed later by a running process.
 */
static void mach_observations(const MachOInfo *info)
{
    unsigned count = 0; int executable_entry = 0;
    puts("\nStructural observations:");
    for (int i = 0; i < info->load_cmd_count; ++i) {
        const MachOLoadCommand *c = &info->load_commands[i];
        if (c->cmd != LC_SEGMENT && c->cmd != LC_SEGMENT_64) continue;
        int wide = c->cmd == LC_SEGMENT_64;
        uint32_t prot = wide ? c->data.segment64.initprot : c->data.segment.initprot;
        uint64_t fileoff = wide ? c->data.segment64.fileoff : c->data.segment.fileoff;
        uint64_t filesize = wide ? c->data.segment64.filesize : c->data.segment.filesize;
        const char *name = wide ? c->data.segment64.segname : c->data.segment.segname;
        if (info->has_entry && (prot & 4) && contains(fileoff, filesize, info->entry_file_offset)) executable_entry = 1;
        if ((prot & 6) == 6) {
            printf("  [WX] Mach-O segment %.16s at slice file offset 0x%016llX declares write and execute permissions (initprot 0x%08X).\n", name, (unsigned long long)fileoff, prot); ++count;
        }
    }
    if (info->has_entry && !executable_entry) {
        printf("  [ENTRY] LC_MAIN slice file offset 0x%016llX is outside declared executable segments.\n", (unsigned long long)info->entry_file_offset); ++count;
    }
    observations_end(count);
}

/*
 * Render one thin architecture using slice-relative and container coordinates.
 * Section entropy is looked up by its absolute container range. Segment protection
 * is inherited metadata, not a claim that the input has been executed or mapped.
 */
static void mach_slice(const MachOInfo *info, const ReportOptions *o)
{
    int width = info->is_64bit ? 16 : 8;
    printf("Summary: Mach-O / %s / %s / %s / %s\n", cpu(info->cputype, 1), info->is_64bit ? "64-bit" : "32-bit",
           info->big_endian ? "big-endian" : "little-endian", mach_type(info->filetype));
    if (info->has_entry) {
        printf("Entry point: LC_MAIN slice file offset 0x%016llX", (unsigned long long)info->entry_file_offset);
        if (info->has_entry_address) printf(" | VA 0x%0*llX", width, (unsigned long long)info->entry_address);
        puts("");
    } else puts("Entry point: unavailable (no LC_MAIN; thread-state entry decoding is not implemented)");
    printf("Counts: %u load commands | %u sections\n", info->ncmds, info->section_count);
    if (show_observations(o)) mach_observations(info);
    if (o->summary) return;
    if (wants(o, REPORT_HEADERS)) {
        printf("\nMach-O headers: CPU 0x%08X (%s), subtype 0x%08X, File type 0x%08X (%s)\n", info->cputype, cpu(info->cputype, 1), info->cpusubtype, info->filetype, mach_type(info->filetype));
        printf("Magic: 0x%08X | Load-command bytes: %u\n", info->magic, info->sizeofcmds);
        printf("Flags: 0x%08X (%s%s%s)\n", info->flags, info->flags & 1 ? "NOUNDEFS " : "", info->flags & 4 ? "DYLDLINK " : "", info->flags & 0x200000 ? "PIE" : "");
    }
    if (wants(o, REPORT_COMMANDS)) {
        puts("\nMach-O load commands:");
        puts("  # | Command                      | Raw value  | Bytes");
        for (int i = 0; i < info->load_cmd_count; ++i) {
            const MachOLoadCommand *c = &info->load_commands[i];
            printf("%3d | %-28s | 0x%08X | %u\n", i + 1, command_type(c->cmd), c->cmd, c->cmdsize);
            if (c->cmd == LC_SEGMENT || c->cmd == LC_SEGMENT_64) {
                int wide = c->cmd == LC_SEGMENT_64;
                printf("      Segment: %.16s | VA 0x%0*llX | VM bytes %llu | Slice file offset 0x%016llX | File bytes %llu | ",
                       wide ? c->data.segment64.segname : c->data.segment.segname, width,
                       (unsigned long long)(wide ? c->data.segment64.vmaddr : c->data.segment.vmaddr),
                       (unsigned long long)(wide ? c->data.segment64.vmsize : c->data.segment.vmsize),
                       (unsigned long long)(wide ? c->data.segment64.fileoff : c->data.segment.fileoff),
                       (unsigned long long)(wide ? c->data.segment64.filesize : c->data.segment.filesize));
                permissions(wide ? c->data.segment64.initprot : c->data.segment.initprot, 1, 2, 4); puts(" (declared)");
            }
        }
    }
    if (wants(o, REPORT_SECTIONS)) {
        puts("\nMach-O sections (permissions are inherited segment declarations):");
        printf("  # | %-33s | %-*s | Slice file offset  | Container offset   | Bytes      | RWX | Entropy | Type / raw flags\n", "Segment,section", width + 2, "VA");
        for (unsigned i = 0; i < info->section_count; ++i) {
            const MachOSection *s = &info->sections[i]; char name[35];
            snprintf(name, sizeof(name), "%s,%s", s->segment, s->name);
            printf("%3u | %-33s | 0x%0*llX | ", i + 1, name, width, (unsigned long long)s->address);
            if (s->zerofill) printf("%-18s | %-18s", "-- (zero-fill)", "--");
            else printf("0x%016llX | 0x%016llX", (unsigned long long)s->offset, (unsigned long long)(info->slice_offset + s->offset));
            printf(" | %10llu | ", (unsigned long long)s->size); permissions(s->protection, 1, 2, 4);
            printf(" | ");
            entropy_value(s->zerofill ? NAN : entropy_lookup(o->entropy, info->slice_offset + s->offset, s->size));
            printf(" | %s / 0x%08X\n", mach_section(s->flags), s->flags);
            if (o->verbose) printf("      Alignment: 2^%u | Relocations: %u | Relocation slice file offset: 0x%016llX\n", s->alignment, s->relocation_count, (unsigned long long)s->relocation_offset);
        }
    }
    if (o->verbose && !o->selected) { puts("\nFull field details:"); print_mach_info(info); }
}

/*
 * Print one identity for the whole file, then each architecture's slice report.
 * Hashes and whole-file entropy identify the container; the nested reports retain
 * each slice's own CPU, byte order, entry point, commands, and sections.
 */
void report_mach(const InputFile *input, const MachOInfo *info, const ReportOptions *o)
{
    identity(input, info->slice_count ? "Universal Mach-O" : "Mach-O");
    entropy_overview(input, o);
    if (info->slice_count) {
        printf("Architectures: %u | Hashes cover the complete container\n", info->slice_count);
        for (unsigned i = 0; i < info->slice_count; ++i) {
            const MachOInfo *slice = &info->slices[i];
            printf("\nSlice %u: CPU 0x%08X (%s), container file offset 0x%016llX, slice bytes %llu\n", i + 1, slice->cputype, cpu(slice->cputype, 1),
                   (unsigned long long)slice->slice_offset, (unsigned long long)slice->slice_size);
            mach_slice(slice, o);
        }
    } else mach_slice(info, o);
}

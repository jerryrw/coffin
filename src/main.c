/*
 * Program entry point: turn command-line arguments into an inspection request.
 * The stages are: open one file, hash it, choose a parser by its signature,
 * measure entropy, optionally extract PE resources, print, then release memory.
 * A parser inspects bytes; it never loads or executes the inspected program.
 * Follow InputFile in common.h and the three *Info structures in the parser headers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "common.h"
#include "report.h"
#include "peparser.h"
#include "entropy.h"
#include "elfparser.h"
#include "machparser.h"

/*
 * argc is the argument count; argv is an array of C strings, including argv[0].
 * Zero-initialized option/context structures provide safe defaults and NULL pointers.
 * Return EXIT_SUCCESS for a completed report and EXIT_FAILURE for any error.
 * Each format-specific result owns heap arrays and is freed even after a failure.
 */
int main(int argc, char *argv[])
{
    InputFile input = {0};
    EntropyContext entropy = {0};
    ReportOptions report = {.entropy = &entropy};
    const char *extract_directory = NULL;
    /*
     * Parse arguments before opening the file. ++i consumes a switch's value.
     * strtoull/strtoul supply an end pointer; checking it rejects trailing junk,
     * and errno reports overflow. Numeric range checks happen before narrowing.
     */
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--verbose")) input.verbose = report.verbose = 1;
        else if (!strcmp(argv[i], "--entropy-window")) {
            if (++i >= argc || entropy.window_size || argv[i][0] < '0' || argv[i][0] > '9') { print_usage(argv); return EXIT_FAILURE; }
            char *end; errno = 0;
            unsigned long long size = strtoull(argv[i], &end, 10);
            if (errno || *end || !size) { print_usage(argv); return EXIT_FAILURE; }
            entropy.window_size = size;
        }
        else if (!strcmp(argv[i], "--summary")) report.summary = 1;
        else if (!strcmp(argv[i], "--no-preview")) report.no_preview = 1;
        else if (!strcmp(argv[i], "--headers")) report.selected |= REPORT_HEADERS;
        else if (!strcmp(argv[i], "--sections")) report.selected |= REPORT_SECTIONS;
        else if (!strcmp(argv[i], "--imports")) report.selected |= REPORT_IMPORTS;
        else if (!strcmp(argv[i], "--exports")) report.selected |= REPORT_EXPORTS;
        else if (!strcmp(argv[i], "--resources")) report.selected |= REPORT_RESOURCES;
        else if (!strcmp(argv[i], "--program-headers")) report.selected |= REPORT_PROGRAMS;
        else if (!strcmp(argv[i], "--load-commands")) report.selected |= REPORT_COMMANDS;
        else if (!strcmp(argv[i], "--observations")) report.selected |= REPORT_OBSERVATIONS;
        else if (!strcmp(argv[i], "--code-page")) {
            if (++i >= argc || input.text_code_page || argv[i][0] < '0' || argv[i][0] > '9') { print_usage(argv); return EXIT_FAILURE; }
            char *end; errno = 0;
            unsigned long page = strtoul(argv[i], &end, 10);
            if (errno || *end || !page || page > UINT32_MAX) { print_usage(argv); return EXIT_FAILURE; }
            input.text_code_page = (uint32_t)page;
        }
        else if (!strcmp(argv[i], "--extract-resources")) {
            if (extract_directory || ++i >= argc) { print_usage(argv); return EXIT_FAILURE; }
            extract_directory = argv[i];
        }
        else if (!strcmp(argv[i], "--help")) { print_usage(argv); return EXIT_SUCCESS; }
        else if (!strcmp(argv[i], "--")) {
            if (++i != argc - 1 || input.path) { print_usage(argv); return EXIT_FAILURE; }
            input.path = argv[i];
        } else if (argv[i][0] == '-' || input.path) { print_usage(argv); return EXIT_FAILURE; }
        else input.path = argv[i];
    }
    if (report.summary && report.selected) { fprintf(stderr, "--summary cannot be combined with detail selectors\n"); return EXIT_FAILURE; }
    if (!input.path) { print_usage(argv); return EXIT_FAILURE; }
    /*
     * "rb" opens for binary reading, without text-mode newline conversions.
     * This one stream is reused by hashing, parsers, entropy, and extraction.
     */
    input.file = fopen(input.path, "rb");
    if (!input.file) { perror(input.path); return EXIT_FAILURE; }
    int status = STATUS_ERROR;
    unsigned char magic[4];
    if (input_prepare(&input) != STATUS_SUCCESS ||
        read_at(input.file, 0, magic, sizeof(magic), input.size) != STATUS_SUCCESS) {
        fprintf(stderr, "Cannot read input file\n");
        goto done;
    }
    /*
     * Magic bytes identify the file format. memcmp compares a fixed number of
     * bytes and does not require a string terminator. Only report after all
     * required parsing and measurements have succeeded.
     */
    if (memcmp(magic, "\177ELF", 4) == 0) {
        if (extract_directory) { fprintf(stderr, "Resource extraction requires a PE file\n"); goto done; }
        if (report_validate(&report, REPORT_HEADERS | REPORT_SECTIONS | REPORT_PROGRAMS | REPORT_OBSERVATIONS) != STATUS_SUCCESS) goto done;
        ELFInfo info;
        status = parse_elf_file(&input, &info);
        if (status == STATUS_SUCCESS) status = entropy_file(&input, &entropy);
        if (status == STATUS_SUCCESS) status = entropy_elf(&input, &entropy, &info);
        if (status == STATUS_SUCCESS) report_elf(&input, &info, &report);
        free_elf_info(&info);
    } else if (magic[0] == 'M' && magic[1] == 'Z') {
        if (report_validate(&report, REPORT_HEADERS | REPORT_SECTIONS | REPORT_IMPORTS | REPORT_EXPORTS | REPORT_RESOURCES | REPORT_OBSERVATIONS) != STATUS_SUCCESS) goto done;
        PEInfo info;
        status = parse_pe_file(&input, &info);
        if (status == STATUS_SUCCESS) status = entropy_file(&input, &entropy);
        if (status == STATUS_SUCCESS) status = entropy_pe(&input, &entropy, &info);
        if (status == STATUS_SUCCESS && extract_directory)
            status = extract_pe_resources(&input, &info, extract_directory);
        if (status == STATUS_SUCCESS) {
            report_pe(&input, &info, &report);
            if (extract_directory) printf("\nExtracted %u resources to %s (see index.tsv)\n", info.resource_total, extract_directory);
        }
        free_pe_info(&info);
    } else {
        if (extract_directory) { fprintf(stderr, "Resource extraction requires a PE file\n"); goto done; }
        uint32_t value = decode32(magic);
        if (value == MACHO_MAGIC || value == MACHO_MAGIC_64 ||
            value == 0xcefaedfe || value == 0xcffaedfe ||
            value == 0xbebafeca || value == 0xcafebabe ||
            value == 0xbfbafeca || value == 0xcafebabf) {
            if (report_validate(&report, REPORT_HEADERS | REPORT_SECTIONS | REPORT_COMMANDS | REPORT_OBSERVATIONS) != STATUS_SUCCESS) goto done;
            MachOInfo info;
            status = parse_mach_file(&input, &info);
            if (status == STATUS_SUCCESS) status = entropy_file(&input, &entropy);
            if (status == STATUS_SUCCESS) status = entropy_mach(&input, &entropy, &info);
            if (status == STATUS_SUCCESS) report_mach(&input, &info, &report);
            free_mach_info(&info);
        } else fprintf(stderr, "Unknown file type\n");
    }
/*
 * A label is a shared exit point. Earlier goto done paths still close the
 * input and release the entropy cache; successful paths fall through here.
 */
done:
    entropy_free(&entropy);
    if (fclose(input.file) != 0) status = STATUS_ERROR;
    return status == STATUS_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
}

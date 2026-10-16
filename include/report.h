/*
 * Report option bits and read-only presentation APIs.
 * Each power-of-two constant is one independent bit. Combine selections with |,
 * for example REPORT_HEADERS | REPORT_SECTIONS. selected == 0 means all details
 * unless summary is set. Reporting borrows parsed results and a populated entropy
 * context; it prints them without freeing them or changing their contents.
 */

#ifndef REPORT_H
#define REPORT_H
#include "common.h"
#include "entropy.h"
#include "peparser.h"
#include "elfparser.h"
#include "machparser.h"

#define REPORT_HEADERS 1u
#define REPORT_SECTIONS 2u
#define REPORT_IMPORTS 4u
#define REPORT_EXPORTS 8u
#define REPORT_RESOURCES 16u
#define REPORT_PROGRAMS 32u
#define REPORT_COMMANDS 64u
#define REPORT_OBSERVATIONS 128u

typedef struct {
    /*
     * Borrowed, already populated context: the caller retains ownership.
     */
    EntropyContext *entropy;
    /*
     * Bit mask of REPORT_* choices; zero means no explicit detail filter.
     */
    unsigned selected;
    /*
     * C uses integer flags here: zero is false; nonzero is true.
     */
    int summary, verbose, no_preview;
} ReportOptions;

/*
 * Validate selected groups against the format's supported mask before parsing.
 * The rendering calls expect successfully parsed results and entropy.
 */
int report_validate(const ReportOptions *options, unsigned supported);
void report_pe(const InputFile *input, const PEInfo *info, const ReportOptions *options);
void report_elf(const InputFile *input, const ELFInfo *info, const ReportOptions *options);
void report_mach(const InputFile *input, const MachOInfo *info, const ReportOptions *options);
#endif

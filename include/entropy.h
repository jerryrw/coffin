/*
 * Entropy API and per-file cache state (src/entropy.c contains the algorithms).
 * Contexts own heap buffers; initialize one with {0}, use it for exactly one
 * unchanged input, then release it. NAN represents "no measurement," distinct
 * from entropy zero, which means all measured bytes have the same value.
 */

#ifndef ENTROPY_H
#define ENTROPY_H
#include "peparser.h"
#include "elfparser.h"
#include "machparser.h"

/* Bounds apply to actual reads, including whole-file and optional windows. */
#define ENTROPY_WORK_LIMIT (UINT64_C(1024) * 1024 * 1024)
#define ENTROPY_CACHE_SLOTS 262144u
#define ENTROPY_MAX_WINDOWS 4096u

typedef struct {
    /*
     * The cache key is the exact file interval; value is its computed entropy.
     */
    uint64_t offset, size;
    double value;
    /*
     * A separate occupancy flag distinguishes an unused slot from offset zero.
     */
    int used;
} EntropyRange;
/* Initialize to zero, use with one unchanged input stream, then entropy_free(). */
typedef struct {
    EntropyRange *ranges;
    /*
     * count is occupied cache entries; capacity is power-of-two hash-table slots.
     */
    unsigned count, capacity;
    /*
     * bytes_read enforces the cumulative budget; window_size == 0 disables windows.
     */
    uint64_t bytes_read, window_size;
    double whole;
    /*
     * Owned array of window_count results, in increasing file-offset order.
     */
    double *windows;
    unsigned window_count;
} EntropyContext;

/* Empty or NULL buffers return NAN: no measurement, rather than zero entropy. */
double calculate_entropy(const unsigned char *buffer, size_t size);
void analyze_entropy(const unsigned char *buffer, size_t size, const char *description);
void entropy_free(EntropyContext *context);
/*
 * Compute and cache into *value; an empty interval succeeds with NAN.
 * lookup reads only cached values and returns NAN for absent/empty ranges.
 */
int entropy_range(const InputFile *input, EntropyContext *context, uint64_t offset, uint64_t size, double *value);
double entropy_lookup(const EntropyContext *context, uint64_t offset, uint64_t size);
/*
 * Populate whole-file and optional window results before report rendering.
 * Format helpers measure file-backed sections, with PE also storing its values.
 */
int entropy_file(const InputFile *input, EntropyContext *context);
int entropy_pe(const InputFile *input, EntropyContext *context, PEInfo *info);
int entropy_elf(const InputFile *input, EntropyContext *context, const ELFInfo *info);
int entropy_mach(const InputFile *input, EntropyContext *context, const MachOInfo *info);
int calc_entropy(const InputFile *input, PEInfo *info);
#endif

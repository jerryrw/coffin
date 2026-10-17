/*
 * Measure Shannon entropy from byte frequencies, in bits per byte (0 to 8).
 * A histogram counts occurrences of each of the 256 possible byte values.
 * Both buffer and streamed measurements use the same histogram formula.
 * Entropy does not consider byte order and cannot prove encryption or randomness.
 * A per-file cache avoids rereading identical ranges; a budget bounds other work.
 */

#include <stdlib.h>
#include <math.h>
#include "entropy.h"

/*
 * For every present byte value, compute p = count / total and add -p * log2(p).
 * Casting to double avoids integer division (which would round most p to zero).
 * Skip zero counts because log2(0) is undefined. With no present counts the sum
 * stays zero; public entry points instead mark empty input as NAN.
 */
static double histogram_entropy(const size_t freq[256], uint64_t size)
{
    double value = 0.0;
    for (unsigned i = 0; i < 256; ++i) if (freq[i]) {
        double p = (double)freq[i] / (double)size;
        value -= p * log2(p);
    }
    return value;
}

/*
 * Measure an in-memory buffer in one pass. freq[byte] indexes a counter by
 * its unsigned byte value, so the only possible indices are 0 through 255.
 * NAN ("not a number") represents no measurement for NULL or empty buffers.
 */
double calculate_entropy(const unsigned char *buffer, size_t size)
{
    if (!buffer || !size) return NAN;
    size_t freq[256] = {0};
    for (size_t i = 0; i < size; ++i) ++freq[buffer[i]];
    return histogram_entropy(freq, size);
}

/*
 * Print an optional standalone buffer measurement without guessing its meaning.
 * isnan checks the special empty-measurement marker; comparing a NAN with ==
 * would not work, since NAN is not equal to itself.
 */
void analyze_entropy(const unsigned char *buffer, size_t size, const char *description)
{
    double value = calculate_entropy(buffer, size);
    fputs("Entropy analysis for ", stdout); print_escaped(stdout, description ? description : "buffer"); fputs(": ", stdout);
    if (isnan(value)) puts("N/A (no measured bytes)");
    else printf("%.4f bits/byte across %zu bytes\n", value, size);
    puts("Byte-frequency entropy does not establish randomness, compression, encryption, or maliciousness.");
}

/*
 * Release the range cache and optional window results owned by the context.
 * Assigning a zero compound literal resets pointers and counters together.
 */
void entropy_free(EntropyContext *c)
{
    free(c->ranges); free(c->windows);
    *c = (EntropyContext){0};
}

/*
 * Mix offset and length into a hash-table index; this is a cache key, not a
 * cryptographic digest. capacity is a power of two, so & (capacity - 1) is
 * an efficient remainder operation that always selects a valid slot.
 */
static unsigned range_slot(uint64_t offset, uint64_t size, unsigned capacity)
{
    uint64_t x = offset ^ (size + UINT64_C(0x9e3779b97f4a7c15));
    x ^= x >> 30; x *= UINT64_C(0xbf58476d1ce4e5b9);
    x ^= x >> 27; x *= UINT64_C(0x94d049bb133111eb);
    return (unsigned)(x ^ (x >> 31)) & (capacity - 1);
}

/*
 * Find a previously computed nonempty file range or return NAN if absent.
 * Linear probing means trying the next slot after a collision. The table is
 * kept at most half full, so an unused slot always ends an unsuccessful search.
 */
double entropy_lookup(const EntropyContext *c, uint64_t offset, uint64_t size)
{
    if (!size || !c || !c->ranges) return NAN;
    unsigned slot = range_slot(offset, size, c->capacity);
    while (c->ranges[slot].used) {
        const EntropyRange *r = &c->ranges[slot];
        if (r->offset == offset && r->size == size) return r->value;
        slot = (slot + 1) & (c->capacity - 1);
    }
    return NAN;
}

/*
 * Measure a validated file range once, caching its exact offset/length pair.
 * Grow and rehash the cache as necessary, then stream into one shared histogram.
 * The read budget counts actual processed bytes, not cache hits. Different
 * partially overlapping ranges still cost work and therefore consume the budget.
 */
int entropy_range(const InputFile *input, EntropyContext *c, uint64_t offset, uint64_t size, double *value)
{
    *value = NAN;
    if (!size) return STATUS_SUCCESS;
    if (!file_range_valid(offset, size, input->size)) goto error;
    if (!c->capacity || (c->count >= c->capacity / 2 && c->capacity < ENTROPY_CACHE_SLOTS)) {
        unsigned capacity = c->capacity ? c->capacity * 2 : 256;
        EntropyRange *ranges = calloc(capacity, sizeof(*ranges));
        if (!ranges) goto error;
        /*
         * Resizing changes each key's slot because the capacity mask changes.
         * Reinsert occupied entries into the new table before freeing the old one;
         * copying their old positions would make lookups miss valid cached ranges.
         */
        for (unsigned i = 0; i < c->capacity; ++i) if (c->ranges[i].used) {
            EntropyRange r = c->ranges[i];
            unsigned slot = range_slot(r.offset, r.size, capacity);
            while (ranges[slot].used) slot = (slot + 1) & (capacity - 1);
            ranges[slot] = r;
        }
        free(c->ranges); c->ranges = ranges; c->capacity = capacity;
    }
    unsigned slot = range_slot(offset, size, c->capacity);
    while (c->ranges[slot].used) {
        EntropyRange *r = &c->ranges[slot];
        if (r->offset == offset && r->size == size) { *value = r->value; return STATUS_SUCCESS; }
        slot = (slot + 1) & (c->capacity - 1);
    }
    if (c->count >= ENTROPY_CACHE_SLOTS / 2 || (c->bytes_read > ENTROPY_WORK_LIMIT || size > ENTROPY_WORK_LIMIT - c->bytes_read)) {
        fprintf(stderr, "Entropy work limit exceeded (1 GiB of reads or 131072 distinct ranges)\n");
        return STATUS_ERROR;
    }
    /*
     * Accumulate all chunks into ONE histogram. Averaging separate chunk
     * entropies would give a different, incorrect whole-range measurement.
     */
    size_t freq[256] = {0};
    unsigned char buffer[8192];
    uint64_t remaining = size, position = offset;
    while (remaining) {
        size_t chunk = remaining < sizeof(buffer) ? (size_t)remaining : sizeof(buffer);
        if (read_at(input->file, position, buffer, chunk, input->size) != STATUS_SUCCESS) goto error;
        c->bytes_read += chunk;
        for (size_t i = 0; i < chunk; ++i) ++freq[buffer[i]];
        remaining -= chunk; position += chunk;
    }
    *value = histogram_entropy(freq, size);
    c->ranges[slot] = (EntropyRange){offset, size, *value, 1}; ++c->count;
    return STATUS_SUCCESS;
error:
    fprintf(stderr, "Cannot measure entropy at file offset 0x%llX across %llu bytes\n",
            (unsigned long long)offset, (unsigned long long)size);
    return STATUS_ERROR;
}

/*
 * Compute the whole-file measurement and optional consecutive file windows.
 * Ceiling division includes a shorter final window. Check the window count
 * before allocating or iterating so a tiny window cannot flood report output.
 */
int entropy_file(const InputFile *input, EntropyContext *c)
{
    if (c->window_size) {
        uint64_t count = input->size / c->window_size + (input->size % c->window_size != 0);
        if (count > ENTROPY_MAX_WINDOWS) {
            fprintf(stderr, "Entropy window report exceeds 4096 windows; use a larger window\n");
            return STATUS_ERROR;
        }
        c->window_count = (unsigned)count;
        c->windows = calloc(c->window_count ? c->window_count : 1, sizeof(*c->windows));
        if (!c->windows) return STATUS_ERROR;
    }
    if (entropy_range(input, c, 0, input->size, &c->whole) != STATUS_SUCCESS) return STATUS_ERROR;
    for (unsigned i = 0; i < c->window_count; ++i) {
        uint64_t offset = i * c->window_size;
        uint64_t size = input->size - offset;
        if (size > c->window_size) size = c->window_size;
        if (entropy_range(input, c, offset, size, &c->windows[i]) != STATUS_SUCCESS) return STATUS_ERROR;
    }
    return STATUS_SUCCESS;
}

/*
 * Measure PE section raw bytes and store the result in each section record.
 * Virtual sizes can differ; virtual zero-fill is not part of this measurement.
 */
int entropy_pe(const InputFile *input, EntropyContext *c, PEInfo *info)
{
    for (int i = 0; i < info->section_count; ++i) {
        PESection *s = &info->sections[i];
        if (entropy_range(input, c, s->PointerToRawData, s->raw_size, &s->entropy) != STATUS_SUCCESS) return STATUS_ERROR;
    }
    return STATUS_SUCCESS;
}
/*
 * Cache measurements for file-backed ELF sections. SHT_NULL and SHT_NOBITS
 * have no payload bytes, so their report rows use NAN/N/A rather than entropy.
 */
int entropy_elf(const InputFile *input, EntropyContext *c, const ELFInfo *info)
{
    for (unsigned i = 0; i < info->section_count; ++i) {
        const SectionHeader *s = &info->section_headers[i]; double value;
        if (s->sh_type != 0 && s->sh_type != 8 &&
            entropy_range(input, c, s->sh_offset, s->sh_size, &value) != STATUS_SUCCESS) return STATUS_ERROR;
    }
    return STATUS_SUCCESS;
}
/*
 * Visit universal slices, then measure each file-backed section at its
 * container offset (slice base + section offset). Skip virtual zero-fill.
 */
int entropy_mach(const InputFile *input, EntropyContext *c, const MachOInfo *info)
{
    for (unsigned i = 0; i < info->slice_count; ++i)
        if (entropy_mach(input, c, &info->slices[i]) != STATUS_SUCCESS) return STATUS_ERROR;
    for (unsigned i = 0; i < info->section_count; ++i) {
        const MachOSection *s = &info->sections[i]; double value;
        if (!s->zerofill && entropy_range(input, c, info->slice_offset + s->offset, s->size, &value) != STATUS_SUCCESS) return STATUS_ERROR;
    }
    return STATUS_SUCCESS;
}
/*
 * Compatibility helper for callers that only need PE section entropy.
 * It creates and frees its own per-file cache; main uses a shared context so
 * whole-file, window, and section calculations can reuse identical ranges.
 */
int calc_entropy(const InputFile *input, PEInfo *info)
{
    EntropyContext c = {0};
    int status = entropy_pe(input, &c, info);
    entropy_free(&c);
    return status;
}

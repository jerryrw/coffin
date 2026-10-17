/*
 * Small services shared by every executable format.
 * A file offset counts bytes from the beginning of a disk file. A virtual address
 * belongs to the program's memory layout and cannot generally be used as an offset.
 * All file reads go through checked ranges; numeric fields are decoded from bytes
 * instead of casting the bytes to a C struct, which could depend on host layout.
 */

#include "common.h"
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "md5.h"
#include "sha256.h"

/*
 * Test whether [offset, offset + length) fits within size bytes.
 * Subtract only after checking offset <= size: adding offset + length first could
 * wrap an unsigned integer and incorrectly accept an out-of-bounds range.
 */
int file_range_valid(uint64_t offset, uint64_t length, uint64_t size)
{
    return offset <= size && length <= size - offset;
}

/*
 * Find a seekable stream's length and rewind it for the hashing pass.
 * ftell returns a signed long; reject its negative error result before converting
 * to size_t, the unsigned C type used for object sizes and buffer lengths.
 */
int file_size_checked(FILE *file, size_t *size)
{
    if (fseek(file, 0, SEEK_END) != 0) return STATUS_ERROR;
    long end = ftell(file);
    if (end < 0 || (uintmax_t)end > SIZE_MAX || fseek(file, 0, SEEK_SET) != 0)
        return STATUS_ERROR;
    *size = (size_t)end;
    return STATUS_SUCCESS;
}

/*
 * Read exactly length bytes into the caller's buffer at an absolute file offset.
 * The caller must provide enough writable memory. Check both the file boundary
 * and the long-based fseek limit; a short fread is an error, not partial success.
 */
int read_at(FILE *file, uint64_t offset, void *buffer, size_t length, size_t size)
{
    if (!file_range_valid(offset, length, size) || offset > LONG_MAX ||
        fseek(file, (long)offset, SEEK_SET) != 0) return STATUS_ERROR;
    return fread(buffer, 1, length, file) == length ? STATUS_SUCCESS : STATUS_ERROR;
}

/*
 * Print the accepted command-line switches. argv[0] is the program name.
 * This routine only prints; main decides whether help or misuse means success.
 */
void print_usage(char *argv[])
{
    fputs("Usage: ", stdout); print_escaped(stdout, argv[0]); puts(" [options] <filepath>");
    puts("  --summary          Summary and structural observations only");
    puts("  --verbose          Full field details and progress on stderr");
    puts("  --headers --sections --observations");
    puts("  --imports --exports --resources       PE detail selectors");
    puts("  --dependencies --symbols             ELF/Mach-O linkage tables");
    puts("  --program-headers                    ELF detail selector");
    puts("  --load-commands                      Mach-O detail selector");
    puts("  --entropy-window BYTES  Add non-overlapping file entropy windows (max 4096)");
    puts("  --no-preview       Hide decoded resource payload previews");
    puts("  --code-page N      Fallback code page for unspecified resource text");
    puts("  --extract-resources NEW_DIRECTORY     Extract PE resource payloads");
    puts("  --version          Show the build version");
    puts("  --help             Show this help");
    puts("Selectors may be combined; unsupported format/selector pairs fail.");

}

/*
 * Combine two little-endian bytes into a 16-bit unsigned integer.
 * Little-endian stores the least significant byte first.
 */
uint16_t decode16(const unsigned char *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/*
 * Combine four little-endian bytes. Cast to an unsigned 32-bit type BEFORE
 * shifting so high-bit input does not become a signed shift overflow.
 */
uint32_t decode32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/*
 * Combine two decoded 32-bit halves, promoting the upper half before << 32.
 * A shift by 32 would be invalid on a value that was still only 32 bits wide.
 */
uint64_t decode64(const unsigned char *p)
{
    return (uint64_t)decode32(p) | ((uint64_t)decode32(p + 4) << 32);
}

/*
 * Convert each digest byte into two lowercase hexadecimal digits.
 * The destination needs 2 * length + 1 bytes; the extra byte is C's '\0'
 * string terminator, which is not part of the displayed digest.
 */
static void hex_string(const uint8_t *bytes, size_t length, char *output)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; ++i) {
        output[2 * i] = digits[bytes[i] >> 4];
        output[2 * i + 1] = digits[bytes[i] & 15];
    }
    output[2 * length] = '\0';
}

/* Both hashes use one pass on the same open stream used by the parsers. */
/*
 * Measure and rewind the stream, then feed each 8 KiB chunk to BOTH hashes.
 * remaining counts known file bytes, preventing a short read from silently
 * producing a digest for truncated input. This leaves the stream at the end;
 * parsers subsequently use absolute read_at calls, so they do not need a rewind.
 */
int input_prepare(InputFile *input)
{
    SHA256_CTX sha;
    MD5_CTX md5;
    unsigned char buffer[8192], sha_digest[32], md5_digest[16];
    if (file_size_checked(input->file, &input->size) != STATUS_SUCCESS)
        return STATUS_ERROR;
    sha256_init(&sha);
    md5_init(&md5);
    size_t remaining = input->size;
    while (remaining) {
        size_t chunk = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
        if (fread(buffer, 1, chunk, input->file) != chunk) return STATUS_ERROR;
        sha256_update(&sha, buffer, chunk);
        md5_update(&md5, buffer, chunk);
        remaining -= chunk;
    }
    if (ferror(input->file)) return STATUS_ERROR;
    sha256_final(&sha, sha_digest);
    md5_final(&md5, md5_digest);
    hex_string(sha_digest, sizeof(sha_digest), input->sha256);
    hex_string(md5_digest, sizeof(md5_digest), input->md5);
    if (input->verbose)
        { fputs("Analyzing ", stderr); print_escaped(stderr, input->path);
          fprintf(stderr, " (%zu bytes); SHA-256 and MD5 calculated\n", input->size); }
    return STATUS_SUCCESS;
}

/*
 * Translate the caller's format-specific bit masks into words.
 * flags & read_bit is nonzero exactly when that permission bit is declared.
 */
void print_permissions(uint32_t flags, uint32_t read_bit, uint32_t write_bit, uint32_t execute_bit)
{
    printf("%s%s%s", flags & read_bit ? "read " : "",
           flags & write_bit ? "write " : "", flags & execute_bit ? "execute" : "");
}

/*
 * Decode a 16-bit field in the file's byte order (big != 0 means big-endian).
 * The caller has already ensured that at least two bytes can be read.
 */
uint16_t read16_order(const unsigned char *p, int big)
{
    return big ? (uint16_t)((uint16_t)p[0] << 8 | p[1]) : decode16(p);
}
/*
 * Decode four bytes in the selected byte order, using unsigned shifts.
 * Big-endian stores the most significant byte first.
 */
uint32_t read32_order(const unsigned char *p, int big)
{
    return big ? ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]) : decode32(p);
}
/*
 * Decode eight bytes as two 32-bit halves in the selected byte order.
 * This also works on machines whose native byte order differs from the file.
 */
uint64_t read64_order(const unsigned char *p, int big)
{
    return big ? ((uint64_t)read32_order(p, 1) << 32 | read32_order(p + 4, 1)) : decode64(p);
}
/*
 * Ensure a heap array can hold needed elements, without changing its count.
 * void ** lets this helper update the caller's pointer when realloc moves it.
 * capacity is allocated slots; the caller separately tracks occupied slots.
 * Grow geometrically to avoid reallocating on every append. Bound multiplication
 * by the per-array byte budget, and keep the old allocation if realloc fails.
 */
int reserve_array(void **array, unsigned *capacity, unsigned needed, size_t item_size)
{
    const size_t budget = 64u * 1024u * 1024u;
    if (!item_size || needed > budget / item_size) {
        fprintf(stderr, "Report table exceeds the 64 MiB allocation budget\n");
        return STATUS_ERROR;
    }
    if (needed <= *capacity) return STATUS_SUCCESS;
    unsigned next = *capacity ? *capacity : 16;
    while (next < needed && next <= (budget / item_size) / 2) next *= 2;
    if (next < needed || next > budget / item_size) next = needed;
    void *grown = realloc(*array, (size_t)next * item_size);
    if (!grown) return STATUS_ERROR;
    *array = grown; *capacity = next;
    return STATUS_SUCCESS;
}

/* Build display text separately from raw file bytes. Escaping high bytes as well
 * as controls avoids locale-dependent interpretation and Unicode direction tricks.
 * The caller supplies distinct input/output buffers; parsing keeps raw offsets. */
void escape_display(char *out, size_t capacity, const unsigned char *bytes, size_t length)
{
    if (!capacity) return;
    size_t required = 0, used = 0; int truncated = 0;
    for (size_t i = 0; i < length && bytes[i]; ++i) {
        unsigned char c = bytes[i];
        size_t n = c < 32 || c >= 127 || c == '\\' ? 4 : 1;
        if (n > capacity - required - 1) { truncated = 1; break; }
        required += n;
    }
    size_t limit = truncated && capacity >= 4 ? capacity - 4 : capacity - 1;
    for (size_t i = 0; i < length && bytes[i]; ++i) {
        unsigned char c = bytes[i];
        size_t n = c < 32 || c >= 127 || c == '\\' ? 4 : 1;
        if (n > limit - used) break;
        if (n == 4) snprintf(out + used, capacity - used, "\\x%02X", c);
        else out[used] = (char)c;
        used += n;
    }
    if (truncated && capacity >= 4) { memcpy(out + used, "...", 3); used += 3; }
    out[used] = 0;
}

/* Paths may be arbitrarily long, so print incrementally rather than truncating. */
void print_escaped(FILE *out, const char *text)
{
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p)
        if (*p < 32 || *p >= 127 || *p == '\\') fprintf(out, "\\x%02X", *p);
        else fputc(*p, out);
}

/* Capture errno before printing, since library calls may change it. */
void print_path_error(const char *prefix, const char *path)
{
    int saved = errno;
    fprintf(stderr, "%s: ", prefix); print_escaped(stderr, path);
    fprintf(stderr, ": %s\n", strerror(saved));
}

int read_display_string(const InputFile *input, uint64_t offset, uint64_t size,
                        char *out, size_t capacity, uint64_t *work)
{
    unsigned char bytes[4096];
    size_t used = 0;
    /* Read short chunks: fetching 4 KiB for every two-character symbol would
     * waste I/O and exhaust the shared budget long before useful table limits. */
    while (used < sizeof(bytes) && used < size) {
        size_t count = size - used < 64 ? (size_t)(size - used) : 64;
        if (count > sizeof(bytes) - used) count = sizeof(bytes) - used;
        if (*work > 16u * 1024u * 1024u || count > 16u * 1024u * 1024u - *work ||
            read_at(input->file, offset + used, bytes + used, count, input->size) != STATUS_SUCCESS) return STATUS_ERROR;
        *work += count;
        const unsigned char *end = memchr(bytes + used, 0, count);
        if (end) {
            escape_display(out, capacity, bytes, (size_t)(end - bytes));
            return STATUS_SUCCESS;
        }
        used += count;
    }
    return STATUS_ERROR;
}

/*
 * Shared types and function declarations (implementations are in src/common.c).
 * #ifndef/#define/#endif form an include guard: repeated #include directives do
 * not redeclare these types in one translation unit. uint32_t/uint64_t specify
 * exact-width unsigned integers; size_t describes in-memory sizes and counts.
 * STATUS_SUCCESS is zero and STATUS_ERROR is -1; always compare explicitly.
 */

#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

/*
 * Checked file helpers return STATUS_*; size/out pointers receive results.
 * read_at requires an output buffer of at least length bytes.
 */
int file_size_checked(FILE *file, size_t *size);
int file_range_valid(uint64_t offset, uint64_t length, uint64_t size);
int read_at(FILE *file, uint64_t offset, void *buffer, size_t length, size_t size);

/*
 * InputFile borrows path (an argv string) and stores one open FILE * stream.
 * main owns opening/closing the stream. Other functions only borrow this record.
 */
typedef struct {
    /*
     * FILE * is a pointer to the C library's stream state, not the file contents.
     */
    FILE *file;
    const char *path;
    size_t size;
    /*
     * Hex strings need two characters per digest byte plus a terminating zero.
     */
    char sha256[65];
    char md5[33];
    int verbose;
    /*
     * Zero selects the default fallback policy; nonzero is the --code-page value.
     */
    uint32_t text_code_page;
} InputFile;

/*
 * Hash the measured file once into the InputFile fields; does not close it.
 */
int input_prepare(InputFile *input);
/*
 * Decode little-endian bytes; the caller validates buffer size first.
 * The *_order variants use big != 0 for big-endian fields.
 */
uint16_t decode16(const unsigned char *bytes);
uint32_t decode32(const unsigned char *bytes);
uint64_t decode64(const unsigned char *bytes);
uint16_t read16_order(const unsigned char *p, int big);
uint32_t read32_order(const unsigned char *p, int big);
uint64_t read64_order(const unsigned char *p, int big);
/*
 * array points to the caller's pointer; capacity points to its slot count.
 * The helper may move the allocation. Needed elements and item size must be valid.
 */
int reserve_array(void **array, unsigned *capacity, unsigned needed, size_t item_size);
void print_permissions(uint32_t flags, uint32_t read_bit, uint32_t write_bit, uint32_t execute_bit);

#define STATUS_ERROR -1
#define STATUS_SUCCESS 0

/* Escape untrusted bytes into ASCII text. Output always ends with zero when
 * capacity is nonzero; a shortened display ends with an ellipsis. */
void escape_display(char *out, size_t capacity, const unsigned char *bytes, size_t length);
void print_escaped(FILE *out, const char *text);
void print_path_error(const char *prefix, const char *path);
/* Read a bounded, terminated string from a checked file interval, charging work. */
int read_display_string(const InputFile *input, uint64_t offset, uint64_t size,
                        char *out, size_t capacity, uint64_t *work);
void print_usage (char* argv[]);

#endif

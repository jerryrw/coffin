/*
 * MD5 streaming state and declarations; implementation is in src/md5.c.
 * uint32_t gives words exactly 32 bits wide; uint64_t holds the bit counter.
 * Arrays store bytes inside the context, so no heap allocation is required.
 * See the lifecycle contract below before calling the functions.
 */

#ifndef MD5_H
#define MD5_H

#include <stdint.h>
#include <stddef.h>

// MD5 context structure
typedef struct
{
    /*
     * Running chaining words; update transforms each full 64-byte block into them.
     */
    uint32_t state[4];
    /*
     * Total input bits modulo 2^64; its low bits locate buffered bytes.
     */
    uint64_t count;
    /*
     * Unprocessed tail, later completed by another update or final padding.
     */
    uint8_t buffer[64];
} MD5_CTX;

/* Streaming API contract:
 * Initialize a non-NULL context before its first update.
 * Updates accept arbitrary chunk sizes; a zero-length update is a no-op and
 * permits a NULL input pointer. Nonempty input must point to that many bytes.
 * Finalize exactly once into a non-NULL output buffer of 16 bytes. Finalization
 * consumes the context; reinitialize before reuse, further updates, or another
 * finalization. These functions do not validate pointers or context state.
 */
void md5_init(MD5_CTX *context);
void md5_update(MD5_CTX *context, const uint8_t *input, size_t input_len);
void md5_final(MD5_CTX *context, uint8_t digest[16]);
/* Internal compression primitive; not part of the streaming API. */
void md5_transform(MD5_CTX *context, const uint8_t block[64]);

#endif

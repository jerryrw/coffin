/*
 * SHA-256 streaming state and declarations; implementation is in src/sha256.c.
 * The context is a caller-owned struct, not an allocated object or file handle.
 * Its data array retains incomplete blocks, and its state words chain full blocks.
 * The API writes raw digest bytes; common.c separately converts them to hex text.
 */

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

// SHA-256 context structure
typedef struct
{
    /*
     * Holds only the incomplete tail between update calls.
     */
    uint8_t data[64];
    /*
     * Number of buffered tail bytes: 0-63 between public calls.
     */
    uint32_t datalen;
    /*
     * Bits from completed blocks; final adds datalen * 8 before length encoding.
     */
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

/* Streaming API contract:
 * Initialize a non-NULL context before its first update.
 * Updates accept arbitrary chunk sizes; a zero-length update is a no-op and
 * permits a NULL input pointer. Nonempty input must point to that many bytes.
 * Finalize exactly once into a non-NULL output buffer of 32 bytes. Finalization
 * consumes the context; reinitialize before reuse, further updates, or another
 * finalization. These functions do not validate pointers or context state.
 */
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t *hash);
/* Internal compression primitive; not part of the streaming API. */
void sha256_transform(SHA256_CTX *ctx, const uint8_t *data);

#endif

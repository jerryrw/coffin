/*
 * Streaming SHA-256 implementation: init -> update chunks -> final digest.
 * Each 64-byte block updates eight 32-bit words. The last partial block stays in
 * the context until more input arrives or final() adds padding and a length.
 * Unsigned 32-bit arithmetic supplies the wraparound required by the algorithm.
 * SHA-256 decodes words and writes its digest in big-endian byte order.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "sha256.h"

// SHA-256 constants
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

/*
 * The large EP functions mix state words; the small SIG functions expand
 * message words. CH selects bits from y/z according to x, while MAJ takes
 * the majority of three bits. ROTRIGHT preserves bits that cross the boundary.
 * K holds the 64 fixed round constants required by the algorithm.
 */
// Bitwise operations
#define ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (32 - (b))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))
#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))

// Initialize SHA-256 context
/*
 * Reset the buffered-byte count, processed-bit count, and eight initial words.
 * The fixed initial values are part of SHA-256, not random values chosen per file.
 */
void sha256_init(SHA256_CTX *ctx)
{
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

// Update context with more data
/*
 * Feed arbitrary chunk sizes without retaining pointers to caller memory.
 * First complete a buffered partial block, then process full input blocks directly,
 * and finally copy the remaining 0-63 bytes into ctx->data. bitlen counts only
 * completed blocks; final adds the buffered tail's bit count.
 */
void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len)
{
    if (!len) return;

    /* Complete the buffered block before processing input blocks directly. */
    if (ctx->datalen) {
        size_t chunk = 64 - ctx->datalen;
        if (chunk > len) chunk = len;
        memcpy(ctx->data + ctx->datalen, data, chunk);
        ctx->datalen += (uint32_t)chunk;
        data += chunk;
        len -= chunk;
        if (ctx->datalen < 64) return;
        sha256_transform(ctx, ctx->data);
        ctx->bitlen += UINT64_C(512);
        ctx->datalen = 0;
    }

    /* The transform decodes bytes explicitly, so unaligned input is safe. */
    while (len >= 64) {
        sha256_transform(ctx, data);
        ctx->bitlen += UINT64_C(512);
        data += 64;
        len -= 64;
    }
    if (len) memcpy(ctx->data, data, len);
    ctx->datalen = (uint32_t)len;
}

// Finalize hash computation
/*
 * Finish with a 1 bit (0x80), zero padding, and the 64-bit big-endian bit length.
 * The length field needs eight bytes; if the buffered tail already occupies 56
 * or more bytes, compress one padding block before writing the length in another.
 * Finally split the eight state words into 32 big-endian digest bytes.
 */
void sha256_final(SHA256_CTX *ctx, uint8_t *hash)
{
    size_t i = ctx->datalen;

    // Padding
    if (ctx->datalen < 56)
    {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0x00;
    }
    else
    {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0x00;

        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    // Append total bit length
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;

    sha256_transform(ctx, ctx->data);

    // Convert state to hash bytes
    for (i = 0; i < 4; ++i)
    {
        hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000FF;
        hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000FF;
        hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000FF;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000FF;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000FF;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000FF;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000FF;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000FF;
    }
}

// Main SHA-256 transformation function
/*
 * Compress one block without modifying datalen/bitlen bookkeeping.
 * Decode 16 big-endian words and expand them into a 64-word message schedule.
 * Run 64 rounds on working words a-h, then add those words to the saved state.
 * All words are uint32_t so arithmetic wraps modulo 2^32 as SHA-256 requires.
 */
void sha256_transform(SHA256_CTX *ctx, const uint8_t *data)
{
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = ((uint32_t)data[j]     << 24) |
               ((uint32_t)data[j + 1] << 16) |
               ((uint32_t)data[j + 2] << 8)  |
               ((uint32_t)data[j + 3]);

    /*
     * Each new schedule word depends on four earlier words. This expansion
     * spreads the original block's bits across all 64 compression rounds.
     */
    for (; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i)
    {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>

// SHA-256 context structure
typedef struct
{
    uint8_t data[64];
    uint32_t datalen;
    unsigned long long bitlen;
    uint32_t state[8];
} SHA256_CTX;

// Function prototypes
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t *hash);
void sha256_transform(SHA256_CTX *ctx, const uint8_t *data);
int calculate_file_sha256(const char *filepath, uint8_t *hash);

#endif
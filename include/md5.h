#ifndef MD5_H
#define MD5_H

#include <stdint.h>

// MD5 context structure
typedef struct
{
    uint32_t state[4];
    uint64_t count;
    uint8_t buffer[64];
} MD5_CTX;

// Function prototypes
void md5_init(MD5_CTX *context);
void md5_update(MD5_CTX *context, const uint8_t *input, size_t input_len);
void md5_final(MD5_CTX *context, uint8_t digest[16]);
void md5_transform(MD5_CTX *context, const uint8_t block[64]);
int calculate_file_md5(const char *filepath, uint8_t *hash);

#endif
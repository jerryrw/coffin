/*
 * Direct hash tests exercise the public init/update/final interfaces.
 * Expected digests are constants, never produced by the implementation under test.
 * assert aborts on a mismatch; compile without NDEBUG to keep checks enabled.
 * Each input is hashed using several partitions, which must all yield the same
 * digest because chunk boundaries are not part of the hashed message.
 */

/* Expected digests are fixed reference values, independent of the C code.
 * Binary vectors use byte[i] = (i * 37 + 11) mod 256.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "md5.h"
#include "sha256.h"

typedef struct {
    const char *text;
    size_t size;
    const char *md5, *sha256;
    int pattern; /* 0: text, 1: binary pattern, 2: repeated 'a'. */
} Vector;

static const Vector vectors[] = {
    {"", 0, "d41d8cd98f00b204e9800998ecf8427e", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 0},
    {"a", 1, "0cc175b9c0f1b6a831c399e269772661", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", 0},
    {"abc", 3, "900150983cd24fb0d6963f7d28e17f72", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 0},
    {"message digest", 14, "f96b697d7cb7938d525a2f31aaf161d0", "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650", 0},
    {"abcdefghijklmnopqrstuvwxyz", 26, "c3fcd3d76192e4007dfb496cca67e13b", "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73", 0},
    {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62, "d174ab98d277d9f5a5611c2c9f419d9f", "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0", 0},
    {"12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80, "57edf4a22be3c955ac49da2e2107b67a", "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e", 0},
    {NULL, 0, "d41d8cd98f00b204e9800998ecf8427e", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 1},
    {NULL, 1, "13c8ffd977013703a701cf8e11deac65", "e7cf46a078fed4fafd0b5e3aff144802b853f8ae459a4f0c14add3314b7cc3a6", 1},
    {NULL, 2, "a22664edce89fafc28f264d313c39d51", "cdc63a6325d5fa92515578c0b418e6eeec1c6d085937a24fc43c2126ea517457", 1},
    {NULL, 3, "876d16c575f9d3d7f51f12fef37237eb", "b39fad1a1075f64570b3226d339ea818f9c66ecd2f1c59fd8b9c5a32b54c513f", 1},
    {NULL, 54, "5e5534f470ef1d65657807ed96610693", "0b35cded48f546833dc4e93133ffc3d7e05c7e41842f4accc39c6e04204c8dde", 1},
    {NULL, 55, "d872aa0473a24da995ce4ac518ade767", "2900465fcb533e05a158fd2b3be0e5e3b03740d83060aa3580e0d98a96bf2384", 1},
    {NULL, 56, "e23567645846677c205de80f9779081b", "31454ff48ef36af2f08fd511bdc37d9d5855ac23e992e5ff5445cb6b7674a674", 1},
    {NULL, 57, "1fe5e4a27e12484d7203d0b60c21c51f", "bcc0a5d3791b985b7550e04ca660a6c63a589ba1edd2283c8e110e5b515df124", 1},
    {NULL, 58, "496c1fa53bb99ae398aa131ced2180d9", "625f50f0c121a43afb524b104e3edf8eacf001ffd8795ac11609f458bb4c9003", 1},
    {NULL, 59, "3788ef2f95eee1791e29c134589d25a7", "5a85bd878ca7ff9e9a89748f613bf443cf10d199662c21e7115fca98262fa411", 1},
    {NULL, 60, "4ac2483217717835220f6aeef7fb9c71", "35d6f8129baac2bc4427ae4f5d831acde4a59233146da0e0524cd6b445ff6982", 1},
    {NULL, 61, "377169c1005e5304bbb6b4f3213324c4", "de1025bf69990152626ae709c870a15a907a1775ecf669fb3d4955a4ee23a3da", 1},
    {NULL, 62, "fb973e262a6b29c6569aacf1f7fbc798", "88908d0c7953bf0924d1e1e6f494578300aab9c32e4312f1e733832ff57d8bff", 1},
    {NULL, 63, "4775b66278a8fc132ff80923378216cd", "5f6401b96532c36de4e65beec0409b69b1d181864c8009b7a04f43e5d56350d1", 1},
    {NULL, 64, "71e123b70c7aa64826fcfe472694cd1c", "94eb5de4943613fd048dc93393ab06877405faa39c11f53e9386083339833e7e", 1},
    {NULL, 65, "5949948f26e35203661075214faa3966", "fc518669b6eb4b4dd91827ecacef86689c725bd5bab888fd3b26dbb196eec954", 1},
    {NULL, 66, "a98798c0bd6121b8600eb7f3585bd13f", "65d7b2dbf0f1402f1c5e0d31165ae5a2660417bb118185f8e802ff2433b10b61", 1},
    {NULL, 118, "b8eb7b96d9672e6200a4abf511457282", "f3283313d4f923cd7202ee64fa023aa6daa492bc7838b9f970d24a9f8cc62a93", 1},
    {NULL, 119, "87f72c7241c5fe218bb4df8c0aba3232", "b0dc41b1a384e2f1203f0351b38fbeaafceef577ce1191d5bfc25da39f721eae", 1},
    {NULL, 120, "bf240b8b7407fba3805adeec63a03b77", "5df24dd802ac26132ce608dcb5f09841eef039ee0f152acf98d26d17fe4e88e6", 1},
    {NULL, 121, "c51004ed1ef4271c82106468a13fe8cf", "5ed5a129bb49444fe2585d785920135a02f64350edf57c5f3ce7605b86f39039", 1},
    {NULL, 122, "e3c630417415f51588089c65aab9c5ad", "8419642ca144c4337525ba61c1f2d3d291449fd49c86eaa902ea1eb756865794", 1},
    {NULL, 123, "d2968ad8dfc3c448319c3f416d6355e1", "b9b8bc6127b8c9e1396cc2081b5181edc2a264746b6038b094e49b7ea8a98a46", 1},
    {NULL, 124, "a6f820c06167fbcfc5632d376c7f9cbd", "3dc980ced4e4687929dd079c84fe8e6e4b3d6a80435a68bb3ad4bb860ea63b80", 1},
    {NULL, 125, "a268e9c5fca2f6424f919af519dbae1e", "7e4f5abad35b869cb65368b12294c008848db0e48c513f6eab6c768daabe73ab", 1},
    {NULL, 126, "f7c3825a26578ffba075a8bd6b0239e0", "8513afe4abd1c76b2e4959fa30344f1c85bb8acbbf0284f161aa47fbf459e483", 1},
    {NULL, 127, "520bdc2dbab7c25d64263ffb242d9e98", "0fe729ff19257bd6fec853acc2ea355f6b34b58e6c0f684c3e188fcdfcd9baae", 1},
    {NULL, 128, "3e93b378458b77da96b2357c3bda8cc2", "0aedd4856f8eba0963627336ad5144a9a7dbe12498e6066f0165fc97d8ddee4c", 1},
    {NULL, 129, "d1ae06bbf9128955a34bedb6231eee62", "4f1757ae4bffbae86d775b831765b75af154d52f7deaa46dd378051a2d3ad57f", 1},
    {NULL, 130, "8a2682a4b1a920cccc7c09422b233d76", "d35b74124cb85cfac62bfeaf3a9771efab3e0ef88fc43702c35a6efe09467cc1", 1},
    {NULL, 255, "e69ce3a96f27a14cc830d6b8b44b1c74", "3c835ac0bba7147eaa568a76183d465e72ac456df24b55e01d44dc87be05a971", 1},
    {NULL, 256, "d2fc7db3ff87e1ebaabbcb16c0c92ea2", "3ef33734daae0e353f132ff5f3241d8f86ba81f851c0b9685149f079c16eb45b", 1},
    {NULL, 257, "de795cc04890f2dd3e653c88a67f3e68", "08570fb3dfab53bcb3e8f4ca60b7331d9c603460a45d978226e18dd019468d07", 1},
    {NULL, 8191, "f08f3d2d7d8912b166ca8b0d92caf799", "b88204d9cd8eb4d1d3c268874db52dcf610a0b41ea701f3cdfccf0c59a3b2fb2", 1},
    {NULL, 8192, "1daee1dda42da9fda27309a6e824a846", "1f5a16c4456f34c5459e4e66d8650d4dbb6b298810d0c21cef6571db21d69c81", 1},
    {NULL, 8193, "eabf3aacb83c95ee7fb5836f5b15a63f", "d37426b71db09954cacd4d2be0059f5dbd7ad5d32fc42ab0eeda4ed1a4e1bebc", 1},
    {NULL, 16385, "bce79ba628f366565dbce5df5061d87e", "5e73ca9fc03d81e49a3451b60dc22dab107d0515d80636f97d95d68d117515ff", 1},
    {NULL, 1000000, "7707d6ae4e027c70eea2a935c2296f21", "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", 2}
};

/*
 * Compare raw digest bytes against a fixed hexadecimal string. The high nibble
 * is byte >> 4; the low nibble is byte & 15. Together they select two hex digits.
 */
static void expect_hex(const unsigned char *digest, size_t size, const char *expected)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < size; ++i) {
        assert(expected[i * 2] == hex[digest[i] >> 4]);
        assert(expected[i * 2 + 1] == hex[digest[i] & 15]);
    }
    assert(expected[size * 2] == '\0');
}

/*
 * For each vector, construct its bytes and try all chunking strategies.
 * Zero means one-shot input; SIZE_MAX selects deterministic varying chunks.
 * Reinitialize the same context objects before every attempt, then insert empty
 * updates between chunks to verify that partial buffered state is preserved.
 */
int main(void)
{
    const size_t chunks[] = {0, 1, 7, 55, 56, 63, 64, 65, 8192, 8193, SIZE_MAX};
    unsigned checks = 0;
    /*
     * sizeof(array) / sizeof(array[0]) gives the number of elements in an actual
     * array. It would NOT work on a pointer, whose sizeof is only the pointer size.
     */
    for (size_t v = 0; v < sizeof(vectors) / sizeof(*vectors); ++v) {
        const Vector *vector = &vectors[v];
        unsigned char *allocation = malloc(vector->size + 2);
        assert(allocation);
        unsigned char *data = allocation + 1; /* Deliberately unaligned blocks. */
        for (size_t i = 0; i < vector->size; ++i)
            data[i] = vector->pattern == 1 ? (unsigned char)(i * 37 + 11) :
                      vector->pattern == 2 ? 'a' : (unsigned char)vector->text[i];
        MD5_CTX md5; SHA256_CTX sha;
        for (size_t c = 0; c < sizeof(chunks) / sizeof(*chunks); ++c) {
            md5_init(&md5); sha256_init(&sha);
            md5_update(&md5, NULL, 0); sha256_update(&sha, NULL, 0);
            size_t offset = 0; uint32_t random = 0xc0ffee;
            while (offset < vector->size) {
                size_t chunk = chunks[c];
                if (!chunk) chunk = vector->size;
                if (chunk == SIZE_MAX) {
                    /*
                     * This deterministic generator varies chunk sizes reproducibly. It is
                     * only test scheduling, not cryptographic randomness or input content.
                     */
                    random = random * UINT32_C(1664525) + UINT32_C(1013904223);
                    chunk = (random % 257) + 1;
                }
                if (chunk > vector->size - offset) chunk = vector->size - offset;
                md5_update(&md5, data + offset, chunk);
                sha256_update(&sha, data + offset, chunk);
                /* Zero-length updates must preserve even partially buffered data. */
                md5_update(&md5, NULL, 0); sha256_update(&sha, NULL, 0);
                offset += chunk;
            }
            unsigned char md5_digest[16], sha_digest[32];
            md5_final(&md5, md5_digest); sha256_final(&sha, sha_digest);
            expect_hex(md5_digest, sizeof(md5_digest), vector->md5);
            expect_hex(sha_digest, sizeof(sha_digest), vector->sha256);
            checks += 2;
        }
        free(allocation);
    }
    printf("Hash tests passed: %u digest checks\n", checks);
    return 0;
}

/*
 * Shared entry point for libFuzzer and the deterministic mutation smoke runner.
 * Malformed inputs are normal: a parser returning an error is not a fuzz failure.
 * Crashes, hangs, and sanitizer diagnostics are what the harness tries to expose.
 * No report is printed, but valid inputs also exercise entropy and image assembly.
 * Always free results: a fuzz process may inspect thousands of inputs in one run.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "peparser.h"
#include "elfparser.h"
#include "machparser.h"
#include "entropy.h"

/* No pathname reopen: the same temporary stream feeds metadata and parsing. */
/*
 * libFuzzer calls this function with a borrowed byte buffer and its size.
 * Store bytes in a temporary stream to exercise the real file-reading code path.
 * Ignore ordinary STATUS_ERROR results, but preserve cleanup on every path.
 * Return zero to let libFuzzer continue generating other inputs.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 1024 * 1024) return 0;
    InputFile input = {0};
    EntropyContext entropy = {0};
    input.path = "<fuzz>";
    input.file = tmpfile();
    if (!input.file) return 0;
    if (fwrite(data, 1, size, input.file) != size ||
        input_prepare(&input) != STATUS_SUCCESS) goto done;
    if (size >= 2 && data[0] == 'M' && data[1] == 'Z') {
        PEInfo info;
        if (parse_pe_file(&input, &info) == STATUS_SUCCESS) {
            (void)entropy_file(&input, &entropy);
            (void)entropy_pe(&input, &entropy, &info);
            for (unsigned i = 0; i < info.resource_count; ++i) {
                unsigned char *image = NULL; size_t image_size = 0;
                (void)reconstruct_resource_image(&input, &info, i, &image, &image_size);
                free(image);
            }
        }
        free_pe_info(&info);
    } else if (size >= 4 && !memcmp(data, "\177ELF", 4)) {
        ELFInfo info;
        if (parse_elf_file(&input, &info) == STATUS_SUCCESS) {
            (void)entropy_file(&input, &entropy);
            (void)entropy_elf(&input, &entropy, &info);
        }
        free_elf_info(&info);
    } else {
        MachOInfo info;
        if (parse_mach_file(&input, &info) == STATUS_SUCCESS) {
            (void)entropy_file(&input, &entropy);
            (void)entropy_mach(&input, &entropy, &info);
        }
        free_mach_info(&info);
    }
done:
    entropy_free(&entropy);
    fclose(input.file);
    return 0;
}

#ifdef STANDALONE_FUZZ
#include <stdlib.h>

/* Portable deterministic smoke runner for toolchains without libFuzzer. */
/*
 * The STANDALONE_FUZZ build supplies this ordinary main instead of libFuzzer's.
 * For each seed, repeatedly reset a copy, truncate or flip a few bits, and pass
 * it to the same harness. A fixed pseudo-random state makes failures reproducible.
 */
int main(int argc, char **argv)
{
    uint32_t random_state = 0xC0FFEE;
    for (int arg = 1; arg < argc; ++arg) {
        FILE *file = fopen(argv[arg], "rb");
        size_t size;
        if (!file || file_size_checked(file, &size) != STATUS_SUCCESS || size > 1024 * 1024) {
            if (file) fclose(file);
            return 1;
        }
        /*
         * Keep the original seed separate from the mutable copy, so mutations do
         * not accumulate and destroy all valid structure. Allocate at least one byte
         * even for an empty seed to avoid relying on malloc(0) behavior.
         */
        unsigned char *seed = malloc(size ? size : 1), *mutated = malloc(size ? size : 1);
        if (!seed || !mutated) { free(seed); free(mutated); fclose(file); return 1; }
        if (fread(seed, 1, size, file) != size) {
            free(seed); free(mutated); fclose(file); return 1;
        }
        fclose(file);
        for (unsigned iteration = 0; iteration < 1000; ++iteration) {
            memcpy(mutated, seed, size);
            random_state = random_state * 1664525u + 1013904223u;
            size_t length = iteration % 4 == 0 ? random_state % (size + 1) : size;
            if (iteration % 4 != 0 && size) {
                for (unsigned j = 0; j < 1 + iteration % 8; ++j) {
                    random_state = random_state * 1664525u + 1013904223u;
                    /* Concentrate some mutations in headers to reach structural checks. */
                    size_t span = iteration % 2 && size > 512 ? 512 : size;
                    size_t offset = random_state % span;
                    mutated[offset] ^= (unsigned char)(1u << ((random_state >> 16) % 8));
                }
            }
            LLVMFuzzerTestOneInput(mutated, length);
        }
        free(seed); free(mutated);
    }
    puts("Completed 1000 deterministic mutations per sample");
    return 0;
}
#endif

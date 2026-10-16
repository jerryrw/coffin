/*
 * Focused entropy tests with mathematically known answers and observable budgets.
 * assert(condition) aborts with a location if a check fails. Run tests without
 * NDEBUG, which disables assertions. Budget/range error messages below are expected
 * negative-test output, not failures. tmpfile supplies an automatically removed
 * stream, and no executable fixture needs to be modified.
 */

#include <assert.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include "entropy.h"

/*
 * Compare floating-point values with a small absolute tolerance rather than ==.
 * Different evaluation orders can introduce tiny rounding differences.
 */
static void near(double actual, double expected)
{
    assert(fabs(actual - expected) < 1e-12);
}

/*
 * Test distributions, chunked reads, cache reuse, rejected reads, rehashing,
 * and final short windows. Stack-built PESection records borrow local storage;
 * do not call free_pe_info on them, because only heap allocations can be freed.
 */
int main(void)
{
    unsigned char bytes[20000];
    memset(bytes, 'A', sizeof(bytes));
    near(calculate_entropy(bytes, sizeof(bytes)), 0);
    memset(bytes + 10000, 'B', 10000);
    near(calculate_entropy(bytes, sizeof(bytes)), 1);
    memset(bytes + 10000, 'A', 5000);
    near(calculate_entropy(bytes, sizeof(bytes)), 0.8112781244591328);
    for (unsigned i = 0; i < sizeof(bytes); ++i) bytes[i] = (unsigned char)i;
    near(calculate_entropy(bytes, 16384), 8); /* Predictable sequence, maximal byte histogram. */
    assert(isnan(calculate_entropy(bytes, 0)));
    assert(isnan(calculate_entropy(NULL, 10)));

    InputFile input = {0};
    input.file = tmpfile(); assert(input.file);
    input.size = sizeof(bytes);
    /* Unequal probabilities across chunk boundaries: averaging chunk entropy fails. */
    memset(bytes, 'A', 15000); memset(bytes + 15000, 'B', 5000);
    assert(fwrite(bytes, 1, sizeof(bytes), input.file) == sizeof(bytes));
    EntropyContext context = {0}; double value;
    assert(entropy_range(&input, &context, 0, input.size, &value) == STATUS_SUCCESS);
    near(value, 0.8112781244591328);
    assert(context.bytes_read == input.size);
    /* Cache lookups must succeed without spending the remaining work budget. */
    /*
     * Simulate an exhausted budget without reading 1 GiB. An exact cache hit
     * must still succeed; a different uncached interval must be rejected.
     */
    context.bytes_read = ENTROPY_WORK_LIMIT;
    assert(entropy_range(&input, &context, 0, input.size, &value) == STATUS_SUCCESS);
    near(value, 0.8112781244591328);
    assert(context.bytes_read == ENTROPY_WORK_LIMIT);
    assert(entropy_range(&input, &context, 1, input.size - 1, &value) == STATUS_ERROR);
    assert(entropy_range(&input, &context, input.size, 1, &value) == STATUS_ERROR);
    assert(entropy_range(&input, &context, 0, 0, &value) == STATUS_SUCCESS && isnan(value));
    entropy_free(&context);

    /* Repeated section aliases share a cache entry. */
    PESection sections[3] = {0};
    PEInfo pe = {0}; pe.sections = sections; pe.section_count = 3;
    for (unsigned i = 0; i < 3; ++i) sections[i].raw_size = sizeof(bytes);
    assert(entropy_pe(&input, &context, &pe) == STATUS_SUCCESS);
    assert(context.bytes_read == input.size && context.count == 1);
    near(sections[2].entropy, 0.8112781244591328);
    /* Exercise rehashing and verify preserved cached values. */
    for (unsigned i = 1; i < 400; ++i)
        assert(entropy_range(&input, &context, i, 1, &value) == STATUS_SUCCESS);
    near(entropy_lookup(&context, 0, input.size), 0.8112781244591328);
    near(entropy_lookup(&context, 399, 1), 0);
    assert(context.capacity >= 1024);
    entropy_free(&context);
    context.window_size = 8192;
    assert(entropy_file(&input, &context) == STATUS_SUCCESS);
    assert(context.window_count == 3);
    near(context.windows[0], 0);
    near(context.windows[2], 0);
    near(context.whole, 0.8112781244591328);
    entropy_free(&context);
    fclose(input.file);
    puts("Entropy unit tests passed");
    return 0;
}

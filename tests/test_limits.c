/* Boundary tests use counters near their limits rather than allocating huge
 * files. A failure must preserve existing pointers and reject subsequent work. */
#include "common.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    InputFile input = {0};
    input.path = "<limits>";
    input.file = tmpfile();
    assert(input.file);
    assert(fwrite("ab", 1, 2, input.file) == 2);
    assert(input_prepare(&input) == STATUS_SUCCESS);
    char byte;
    input.budget->metadata_bytes = PARSER_METADATA_BYTES - 1;
    assert(parser_read(&input, 0, &byte, 1) == STATUS_SUCCESS && byte == 'a');
    assert(parser_read(&input, 1, &byte, 1) == STATUS_ERROR);
    assert(parser_read(&input, 0, &byte, 0) == STATUS_ERROR);
    assert(input_prepare(&input) == STATUS_SUCCESS); /* new analysis resets state */
    input.budget->read_operations = PARSER_READ_OPERATIONS - 1;
    assert(parser_read(&input, 0, &byte, 1) == STATUS_SUCCESS);
    assert(parser_read(&input, 0, &byte, 1) == STATUS_ERROR);
    assert(input_prepare(&input) == STATUS_SUCCESS);
    void *first = NULL, *second = NULL;
    unsigned first_capacity = 0, second_capacity = 0;
    input.budget->table_bytes = PARSER_TABLE_BYTES - 16;
    assert(reserve_array(&input, &first, &first_capacity, 1, 1) == STATUS_SUCCESS);
    assert(input.budget->table_bytes == PARSER_TABLE_BYTES);
    /* A second array shares the same budget; the first remains usable. */
    memset(first, 42, first_capacity);
    assert(reserve_array(&input, &second, &second_capacity, 1, 1) == STATUS_ERROR);
    assert(!second && !second_capacity && ((char *)first)[0] == 42);
    void *unchanged = first;
    assert(reserve_array(&input, &first, &first_capacity, 17, 1) == STATUS_ERROR);
    assert(first == unchanged && first_capacity == 16 && ((char *)first)[0] == 42);
    free(first);
    assert(input_prepare(&input) == STATUS_SUCCESS);
    assert(reserve_array(&input, &second, &second_capacity,
                         PARSER_TABLE_ENTRIES + 1, 1) == STATUS_ERROR);
    assert(!second && !second_capacity);
    input.budget->lookup_steps = PARSER_LOOKUP_STEPS - 1;
    assert(parser_lookup_work(&input, 1) == STATUS_SUCCESS);
    assert(parser_lookup_work(&input, 1) == STATUS_ERROR);
    InputFile other = {0};
    other.path = "<independent>";
    other.file = tmpfile();
    assert(other.file && fwrite("z", 1, 1, other.file) == 1);
    assert(input_prepare(&other) == STATUS_SUCCESS);
    assert(parser_read(&other, 0, &byte, 1) == STATUS_SUCCESS && byte == 'z');
    assert(input.budget->exceeded && other.budget->metadata_bytes == 1);
    assert(fclose(other.file) == 0);
    /* Separate inputs do not inherit the previous input's accounting. */
    assert(input_prepare(&input) == STATUS_SUCCESS);
    assert(parser_read(&input, 0, &byte, 1) == STATUS_SUCCESS);
    assert(reserve_array(&input, &second, &second_capacity,
                         PARSER_TABLE_ENTRIES, 1) == STATUS_SUCCESS);
    assert(second_capacity == PARSER_TABLE_ENTRIES);
    free(second);
    assert(fclose(input.file) == 0);
    puts("Parser resource budget tests passed");
    return 0;
}

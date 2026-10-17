/* Terminal-safe byte escaping must preserve whole escapes and terminators at
 * every output capacity, including zero. These are direct boundary checks. */
#include <assert.h>
#include <string.h>
#include "common.h"

int main(void)
{
    const unsigned char text[] = "a\033\\\377b";
    char output[32];
    escape_display(output, sizeof(output), text, sizeof(text));
    assert(!strcmp(output, "a\\x1B\\x5C\\xFFb"));
    escape_display(output, 5, (const unsigned char *)"abcd", 4);
    assert(!strcmp(output, "abcd")); /* Exact fit must not be shortened. */
    escape_display(output, 5, (const unsigned char *)"abcde", 5);
    assert(!strcmp(output, "a..."));
    for (size_t size = 1; size <= sizeof(output); ++size) {
        memset(output, 'Z', sizeof(output));
        escape_display(output, size, text, sizeof(text));
        assert(memchr(output, 0, size));
        assert(!memchr(output, 27, size));
        if (size < sizeof(output)) assert(output[size] == 'Z');
    }
    escape_display(NULL, 0, text, sizeof(text));
    puts("Display escaping tests passed");
    return 0;
}

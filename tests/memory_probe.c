/* Deliberately leak one allocation to verify the checker can detect leaks.
 * This program is only a test of the testing tool; it is never shipped. */
#include <stdlib.h>
static void *allocation;
int main(void)
{
    allocation = malloc(12345);
    if (!allocation) return 2;
    ((char *)allocation)[0] = 42;
    allocation = NULL;
    return 0;
}

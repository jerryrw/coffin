#include <stdio.h>
#include <stdlib.h>
#include "common.h"
#include "peparser.h"
#include "entropy.h"

int main(int argc, char *argv[])
{
    const char *filepath; // file to analyize

    PEInfo pe_info = {0};

    if (argc > 1)
    {
        filepath = argv[1]; // TODO need some error checking here
    }
    else
    {
        print_usage(argv); // in common.c
        return 1;
    };

    if (parse_pe_file(filepath, &pe_info))
    {
        print_pe_info(&pe_info);
    }
    //-----------------------------Test Entropy Code
    // Test case 1: All same bytes (minimum entropy)
    unsigned char uniform[1000];
    memset(uniform, 'A', sizeof(uniform));
    analyze_entropy(uniform, sizeof(uniform), "uniform data (all 'A's)");

    // Test case 2: Alternating pattern
    unsigned char pattern[1000];
    for (int i = 0; i < 1000; i++)
    {
        pattern[i] = (i % 2) ? 'A' : 'B';
    }
    analyze_entropy(pattern, sizeof(pattern), "alternating pattern");

    // Test case 3: Text data
    const char *text = "Hello, World! This is a sample text for entropy calculation.";
    analyze_entropy((const unsigned char *)text, strlen(text), "sample text");

    // Test case 4: Pseudo-random data
    unsigned char random_data[1000];
    srand(12345); // Fixed seed for reproducible results
    for (int i = 0; i < 1000; i++)
    {
        random_data[i] = rand() % 256;
    }
    analyze_entropy(random_data, sizeof(random_data), "pseudo-random data");

    //-----------------------------End Test Entropy Code
    return 0;
}

// save this snippet for later

// void print_usage (char* argv[]) {
//    printf("Usage: %s -n -f <filepath>\n", argv[0]);
//    printf("\t -n - create new database file\n");
//    printf("\t -f - (required) path to database file\n");
//    return;
//}

// while((c = getopt(argc, argv, "nf:a:l")) != -1) {
//     switch (c) {
//         case 'n':
//             newfile = true;
//             break;
//         case 'f':
//             filepath = optarg;
//             break;
//         case 'a':
//             addstring = optarg;
//             break;
//         case 'l':
//             list = true;
//             break;
//         case '?':
//             printf ("Unknown option -%c\n", c);
//             break;
//         default:
//             printf("Filepath is a required argument\n\n");
//             print_usage(argv);
//             return -1;
//     }
// }
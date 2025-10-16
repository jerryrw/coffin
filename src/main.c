// https://stackoverflow.com/questions/76815878/understanding-sizeofheaders
// https://0xrick.github.io/win-internals/pe4/
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
// https://tech-zealots.com/malware-analysis/pe-portable-executable-structure-malware-analysis-part-2/
// https://tech-zealots.com/malware-analysis/journey-towards-import-address-table-of-an-executable-file/
// https://0xrick.github.io/win-internals/pe8/
// https://tech-zealots.com/malware-analysis/pe-portable-executable-structure-malware-analysis-part-2/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "peparser.h"
#include "entropy.h"

int main(int argc, char *argv[])
{
    const char *filepath; // file to analyize
                          // something
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

    if (parse_pe_file(filepath, &pe_info)) // TODO -handle the error return
    {
        calc_entropy(filepath, &pe_info); // must be called before print_pe_info
        print_pe_info(&pe_info);
    }

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
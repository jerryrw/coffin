#include <stdio.h>
#include "common.h"
#include "sha256.h"
#include "md5.h"
#include "peparser.h"

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
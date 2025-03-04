#include <stdio.h>
#include "common.h"
#include "sha256.h"
#include "md5.h"
#include "peparser.h"

int main(int argc, char *argv[])
{
    const char *filepath;
    uint8_t hash[32];    // for the SHA256
    uint8_t md5hash[16]; // 256 bits = 32 bytes change this to 128 bits 16 bytes for MD5

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

    printf("Hello World Coffin\n");

    if (calculate_file_sha256(filepath, hash) == 0)
    {
        printf("SHA-256 Hash: ");
        for (int i = 0; i < 32; ++i) // change this 32 to 16 for MD5
        {
            printf("%02x", hash[i]);
        }
        printf("\n");
    }

    if (calculate_file_md5(filepath, md5hash) == 0)
    {
        printf("MD5 Hash: ");
        for (int i = 0; i < 16; ++i) // change this to 16 for MD5
        {
            printf("%02x", md5hash[i]);
        }
        printf("\n");
    }

    //     if (parse_pe_file(argv[1], &pe_info)) {
    //         print_pe_info(&pe_info);
    //     }

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
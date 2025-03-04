#include <stdio.h>
#include "common.h"
#include "sha256.h"
#include "md5.h"

int main(int argc, char *argv[])
{
    const char *filepath = "test.txt";
    uint8_t hash[32];
        if (calculate_file_sha256(filepath, hash) == 0)
     {
         printf("SHA-256 Hash: ");
         for (int i = 0; i < 32; ++i) // change this 32 to 16 for MD5
         {
             printf("%02x", hash[i]);
         }
         printf("\n");
     }
    printf("Hello World Coffin\n");

}

// Example usage change hash size to 16 for MD5
// int main()
// {
//     const char *filepath = "example.txt";
//     uint8_t hash[32]; // 256 bits = 32 bytes change this to 128 bits 16 bytes for MD5

//     if (calculate_file_sha256(filepath, hash) == 0)
//     {
//         printf("SHA-256 Hash: ");
//         for (int i = 0; i < 32; ++i) // change this 32 to 16 for MD5
//         {
//             printf("%02x", hash[i]);
//         }
//         printf("\n");
//     }

//     return 0;
// }

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
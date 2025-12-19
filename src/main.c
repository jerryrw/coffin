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
#include "elfparser.h"
#include "machparser.h"

int main(int argc, char *argv[])
{
    const char *filepath;
    PEInfo pe_info = {0};
    ELFInfo elf_info = {0};
    MachOInfo mach_info = {0};

    if (argc > 1)
    {
        filepath = argv[1];
    }
    else
    {
        print_usage(argv);
        return 1;
    }

    // Open file and read magic bytes
    FILE *file = fopen(filepath, "rb");
    if (!file)
    {
        fprintf(stderr, "Cannot open file: %s\n", filepath);
        return 1;
    }

    uint8_t magic[4];
    if (fread(magic, 1, 4, file) != 4)
    {
        fprintf(stderr, "Cannot read file header\n");
        fclose(file);
        return 1;
    }
    fclose(file);

    // Detect file type
    if (magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F')
    {
        // ELF file
        if (parse_elf_file(filepath, &elf_info) == 1)
        {
            print_elf_info(&elf_info);
        }
    }
    else if (magic[0] == 'M' && magic[1] == 'Z')
    {
        // PE file (DOS/Windows executable)
        if (parse_pe_file(filepath, &pe_info) == 1)
        {
            calc_entropy(filepath, &pe_info);
            print_pe_info(&pe_info);
        }
    }
    else if ((magic[0] == 0xCE && magic[1] == 0xFA && magic[2] == 0xED && magic[3] == 0xFE) ||
             (magic[0] == 0xCF && magic[1] == 0xFA && magic[2] == 0xED && magic[3] == 0xFE))
    {
        // Mach-O file (macOS/iOS executable)
        if (parse_mach_file(filepath, &mach_info) == 1)
        {
            print_mach_info(&mach_info);
        }
    }
    else
    {
        fprintf(stderr, "Unknown file type (magic: 0x%02X 0x%02X 0x%02X 0x%02X)\n",
                magic[0], magic[1], magic[2], magic[3]);
        return 1;
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
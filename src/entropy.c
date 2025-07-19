#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include "common.h"
#include "peparser.h"

/**
 * Calculate the Shannon entropy of a memory buffer
 *
 * @param buffer: pointer to the memory buffer
 * @param size: size of the buffer in bytes
 * @return: entropy value in bits (0.0 to 8.0 for byte data)
 */
double calculate_entropy(const unsigned char *buffer, size_t size)
{
    if (buffer == NULL || size == 0)
    {
        return 0.0;
    }

    // Frequency table for all possible byte values (0-255)
    int freq[256] = {0};

    // Count frequency of each byte value
    for (size_t i = 0; i < size; i++)
    {
        freq[buffer[i]]++;
    }

    // Calculate entropy using Shannon's formula: H = -Σ(p * log2(p))
    double entropy = 0.0;
    for (int i = 0; i < 256; i++)
    {
        if (freq[i] > 0)
        {
            double probability = (double)freq[i] / size;
            entropy -= probability * log2(probability);
        }
    }

    return entropy;
}

/**
 * Calculate entropy and provide interpretation
 */
void analyze_entropy(const unsigned char *buffer, size_t size, const char *description)
{
    double entropy = calculate_entropy(buffer, size);

    printf("Entropy analysis for %s:\n", description);
    printf("  Buffer size: %zu bytes\n", size);
    printf("  Entropy: %.4f bits per byte\n", entropy);

    // Interpretation
    if (entropy < 1.0)
    {
        printf("  Analysis: Very low entropy - highly predictable/repetitive data\n");
    }
    else if (entropy < 4.0)
    {
        printf("  Analysis: Low entropy - structured or compressed data\n");
    }
    else if (entropy < 6.0)
    {
        printf("  Analysis: Medium entropy - mixed content\n");
    }
    else if (entropy < 7.5)
    {
        printf("  Analysis: High entropy - compressed or encrypted data\n");
    }
    else
    {
        printf("  Analysis: Very high entropy - likely random or well-encrypted data\n");
    }
    printf("\n");
}

void calc_entropy (const char *filepath, PEInfo *pe_info) { //- TODO -error handling
    FILE *file = fopen(filepath, "rb");           
    for (int i=0; i<pe_info->section_count; i++) {    //loop through the sections
        fseek (file, pe_info->sections[i].PointerToRawData, SEEK_SET);              //seek to the section begin
        
        size_t buffer_size = (size_t)pe_info->sections[i].raw_size;
        unsigned char *buffer = (unsigned char *)malloc(buffer_size);
        fread (buffer, 1, buffer_size, file);
               
        pe_info->sections[i].entropy = calculate_entropy (buffer, buffer_size); //save the entropy
       
        //printf ("Entropy for: %s %f\n", pe_info->sections[i].name, pe_info->sections[i].entropy);
        free (buffer);
       
    }
    fclose(file);                                                                   
}    
/**
     * void calc_entropy (const char *filepath, PEInfo *pe_info)
     * void calc_entropy (filepath, &pe_info)
     * here we need to open the file
     * FILE *file = fopen(filepath, "rb");
     * loop through the number of sections
     * for (i=1; i<pe_info.sectionCount; i++)
     *  seek to the pointertorawdata
     *      fseek(file, pe_info->sections[i].pointertorawdata, SEEK_SET)
     *  create a buffer of rawsize
     *      unsigned char* buffer = malloc (pe_info->sections[i].sizeofrawdata)
     *  read rawsize data from the file
     *      fread (buffer, 1, pe_info->sections[i].sizeofrawdata)
     *  calc the entropy of the buffer and save the entropy in the pe_info struct
     *  needs to be a double
     *      pe_info->sections[i].entropy = calculate_entropy(&buffer, sizeof(buffer))
     *  release buffer
     *      free (buffer)
     *  loop
     */










// Example usage and test cases
/** --moved to main.c
int main()
{
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

    return 0;
}
    */
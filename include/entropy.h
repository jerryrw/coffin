#ifndef ENTROPY_H
#define ENTROPY_H

double calculate_entropy(const unsigned char *buffer, size_t size);
void analyze_entropy(const unsigned char *buffer, size_t size, const char *description);
void calc_entropy (const char *filepath, PEInfo *pe_info);

#endif
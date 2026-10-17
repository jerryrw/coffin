/* Shared display records for dependencies and symbols. Strings are escaped at
 * parse time; values retain raw flags so reports do not guess runtime behavior. */
#ifndef LINKAGE_H
#define LINKAGE_H
#include "common.h"
#define LINKAGE_WORK_LIMIT 100000u

typedef struct {
    char name[1024];
    uint32_t kind, current_version, compatibility_version;
} Dependency;
typedef struct {
    char name[256], indirect[256];
    uint64_t value, size;
    uint32_t section, table;
    uint16_t description;
    uint8_t binding, type, visibility;
    int dynamic;
} BinarySymbol;
#endif

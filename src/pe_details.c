/*
 * Decode PE imports, exports, and the resource directory after the outer headers.
 * An RVA is a relative virtual address: an address measured from the image base.
 * It must be mapped through a section before reading the corresponding file bytes.
 * PEReader carries that mapping, work counters, and resource-tree traversal state.
 * Every offset and count comes from an untrusted file and needs bounds checking.
 */

/* PE directory layouts: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "peparser.h"

/* Work limits are independent of the report limit and bound hostile tables. */
#define PE_WORK_LIMIT 100000u
#define RESOURCE_WORK_LIMIT 4096u
#define RESOURCE_DEPTH 16u
#define STRING_LIMIT 4096u

typedef struct { uint32_t rva, offset, size; } Mapping;
typedef struct {
    const InputFile *input;
    PEInfo *info;
    Mapping *maps;
    unsigned map_count, work, resource_work;
    uint64_t resource_offset;
    uint32_t resource_size;
    uint32_t ancestors[RESOURCE_DEPTH];
    uint32_t type_id, name_id;
    uint64_t decoded_bytes;
} PEReader;

/*
 * qsort calls this comparator through generic void pointers.
 * Cast back to Mapping, then return negative/zero/positive for ordering. Comparing
 * rather than subtracting RVAs avoids unsigned subtraction overflow.
 */
static int compare_mapping(const void *a, const void *b)
{
    uint32_t x = ((const Mapping *)a)->rva, y = ((const Mapping *)b)->rva;
    return (x > y) - (x < y);
}

/* Map only bytes actually present in the file, never zero-filled virtual tails. */
/*
 * Translate an image-relative address into a file offset and remaining bytes.
 * Headers map directly; other RVAs use a sorted, nonoverlapping section map.
 * Output pointers return two values to the caller. The lookup counter also bounds
 * malicious tables whose terminators would otherwise require excessive searching.
 */
static int map_rva(PEReader *r, uint64_t rva, uint64_t length,
                   uint64_t *offset, uint64_t *available)
{
    if (++r->work > PE_WORK_LIMIT || rva > UINT32_MAX || length > UINT64_C(0x100000000) - rva)
        return STATUS_ERROR;
    if (rva < r->info->size_of_headers) {
        *offset = rva;
        *available = r->info->size_of_headers - rva;
    } else {
        /*
         * Binary search finds the last section whose starting RVA is <= the query.
         * This is logarithmic lookup: each comparison discards about half the maps.
         * The subsequent delta check rejects gaps between sections.
         */
        unsigned low = 0, high = r->map_count;
        while (low < high) {
            unsigned mid = low + (high - low) / 2;
            if (r->maps[mid].rva <= rva) low = mid + 1;
            else high = mid;
        }
        if (!low) return STATUS_ERROR;
        Mapping *map = &r->maps[low - 1];
        uint64_t delta = rva - map->rva;
        if (delta >= map->size) return STATUS_ERROR;
        *offset = (uint64_t)map->offset + delta;
        *available = map->size - delta;
    }
    return length <= *available && file_range_valid(*offset, length, r->input->size)
        ? STATUS_SUCCESS : STATUS_ERROR;
}

/*
 * Combine RVA translation and an exact checked read into the caller's buffer.
 * Callers can work in the PE address space without doing unchecked file seeks.
 */
static int rva_read(PEReader *r, uint64_t rva, void *out, size_t size)
{
    uint64_t offset, available;
    if (map_rva(r, rva, size, &offset, &available) != STATUS_SUCCESS) return STATUS_ERROR;
    return read_at(r->input->file, offset, out, size, r->input->size);
}

/* Strings must terminate within mapped bytes and the work limit. Escape control bytes. */
/*
 * Read a zero-terminated byte string within both mapping and work limits.
 * Escape nonprintable bytes and backslashes so file content cannot inject terminal
 * control sequences. Display truncation still requires a real terminator.
 */
static int rva_string(PEReader *r, uint64_t rva, uint64_t bound, char out[256])
{
    unsigned char bytes[STRING_LIMIT];
    uint64_t offset, available;
    if (map_rva(r, rva, 1, &offset, &available) != STATUS_SUCCESS) return STATUS_ERROR;
    if (available > bound) available = bound;
    size_t count = available < sizeof(bytes) ? (size_t)available : sizeof(bytes);
    if (read_at(r->input->file, offset, bytes, count, r->input->size) != STATUS_SUCCESS)
        return STATUS_ERROR;
    unsigned char *end = memchr(bytes, 0, count);
    if (!end) return STATUS_ERROR;
    size_t used = 0;
    for (const unsigned char *p = bytes; p < end; ++p) {
        char escaped[5];
        size_t n = 1;
        escaped[0] = (char)*p;
        if (*p < 32 || *p >= 127 || *p == '\\') {
            snprintf(escaped, sizeof(escaped), "\\x%02X", *p);
            n = 4;
        }
        if (used + n > 252) { memcpy(out + used, "...", 4); return STATUS_SUCCESS; }
        memcpy(out + used, escaped, n); used += n;
    }
    out[used] = 0;
    return STATUS_SUCCESS;
}

/*
 * Older delay-import descriptors store virtual addresses rather than RVAs.
 * Subtract the preferred image base after checking underflow and 32-bit range.
 */
static int delay_rva(PEReader *r, uint64_t address, uint64_t *rva)
{
    if (address < r->info->image_base || address - r->info->image_base > UINT32_MAX) return STATUS_ERROR;
    *rva = address - r->info->image_base;
    return STATUS_SUCCESS;
}

/*
 * Walk a DLL's thunk table until its zero terminator. A thunk is a 32/64-bit
 * lookup entry: its top bit selects an ordinal; otherwise it points to a
 * hint-plus-name record. Append a normalized PEImport for either representation.
 */
static int import_symbols(PEReader *r, uint32_t table, const char *dll, int delayed, int legacy)
{
    unsigned width = r->info->is_64bit ? 8 : 4;
    uint64_t ordinal_bit = r->info->is_64bit ? UINT64_C(1) << 63 : UINT64_C(1) << 31;
    unsigned char thunk[8], hint[2];
    for (uint64_t i = 0;; ++i) {
        if (rva_read(r, (uint64_t)table + i * width, thunk, width) != STATUS_SUCCESS)
            return STATUS_ERROR;
        uint64_t value = width == 8 ? decode64(thunk) : decode32(thunk);
        if (!value) break;
        PEImport entry = {0};
        entry.delay_load = delayed;
        strcpy(entry.dll, dll);
        /*
         * Masks separate an ordinal marker from its 16-bit numeric value.
         * Reject other set bits instead of silently treating malformed data as valid.
         */
        if (value & ordinal_bit) {
            if (value & ~(ordinal_bit | UINT64_C(0xffff))) return STATUS_ERROR;
            entry.by_ordinal = 1; entry.ordinal = (uint16_t)value;
        } else {
            if (legacy && delay_rva(r, value, &value) != STATUS_SUCCESS) return STATUS_ERROR;
            if (value > UINT32_MAX || rva_read(r, value, hint, 2) != STATUS_SUCCESS ||
                rva_string(r, value + 2, UINT64_MAX, entry.name) != STATUS_SUCCESS)
                return STATUS_ERROR;
            entry.hint = decode16(hint);
        }
        if (reserve_array((void **)&r->info->imports, &r->info->import_capacity,
                          r->info->import_count + 1, sizeof(entry)) != STATUS_SUCCESS) return STATUS_ERROR;
        r->info->imports[r->info->import_count++] = entry;
        ++r->info->import_total;
        if (delayed) ++r->info->delay_import_count;
    }
    return STATUS_SUCCESS;
}

/*
 * Read 32-byte delay-load descriptors and convert legacy VA fields to RVAs.
 * A zero descriptor terminates the list. Validate optional tables as well as the
 * name table so a superficially readable descriptor cannot hide invalid ranges.
 */
static int delay_imports(PEReader *r, RVA_Data_Directory directory)
{
    for (uint64_t at = 0; at + 32 <= directory.Size; at += 32) {
        unsigned char bytes[32], empty[32] = {0};
        if (rva_read(r, (uint64_t)directory.VirtualAddress + at, bytes, 32) != STATUS_SUCCESS) return STATUS_ERROR;
        if (!memcmp(bytes, empty, 32)) return STATUS_SUCCESS;
        uint32_t attributes = decode32(bytes);
        if (attributes & ~1u) return STATUS_ERROR;
        uint64_t fields[6];
        for (unsigned j = 0; j < 6; ++j) {
            fields[j] = decode32(bytes + 4 + j * 4);
            if (!(attributes & 1) && fields[j] && delay_rva(r, fields[j], &fields[j]) != STATUS_SUCCESS)
                return STATUS_ERROR;
        }
        char dll[256];
        uint64_t offset, available;
        if (!fields[0] || !fields[2] ||
            rva_string(r, fields[0], UINT64_MAX, dll) != STATUS_SUCCESS ||
            map_rva(r, fields[2], r->info->is_64bit ? 8 : 4, &offset, &available) != STATUS_SUCCESS ||
            (fields[1] && map_rva(r, fields[1], r->info->is_64bit ? 8 : 4, &offset, &available) != STATUS_SUCCESS))
            return STATUS_ERROR;
        for (unsigned j = 4; j < 6; ++j)
            if (fields[j] && map_rva(r, fields[j], r->info->is_64bit ? 8 : 4, &offset, &available) != STATUS_SUCCESS)
                return STATUS_ERROR;
        unsigned before = r->info->import_count;
        if (import_symbols(r, (uint32_t)(fields[3] ? fields[3] : fields[2]), dll, 1, !(attributes & 1)) != STATUS_SUCCESS)
            return STATUS_ERROR;
        uint64_t bytes_needed = ((uint64_t)r->info->import_count - before + 1) * (r->info->is_64bit ? 8 : 4);
        for (unsigned j = 2; j < 6; ++j)
            if (fields[j] && map_rva(r, fields[j], bytes_needed, &offset, &available) != STATUS_SUCCESS)
                return STATUS_ERROR;
    }
    return STATUS_ERROR;
}

/*
 * Read ordinary 20-byte DLL descriptors until an all-zero descriptor.
 * OriginalFirstThunk names the lookup table; when absent, try FirstThunk.
 * The declared directory must include its terminator, not just the live entries.
 */
static int imports(PEReader *r, RVA_Data_Directory directory)
{
    unsigned char descriptor[20];
    for (uint64_t at = 0; at + 20 <= directory.Size; at += 20) {
        if (rva_read(r, (uint64_t)directory.VirtualAddress + at, descriptor, 20) != STATUS_SUCCESS)
            return STATUS_ERROR;
        unsigned char empty[20] = {0};
        if (!memcmp(descriptor, empty, sizeof(empty))) return STATUS_SUCCESS;
        char dll[256];
        uint32_t table = decode32(descriptor);
        if (!table) table = decode32(descriptor + 16); /* OriginalFirstThunk fallback. */
        if (!table || !decode32(descriptor + 12) ||
            rva_string(r, decode32(descriptor + 12), UINT64_MAX, dll) != STATUS_SUCCESS)
            return STATUS_ERROR;
        if (import_symbols(r, table, dll, 0, 0) != STATUS_SUCCESS) return STATUS_ERROR;
    }
    return STATUS_ERROR; /* A directory must include its terminating descriptor. */
}

/*
 * Append one exported name or ordinal, ignoring empty address-table slots.
 * An address inside the export directory identifies a forwarder string such as
 * OTHER.Function rather than code. Several names may refer to the same ordinal.
 */
static int add_export(PEReader *r, RVA_Data_Directory directory, uint32_t base,
                      uint32_t index, uint32_t rva, const char *name)
{
    if (!rva) return STATUS_SUCCESS; /* Empty address-table slot. */
    PEExport entry = {0};
    entry.ordinal = (uint64_t)base + index;
    entry.rva = rva;
    if (name) strcpy(entry.name, name);
    uint64_t end = (uint64_t)directory.VirtualAddress + directory.Size;
    if (rva >= directory.VirtualAddress && rva < end &&
        rva_string(r, rva, end - rva, entry.forwarder) != STATUS_SUCCESS) return STATUS_ERROR;
    if (reserve_array((void **)&r->info->exports, &r->info->export_capacity,
                      r->info->export_count + 1, sizeof(entry)) != STATUS_SUCCESS) return STATUS_ERROR;
    r->info->exports[r->info->export_count++] = entry;
    ++r->info->export_total;
    return STATUS_SUCCESS;
}

/*
 * Combine the export address table, name table, and ordinal-index table.
 * Named entries come first; a temporary byte-per-address bitmap records which
 * slots already have names so a second pass can add ordinal-only exports.
 * The done label releases the bitmap on both success and any intermediate error.
 */
static int exports(PEReader *r, RVA_Data_Directory directory)
{
    unsigned char bytes[40], word[4], ordinal[2];
    if (directory.Size < 40 || rva_read(r, directory.VirtualAddress, bytes, 40) != STATUS_SUCCESS)
        return STATUS_ERROR;
    uint32_t base = decode32(bytes + 16), count = decode32(bytes + 20), names = decode32(bytes + 24);
    uint32_t addresses = decode32(bytes + 28), name_table = decode32(bytes + 32), ordinals = decode32(bytes + 36);
    uint64_t offset, available;
    if (count > PE_WORK_LIMIT || names > PE_WORK_LIMIT ||
        (count && (!addresses || map_rva(r, addresses, (uint64_t)count * 4, &offset, &available) != STATUS_SUCCESS)) ||
        (names && (!name_table || !ordinals ||
          map_rva(r, name_table, (uint64_t)names * 4, &offset, &available) != STATUS_SUCCESS ||
          map_rva(r, ordinals, (uint64_t)names * 2, &offset, &available) != STATUS_SUCCESS)) ||
        (decode32(bytes + 12) && rva_string(r, decode32(bytes + 12), UINT64_MAX, r->info->export_dll) != STATUS_SUCCESS))
        return STATUS_ERROR;
    unsigned char *named = calloc(count ? count : 1, 1);
    if (!named) return STATUS_ERROR;
    int status = STATUS_ERROR;
    for (uint32_t i = 0; i < names; ++i) {
        char name[256];
        if (rva_read(r, (uint64_t)name_table + i * 4ULL, word, 4) != STATUS_SUCCESS ||
            rva_string(r, decode32(word), UINT64_MAX, name) != STATUS_SUCCESS ||
            rva_read(r, (uint64_t)ordinals + i * 2ULL, ordinal, 2) != STATUS_SUCCESS) goto done;
        uint32_t index = decode16(ordinal);
        if (index >= count || rva_read(r, (uint64_t)addresses + index * 4ULL, word, 4) != STATUS_SUCCESS)
            goto done;
        named[index] = 1;
        if (add_export(r, directory, base, index, decode32(word), name) != STATUS_SUCCESS) goto done;
    }
    for (uint32_t i = 0; i < count; ++i) {
        if (named[i]) continue;
        if (rva_read(r, (uint64_t)addresses + i * 4ULL, word, 4) != STATUS_SUCCESS ||
            add_export(r, directory, base, i, decode32(word), NULL) != STATUS_SUCCESS) goto done;
    }
    status = STATUS_SUCCESS;
done:
    free(named);
    return status;
}

/*
 * Read bytes relative to the resource directory's start, not an image RVA.
 * The separate counter bounds tree traversal even when every small read is valid.
 */
static int resource_read(PEReader *r, uint64_t relative, void *out, size_t size)
{
    if (++r->resource_work > RESOURCE_WORK_LIMIT ||
        !file_range_valid(relative, size, r->resource_size)) return STATUS_ERROR;
    return read_at(r->input->file, r->resource_offset + relative, out, size, r->input->size);
}

/*
 * Translate common numeric Windows resource IDs into readable labels.
 * NULL means the ID is not one of our known names, so callers print the number.
 */
static const char *resource_type(uint32_t id)
{
    switch (id) {
    case 1: return "CURSOR"; case 2: return "BITMAP"; case 3: return "ICON";
    case 4: return "MENU"; case 5: return "DIALOG"; case 6: return "STRING";
    case 9: return "ACCELERATOR"; case 10: return "RCDATA";
    case 11: return "MESSAGETABLE"; case 23: return "HTML";
    case 12: return "GROUP_CURSOR"; case 14: return "GROUP_ICON";
    case 16: return "VERSION"; case 24: return "MANIFEST";
    default: return NULL;
    }
}

/*
 * A resource entry's high bit distinguishes a string-name offset from an ID.
 * Decode UTF-16 surrogate pairs into Unicode code points, then UTF-8 display bytes.
 * Escape separators/control characters so one label cannot look like a new path.
 * Even after display truncation, validate the entire declared UTF-16 name.
 */
static int resource_label(PEReader *r, uint32_t value, unsigned depth, char out[256])
{
    if (!(value & 0x80000000)) {
        const char *type = depth == 0 ? resource_type(value) : NULL;
        if (type) snprintf(out, 256, "%s(#%u)", type, value);
        else snprintf(out, 256, "#%u", value);
        return STATUS_SUCCESS;
    }
    uint32_t relative = value & 0x7fffffff;
    unsigned char bytes[STRING_LIMIT * 2], length[2];
    if (resource_read(r, relative, length, 2) != STATUS_SUCCESS) return STATUS_ERROR;
    uint16_t count = decode16(length);
    if (count > STRING_LIMIT || resource_read(r, (uint64_t)relative + 2, bytes, (size_t)count * 2) != STATUS_SUCCESS)
        return STATUS_ERROR;
    size_t used = 0;
    int truncated = 0;
    for (unsigned i = 0; i < count; ++i) {
        uint32_t cp = decode16(bytes + i * 2);
        if (cp >= 0xd800 && cp <= 0xdbff) {
            if (++i >= count) return STATUS_ERROR;
            uint32_t low = decode16(bytes + i * 2);
            if (low < 0xdc00 || low > 0xdfff) return STATUS_ERROR;
            cp = 0x10000 + ((cp - 0xd800) << 10) + low - 0xdc00;
        } else if (cp >= 0xdc00 && cp <= 0xdfff) return STATUS_ERROR;
        char utf8[8]; size_t n;
        if (cp < 32 || (cp >= 127 && cp <= 159) || cp == 0x061c || cp == 0x200e || cp == 0x200f || cp == 0x2028 || cp == 0x2029 ||
            (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069) || cp == '/' || cp == '\\') {
            snprintf(utf8, sizeof(utf8), "\\u%04X", cp); n = 6;
        } else if (cp < 0x80) { utf8[0] = (char)cp; n = 1; }
        else if (cp < 0x800) {
            utf8[0] = (char)(0xc0 | (cp >> 6)); utf8[1] = (char)(0x80 | (cp & 63)); n = 2;
        } else if (cp < 0x10000) {
            utf8[0] = (char)(0xe0 | (cp >> 12)); utf8[1] = (char)(0x80 | ((cp >> 6) & 63));
            utf8[2] = (char)(0x80 | (cp & 63)); n = 3;
        } else {
            utf8[0] = (char)(0xf0 | (cp >> 18)); utf8[1] = (char)(0x80 | ((cp >> 12) & 63));
            utf8[2] = (char)(0x80 | ((cp >> 6) & 63)); utf8[3] = (char)(0x80 | (cp & 63)); n = 4;
        }
        if (!truncated && used + n <= 252) { memcpy(out + used, utf8, n); used += n; }
        else truncated = 1;
    }
    if (truncated) { memcpy(out + used, "...", 3); used += 3; }
    out[used] = 0;
    return STATUS_SUCCESS;
}

/*
 * Walk resource directories recursively, building type/name/language paths.
 * ancestors records offsets on the current path to detect cycles. Depth and work
 * limits prevent a crafted tree from exhausting the call stack or CPU time.
 * A leaf contains a payload RVA, size, and code page; store its metadata and preview.
 */
static int resource_tree(PEReader *r, uint32_t relative, unsigned depth, const char *path)
{
    unsigned char header[16], entry[8], data[16];
    if (depth >= RESOURCE_DEPTH) return STATUS_ERROR;
    for (unsigned i = 0; i < depth; ++i)
        if (r->ancestors[i] == relative) return STATUS_ERROR;
    /*
     * Only ancestors matter for cycle detection: two different branches may
     * legitimately refer to the same subtree without forming a cycle.
     */
    r->ancestors[depth] = relative;
    if (resource_read(r, relative, header, 16) != STATUS_SUCCESS) return STATUS_ERROR;
    uint32_t count = (uint32_t)decode16(header + 12) + decode16(header + 14);
    if (!file_range_valid((uint64_t)relative + 16, (uint64_t)count * 8, r->resource_size))
        return STATUS_ERROR;
    for (uint32_t i = 0; i < count; ++i) {
        char label[256], next[768];
        if (resource_read(r, (uint64_t)relative + 16 + i * 8ULL, entry, 8) != STATUS_SUCCESS ||
            resource_label(r, decode32(entry), depth, label) != STATUS_SUCCESS) return STATUS_ERROR;
        int n = snprintf(next, sizeof(next), "%s%s%s", path, depth ? "/" : "", label);
        if (n < 0 || (size_t)n >= sizeof(next)) return STATUS_ERROR;
        if (depth == 0) { r->type_id = decode32(entry) & 0x80000000 ? 0 : decode32(entry); r->name_id = 0; }
        if (depth == 1) r->name_id = decode32(entry) & 0x80000000 ? 0 : decode32(entry);
        /*
         * The target's high bit means "another directory"; a clear bit means
         * "resource data entry." Masking removes the tag before using its offset.
         */
        uint32_t target = decode32(entry + 4);
        if (target & 0x80000000) {
            if (resource_tree(r, target & 0x7fffffff, depth + 1, next) != STATUS_SUCCESS)
                return STATUS_ERROR;
        } else {
            PEResource resource = {0};
            if (resource_read(r, target, data, 16) != STATUS_SUCCESS) return STATUS_ERROR;
            resource.rva = decode32(data); resource.size = decode32(data + 4);
            resource.codepage = decode32(data + 8);
            uint64_t available;
            if (resource.size && map_rva(r, resource.rva, resource.size, &resource.file_offset, &available) != STATUS_SUCCESS)
                return STATUS_ERROR;
            strcpy(resource.path, next);
            resource.type_id = r->type_id; resource.name_id = r->name_id;
            resource.language_id = depth == 2 && !(decode32(entry) & 0x80000000) ? decode32(entry) : 0;
            if (r->decoded_bytes + resource.size <= 16u * 1024u * 1024u) {
                r->decoded_bytes += resource.size;
                if (decode_resource_payload(r->input, &resource) != STATUS_SUCCESS) return STATUS_ERROR;
            } else snprintf(resource.decoded, sizeof(resource.decoded), "Preview skipped: aggregate 16 MiB decode budget; raw extraction available");
            if (reserve_array((void **)&r->info->resources, &r->info->resource_capacity,
                              r->info->resource_count + 1, sizeof(resource)) != STATUS_SUCCESS) return STATUS_ERROR;
            r->info->resources[r->info->resource_count++] = resource;
            ++r->info->resource_total;
        }
    }
    return STATUS_SUCCESS;
}

/*
 * Build a sorted RVA-to-file map from every section that has raw bytes.
 * Reject overlaps with headers or earlier maps, because an RVA must identify one
 * unambiguous file range. The caller frees maps even if preparation fails midway.
 */
static int prepare_reader(PEReader *r, const InputFile *input, PEInfo *info)
{
    r->input = input; r->info = info;
    r->maps = calloc(info->number_of_sections ? info->number_of_sections : 1, sizeof(*r->maps));
    if (!r->maps) return STATUS_ERROR;
    if (info->size_of_headers > input->size) return STATUS_ERROR;
    for (unsigned i = 0; i < info->number_of_sections; ++i) {
        unsigned char section[40];
        if (read_at(input->file, info->section_table_offset + (uint64_t)i * 40,
                    section, 40, input->size) != STATUS_SUCCESS) return STATUS_ERROR;
        Mapping map = { decode32(section + 12), decode32(section + 20), decode32(section + 16) };
        if (map.size) r->maps[r->map_count++] = map;
    }
    qsort(r->maps, r->map_count, sizeof(*r->maps), compare_mapping);
    uint64_t previous_end = info->size_of_headers;
    for (unsigned i = 0; i < r->map_count; ++i) {
        if (r->maps[i].rva < previous_end ||
            (uint64_t)r->maps[i].rva + r->maps[i].size > UINT64_C(0x100000000)) return STATUS_ERROR;
        previous_end = (uint64_t)r->maps[i].rva + r->maps[i].size;
    }
    return STATUS_SUCCESS;
}

/*
 * Return a separately allocated copy of all parsed resource records.
 * The output parameter is a pointer-to-pointer because this function creates the
 * array. The caller owns the copy and must free it; info keeps its original array.
 */
int collect_pe_resources(const InputFile *input, const PEInfo *info, PEResource **resources)
{
    (void)input;
    *resources = NULL;
    if (!info->resource_count) return STATUS_SUCCESS;
    *resources = malloc((size_t)info->resource_count * sizeof(**resources));
    if (!*resources) return STATUS_ERROR;
    memcpy(*resources, info->resources, (size_t)info->resource_count * sizeof(**resources));
    return STATUS_SUCCESS;
}

/*
 * Dispatch the implemented data-directory entries: export=0, import=1,
 * resource=2, delay import=13. Absent directories require no mapping work.
 * The local reader owns only its mapping array; PEInfo owns collected results.
 */
int parse_pe_details(const InputFile *input, PEInfo *info)
{
    int present = 0;
    for (unsigned i = 0; i < 16; ++i)
        if (i < 3 || i == 13) present |= info->directories[i].VirtualAddress != 0 || info->directories[i].Size != 0;
    if (!present) return STATUS_SUCCESS;
    PEReader r = {0}; r.input = input; r.info = info;
    int status = STATUS_ERROR;
    if (prepare_reader(&r, input, info) != STATUS_SUCCESS) goto done;
    for (unsigned i = 0; i < 16; ++i) {
        if (i >= 3 && i != 13) continue;
        RVA_Data_Directory dir = info->directories[i];
        if (!dir.VirtualAddress && !dir.Size) continue;
        uint64_t offset, available;
        if (!dir.VirtualAddress || !dir.Size ||
            map_rva(&r, dir.VirtualAddress, dir.Size, &offset, &available) != STATUS_SUCCESS) goto done;
        if (i == 0 && exports(&r, dir) != STATUS_SUCCESS) goto done;
        if (i == 1 && imports(&r, dir) != STATUS_SUCCESS) goto done;
        if (i == 13 && delay_imports(&r, dir) != STATUS_SUCCESS) goto done;
        if (i == 2) {
            r.resource_offset = offset; r.resource_size = dir.Size;
            if (resource_tree(&r, 0, 0, "") != STATUS_SUCCESS) goto done;
        }
    }
    status = STATUS_SUCCESS;
done:
    free(r.maps);
    if (status != STATUS_SUCCESS)
        fprintf(stderr, "Invalid PE imports, exports, or resources (or directory work limit exceeded)\n");
    return status;
}

/*
 * Print expanded import/export/resource lists from stored metadata.
 * The previews switch affects displayed resource text, not resource bytes or
 * extraction. This function does not reopen or parse the input file.
 */
void print_pe_details(const PEInfo *info, int previews)
{
    printf("\nImports: %u symbols\n", info->import_total - info->delay_import_count);
    for (unsigned i = 0; i < info->import_count; ++i) {
        const PEImport *entry = &info->imports[i];
        if (entry->delay_load) continue;
        if (entry->by_ordinal) printf("  %s!#%u (ordinal)\n", entry->dll, entry->ordinal);
        else printf("  %s!%s (hint %u)\n", entry->dll, entry->name, entry->hint);
    }
    printf("\nDelay-load Imports: %u symbols\n", info->delay_import_count);
    for (unsigned i = 0; i < info->import_count; ++i) {
        const PEImport *entry = &info->imports[i];
        if (!entry->delay_load) continue;
        if (entry->by_ordinal) printf("  %s!#%u (ordinal, delay-load)\n", entry->dll, entry->ordinal);
        else printf("  %s!%s (hint %u, delay-load)\n", entry->dll, entry->name, entry->hint);
    }
    printf("\nExports: %u entries", info->export_total);
    if (info->export_dll[0]) printf(" (%s)", info->export_dll);
    printf("\n");
    for (unsigned i = 0; i < info->export_count; ++i) {
        const PEExport *entry = &info->exports[i];
        printf("  Ordinal %llu: %s, RVA 0x%08X", (unsigned long long)entry->ordinal,
               entry->name[0] ? entry->name : "<ordinal-only>", entry->rva);
        if (entry->forwarder[0]) printf(" -> %s", entry->forwarder);
        printf("\n");
    }
    printf("\nResources: %u entries\n", info->resource_total);
    for (unsigned i = 0; i < info->resource_count; ++i) {
        const PEResource *entry = &info->resources[i];
        printf("  %s: RVA 0x%08X, size %u, code page %u",
               entry->path, entry->rva, entry->size, entry->codepage);
        if (entry->size) printf(", file offset 0x%llX", (unsigned long long)entry->file_offset);
        printf("\n");
        if (previews && entry->decoded[0]) printf("    %s\n", entry->decoded);
    }
}

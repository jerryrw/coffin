/*
 * Reconstruct ICO/CUR files from PE icon/cursor resources without decoding pixels.
 * Resource payloads contain image bytes, but standalone files also need a header
 * and a directory of images. Group resources refer to image IDs, not file offsets.
 * We resolve those references, calculate output offsets, then copy image bytes.
 * The returned heap buffer belongs to the caller, which must free() it.
 */

#include <stdlib.h>
#include <string.h>
#include "peparser.h"

#define IMAGE_LIMIT (16u * 1024u * 1024u)
/*
 * Write an integer as two little-endian bytes into an already sized output.
 * This avoids depending on host byte order or alignment when constructing files.
 */
static void put16(unsigned char *p, uint16_t value) { p[0] = (unsigned char)value; p[1] = (unsigned char)(value >> 8); }
/*
 * Write a little-endian 32-bit field using two 16-bit halves.
 * The ICO/CUR directory format uses these for image lengths and file offsets.
 */
static void put32(unsigned char *p, uint32_t value) { put16(p, (uint16_t)value); put16(p + 2, (uint16_t)(value >> 16)); }
typedef struct { const PEResource *resource; unsigned skip; unsigned char entry[16]; } ImagePart;

/*
 * Resolve a group image ID, preferring the same language, then neutral,
 * then the sole matching image. Return NULL for a missing or ambiguous match:
 * guessing could reconstruct an unrelated language's image.
 */
static const PEResource *find_image(const PEInfo *info, uint32_t type, uint32_t id, uint32_t language)
{
    const PEResource *exact = NULL, *neutral = NULL, *only = NULL;
    unsigned matches = 0, exact_count = 0, neutral_count = 0;
    for (unsigned i = 0; i < info->resource_count; ++i) {
        const PEResource *r = &info->resources[i];
        if (r->type_id != type || r->name_id != id) continue;
        only = r; ++matches;
        if (r->language_id == language) { exact = r; ++exact_count; }
        if (!r->language_id) { neutral = r; ++neutral_count; }
    }
    if (exact_count) return exact_count == 1 ? exact : NULL;
    if (neutral_count) return neutral_count == 1 ? neutral : NULL;
    return matches == 1 ? only : NULL;
}

/*
 * Inspect a resource image header and prepare one 16-byte ICO/CUR directory row.
 * PNG uses direct dimensions; icon/cursor DIBs store doubled heights for masks.
 * For cursors, move the resource's hotspot prefix into the directory row and omit
 * it from copied image data. For icons, store plane count and bits per pixel.
 */
static int image_entry(const InputFile *input, ImagePart *part, int cursor)
{
    const PEResource *r = part->resource;
    unsigned char head[44] = {0};
    part->skip = cursor ? 4 : 0;
    if (r->size <= part->skip || r->size > IMAGE_LIMIT) return STATUS_ERROR;
    size_t length = r->size < sizeof(head) ? r->size : sizeof(head);
    if (read_at(input->file, r->file_offset, head, length, input->size) != STATUS_SUCCESS) return STATUS_ERROR;
    const unsigned char *p = head + part->skip;
    size_t size = length - part->skip;
    uint32_t width, height;
    uint16_t planes = 1, bits = 32;
    if (size >= 24 && !memcmp(p, "\x89PNG\r\n\x1a\n", 8) && !memcmp(p + 12, "IHDR", 4)) {
        width = read32_order(p + 16, 1); height = read32_order(p + 20, 1);
    } else if (size >= 12 && decode32(p) == 12) {
        width = decode16(p + 4); height = decode16(p + 6) / 2;
        planes = decode16(p + 8); bits = decode16(p + 10);
        if (decode16(p + 6) % 2) return STATUS_ERROR;
    } else if (size >= 40 && decode32(p) >= 40 && decode32(p) <= r->size - part->skip) {
        width = decode32(p + 4); height = decode32(p + 8) / 2;
        planes = decode16(p + 12); bits = decode16(p + 14);
        if (decode32(p + 8) % 2) return STATUS_ERROR;
    } else return STATUS_ERROR;
    if (!width || width > 256 || !height || height > 256) return STATUS_ERROR;
    /*
     * ICO/CUR dimension bytes use zero to represent 256, so converting the
     * validated value 256 to unsigned char deliberately produces zero.
     */
    part->entry[0] = (unsigned char)width; part->entry[1] = (unsigned char)height;
    if (cursor) {
        uint16_t x = decode16(head), y = decode16(head + 2);
        if (x >= width || y >= height) return STATUS_ERROR;
        put16(part->entry + 4, x); put16(part->entry + 6, y);
    } else {
        part->entry[2] = bits < 8 ? (unsigned char)(1u << bits) : 0;
        put16(part->entry + 4, planes); put16(part->entry + 6, bits);
    }
    put32(part->entry + 8, r->size - part->skip);
    return STATUS_SUCCESS;
}

/* Produces single-image files for RT_ICON/RT_CURSOR and multi-image files for groups. */
/*
 * Build a complete single-image file or resolve all images in a group.
 * First calculate directory rows and the total size, checking the image budget.
 * Only then allocate output and copy payloads. On success *data becomes the
 * caller's heap allocation; on failure outputs remain NULL/zero.
 */
int reconstruct_resource_image(const InputFile *input, const PEInfo *info, unsigned index,
                               unsigned char **data, size_t *size)
{
    *data = NULL; *size = 0;
    if (index >= info->resource_count) return STATUS_ERROR;
    const PEResource *r = &info->resources[index];
    int group = r->type_id == 12 || r->type_id == 14;
    int cursor = r->type_id == 1 || r->type_id == 12;
    if (!group && r->type_id != 1 && r->type_id != 3) return STATUS_ERROR;
    unsigned char *directory = NULL;
    unsigned count = 1;
    if (group) {
        if (r->size < 6 || r->size > 1024u * 1024u) return STATUS_ERROR;
        directory = malloc(r->size);
        if (!directory) return STATUS_ERROR;
        if (read_at(input->file, r->file_offset, directory, r->size, input->size) != STATUS_SUCCESS ||
            decode16(directory) || decode16(directory + 2) != (cursor ? 2 : 1)) goto invalid_directory;
        count = decode16(directory + 4);
        if (!count || count > 1024 || !file_range_valid(6, (uint64_t)count * 14, r->size)) goto invalid_directory;
    }
    ImagePart *parts = calloc(count, sizeof(*parts));
    if (!parts) goto invalid_directory;
    /*
     * A standalone file has a 6-byte header and 16-byte entries. A Windows
     * group resource instead has 14-byte entries ending in resource IDs.
     * Reconstruction replaces those IDs with byte offsets in the new file.
     */
    size_t total = 6 + (size_t)count * 16;
    for (unsigned i = 0; i < count; ++i) {
        parts[i].resource = group ? find_image(info, cursor ? 1 : 3, decode16(directory + 6 + i * 14 + 12), r->language_id) : r;
        if (!parts[i].resource || image_entry(input, &parts[i], cursor) != STATUS_SUCCESS) goto invalid_parts;
        if (group && decode32(directory + 6 + i * 14 + 8) != parts[i].resource->size) goto invalid_parts;
        uint32_t bytes = parts[i].resource->size - parts[i].skip;
        if (bytes > IMAGE_LIMIT - total) goto invalid_parts;
        put32(parts[i].entry + 12, (uint32_t)total);
        total += bytes;
    }
    unsigned char *output = calloc(total, 1);
    if (!output) goto invalid_parts;
    put16(output + 2, cursor ? 2 : 1); put16(output + 4, (uint16_t)count);
    for (unsigned i = 0; i < count; ++i) {
        memcpy(output + 6 + i * 16, parts[i].entry, 16);
        size_t offset = decode32(parts[i].entry + 12), bytes = decode32(parts[i].entry + 8);
        if (read_at(input->file, parts[i].resource->file_offset + parts[i].skip,
                    output + offset, bytes, input->size) != STATUS_SUCCESS) { free(output); goto invalid_parts; }
    }
    *data = output; *size = total;
    free(parts); free(directory);
    return STATUS_SUCCESS;
/*
 * Cleanup labels correspond to progressively acquired resources. Falling
 * through from invalid_parts also frees directory. No pointer is returned
 * until the whole file is built, so the caller never owns a partial buffer.
 */
invalid_parts:
    free(parts);
invalid_directory:
    free(directory);
    return STATUS_ERROR;
}

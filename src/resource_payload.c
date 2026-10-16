/*
 * Turn selected Windows resource bytes into short, terminal-safe text previews.
 * The PE resource tree tells us the payload's type and location; this file decodes
 * its contents. Malformed payloads get a descriptive preview rather than being
 * executed. Read/allocation failures are fatal, but unsupported encodings can
 * still be extracted unchanged. Output and parsing both have explicit limits.
 */

/* Bounded previews of common Windows resource payloads; extraction preserves raw bytes. */
#include <stdarg.h>
#include <errno.h>
#include <iconv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "peparser.h"

#define PAYLOAD_LIMIT (1024u * 1024u)
typedef struct { char *text; size_t size, used; int truncated; } Preview;

/*
 * Append printf-style text into a fixed-size preview, preserving its terminator.
 * The ... argument list is accessed with va_list/va_start/va_end; vsnprintf
 * reports the length it wanted to write. Reserve room for "..." and '\0'.
 * Once truncated, later calls stop writing, but payload validation continues.
 */
static void append(Preview *p, const char *format, ...)
{
    if (p->truncated) return;
    va_list args;
    va_start(args, format);
    int n = vsnprintf(p->text + p->used, p->size - p->used, format, args);
    va_end(args);
    if (n < 0) return;
    if ((size_t)n > p->size - p->used - 4) {
        memcpy(p->text + p->used, "...", 4);
        p->truncated = 1;
    } else p->used += (size_t)n;
}

/*
 * Append one Unicode code point as UTF-8, escaping control and direction marks.
 * A code point is a character number; UTF-8 represents that number using 1-4 bytes.
 * Escaping makes potentially misleading text visible instead of controlling the
 * terminal or changing the visual order of neighboring report text.
 */
static void character(Preview *p, uint32_t cp)
{
    if (cp < 32 || (cp >= 127 && cp <= 159) || cp == '\\' || cp == 0x2028 || cp == 0x2029 ||
        (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069)) {
        append(p, "\\u%04X", cp); return;
    }
    char bytes[5] = {0};
    if (cp < 128) bytes[0] = (char)cp;
    else if (cp < 0x800) {
        bytes[0] = (char)(0xc0 | cp >> 6); bytes[1] = (char)(0x80 | (cp & 63));
    } else if (cp < 0x10000) {
        bytes[0] = (char)(0xe0 | cp >> 12); bytes[1] = (char)(0x80 | ((cp >> 6) & 63));
        bytes[2] = (char)(0x80 | (cp & 63));
    } else {
        bytes[0] = (char)(0xf0 | cp >> 18); bytes[1] = (char)(0x80 | ((cp >> 12) & 63));
        bytes[2] = (char)(0x80 | ((cp >> 6) & 63)); bytes[3] = (char)(0x80 | (cp & 63));
    }
    append(p, "%s", bytes);
}

/*
 * Decode one two-byte UTF-16 code unit in the requested byte order.
 * A unit may represent a character or half of a supplementary character.
 */
static uint16_t unit(const unsigned char *data, int big)
{
    return big ? (uint16_t)((uint16_t)data[0] << 8 | data[1]) : decode16(data);
}

/*
 * Decode an even-length sequence of UTF-16 units into safe preview text.
 * A high surrogate must be followed by a low surrogate; combining the pair
 * produces one code point above U+FFFF. Reject isolated halves or incomplete pairs.
 */
static int utf16(Preview *p, const unsigned char *data, size_t size, int big)
{
    if (size % 2) return STATUS_ERROR;
    for (size_t i = 0; i < size; i += 2) {
        uint32_t cp = unit(data + i, big);
        if (cp >= 0xd800 && cp <= 0xdbff) {
            if (i + 4 > size) return STATUS_ERROR;
            uint32_t low = unit(data + i + 2, big);
            if (low < 0xdc00 || low > 0xdfff) return STATUS_ERROR;
            cp = 0x10000 + ((cp - 0xd800) << 10) + low - 0xdc00; i += 2;
        } else if (cp >= 0xdc00 && cp <= 0xdfff) return STATUS_ERROR;
        character(p, cp);
    }
    return STATUS_SUCCESS;
}

/*
 * Preserve bytes when no reliable character conversion is available.
 * ASCII bytes pass through the same control-character escaping as decoded text;
 * bytes >= 128 appear as hex escapes instead of guessed characters.
 */
static void escaped_bytes(Preview *p, const unsigned char *bytes, size_t size)
{
    for (size_t i = 0; i < size; ++i)
        if (bytes[i] >= 128) append(p, "\\x%02X", bytes[i]); else character(p, bytes[i]);
}

/* Resource metadata selects the code page; the host locale is never used. */
/*
 * Convert a declared Windows code page with iconv, then escape each code point.
 * UTF-32LE output makes each converted character a four-byte integer for character().
 * iconv advances input/output pointers and updates their remaining-byte counts.
 * E2BIG means "output buffer full": consume produced text and continue. Other
 * conversion errors retain the unconverted suffix as escaped bytes.
 */
static int legacy_text(Preview *p, const unsigned char *bytes, size_t size, uint32_t codepage)
{
    char encoding[32];
    const char *name = encoding;
    switch (codepage) {
    case 0: append(p, "[code page unspecified; escaped bytes] "); escaped_bytes(p, bytes, size); return STATUS_SUCCESS;
    case 65001: name = "UTF-8"; break;
    case 1200: name = "UTF-16LE"; break;
    case 1201: name = "UTF-16BE"; break;
    case 20127: name = "ASCII"; break;
    case 932: name = "CP932"; break;
    case 936: name = "GBK"; break;
    case 949: name = "CP949"; break;
    case 950: name = "BIG5"; break;
    case 54936: name = "GB18030"; break;
    default:
        if ((codepage >= 1250 && codepage <= 1258) || codepage == 437 || codepage == 850 || codepage == 866 || codepage == 874)
            snprintf(encoding, sizeof(encoding), "CP%u", codepage);
        else if (codepage >= 28591 && codepage <= 28606)
            snprintf(encoding, sizeof(encoding), "ISO-8859-%u", codepage - 28590);
        else { append(p, "[unsupported code page %u; escaped bytes] ", codepage); escaped_bytes(p, bytes, size); return STATUS_SUCCESS; }
    }
    iconv_t converter = iconv_open("UTF-32LE", name);
    if (converter == (iconv_t)-1) {
        append(p, "[code page %u unavailable; escaped bytes] ", codepage);
        escaped_bytes(p, bytes, size); return STATUS_SUCCESS;
    }
    char *cursor = (char *)bytes;
    size_t remaining = size;
    while (remaining) {
        unsigned char output[1024];
        char *out = (char *)output;
        size_t available = sizeof(output);
        errno = 0;
        size_t result = iconv(converter, &cursor, &remaining, &out, &available);
        int conversion_error = errno;
        size_t produced = sizeof(output) - available;
        for (size_t i = 0; i + 4 <= produced; i += 4) character(p, decode32(output + i));
        if (result == (size_t)-1 && conversion_error != E2BIG) {
            append(p, "[invalid code page %u sequence; escaped bytes] ", codepage);
            escaped_bytes(p, (const unsigned char *)cursor, remaining); break;
        }
    }
    iconv_close(converter);
    return STATUS_SUCCESS;
}

/*
 * Parse one nested version-info block inside its parent byte boundary.
 * Each block carries a total length, a value length, a type, and a UTF-16 key.
 * Value length counts UTF-16 units for text but bytes for binary values. Children
 * start on four-byte boundaries. Both depth and block count bound recursion.
 */
static int version_block(Preview *p, const unsigned char *bytes, size_t start, size_t limit,
                         unsigned depth, unsigned *work)
{
    if (depth > 8 || ++*work > 1024 || !file_range_valid(start, 6, limit)) return STATUS_ERROR;
    size_t length = decode16(bytes + start), value_length = decode16(bytes + start + 2);
    unsigned type = decode16(bytes + start + 4);
    if (length < 6 || !file_range_valid(start, length, limit) || type > 1) return STATUS_ERROR;
    /*
     * The range was validated before computing end. The expression
     * (pos + 3) & ~3 below rounds upward to a multiple of four: adding three
     * reaches the next boundary, and clearing two low bits supplies alignment.
     */
    size_t end = start + length, key = start + 6, pos = key;
    while (file_range_valid(pos, 2, end) && decode16(bytes + pos)) pos += 2;
    if (!file_range_valid(pos, 2, end)) return STATUS_ERROR;
    size_t key_size = pos - key;
    pos = (pos + 2 + 3) & ~(size_t)3;
    size_t value_bytes = value_length * (type ? 2 : 1);
    if (value_bytes && !file_range_valid(pos, value_bytes, end)) return STATUS_ERROR;
    if (depth == 0) {
        static const unsigned char root[] = {'V',0,'S',0,'_',0,'V',0,'E',0,'R',0,'S',0,'I',0,'O',0,'N',0,'_',0,'I',0,'N',0,'F',0,'O',0};
        if (key_size != sizeof(root) || memcmp(bytes + key, root, sizeof(root))) return STATUS_ERROR;
        if (value_bytes) {
            if (type || value_bytes < 52 || decode32(bytes + pos) != 0xfeef04bd) return STATUS_ERROR;
            uint32_t fm = decode32(bytes + pos + 8), fl = decode32(bytes + pos + 12);
            uint32_t pm = decode32(bytes + pos + 16), pl = decode32(bytes + pos + 20);
            append(p, "File version: %u.%u.%u.%u; Product version: %u.%u.%u.%u; ",
                   fm >> 16, fm & 65535, fl >> 16, fl & 65535,
                   pm >> 16, pm & 65535, pl >> 16, pl & 65535);
        }
    } else if (type && value_bytes) {
        if (utf16(p, bytes + key, key_size, 0) != STATUS_SUCCESS) return STATUS_ERROR;
        append(p, "=");
        size_t text_bytes = value_bytes;
        if (text_bytes >= 2 && !decode16(bytes + pos + text_bytes - 2)) text_bytes -= 2;
        if (utf16(p, bytes + pos, text_bytes, 0) != STATUS_SUCCESS) return STATUS_ERROR;
        append(p, "; ");
    }
    size_t child = (pos + value_bytes + 3) & ~(size_t)3;
    while (child < end) {
        if (end - child < 6) {
            for (size_t i = child; i < end; ++i) if (bytes[i]) return STATUS_ERROR;
            break;
        }
        size_t child_length = decode16(bytes + child);
        if (!child_length || version_block(p, bytes, child, end, depth + 1, work) != STATUS_SUCCESS)
            return STATUS_ERROR;
        child = (child + child_length + 3) & ~(size_t)3;
    }
    return STATUS_SUCCESS;
}

/*
 * Read a zero-terminated UTF-16 string at *pos, then advance the caller's cursor.
 * A size_t * lets the helper return a new position as well as a status code.
 * The preview excludes the terminator, while the cursor advances past it.
 */
static int wide_z(Preview *p, const unsigned char *bytes, size_t size, size_t *pos)
{
    size_t start = *pos;
    while (file_range_valid(*pos, 2, size) && decode16(bytes + *pos)) *pos += 2;
    if (!file_range_valid(*pos, 2, size)) return STATUS_ERROR;
    size_t length = *pos - start; *pos += 2;
    return utf16(p, bytes + start, length, 0);
}

/*
 * A dialog menu/class/title field is either a UTF-16 string or 0xFFFF + ordinal.
 * An ordinal is a numeric resource identifier, displayed here with a # prefix.
 * wide_z also handles an empty field because its first unit is already zero.
 */
static int dialog_field(Preview *p, const unsigned char *bytes, size_t size, size_t *pos)
{
    if (!file_range_valid(*pos, 2, size)) return STATUS_ERROR;
    if (decode16(bytes + *pos) == 0xffff) {
        if (!file_range_valid(*pos, 4, size)) return STATUS_ERROR;
        append(p, "#%u", decode16(bytes + *pos + 2)); *pos += 4; return STATUS_SUCCESS;
    }
    return wide_z(p, bytes, size, pos);
}

/*
 * Decode a control's string class or standard numeric class ID.
 * IDs 0x80-0x85 identify common controls such as buttons and edit boxes;
 * unknown IDs are retained numerically rather than treated as strings.
 */
static int control_class(Preview *p, const unsigned char *bytes, size_t size, size_t *pos)
{
    if (!file_range_valid(*pos, 2, size)) return STATUS_ERROR;
    if (decode16(bytes + *pos) == 0xffff) {
        if (!file_range_valid(*pos, 4, size)) return STATUS_ERROR;
        unsigned ordinal = decode16(bytes + *pos + 2);
        static const char *classes[] = {"Button", "Edit", "Static", "ListBox", "ScrollBar", "ComboBox"};
        if (ordinal >= 0x80 && ordinal <= 0x85) append(p, "%s(#%u)", classes[ordinal - 0x80], ordinal);
        else append(p, "#%u", ordinal);
        *pos += 4; return STATUS_SUCCESS;
    }
    return wide_z(p, bytes, size, pos);
}

/*
 * Parse a standard or extended dialog template without creating any windows.
 * The two layouts differ in header sizes, control IDs, and optional font data.
 * A running byte cursor handles variable-length names, aligned control records,
 * and creation-data blobs. Coordinates are signed 16-bit values, not unsigned sizes.
 */
static int dialog_payload(Preview *p, const unsigned char *bytes, size_t size)
{
    int extended = size >= 4 && decode16(bytes + 2) == 0xffff;
    size_t fixed = extended ? 26 : 18;
    if (size < fixed || (extended && decode16(bytes) != 1)) return STATUS_ERROR;
    size_t pos = fixed;
    unsigned controls = decode16(bytes + (extended ? 16 : 8));
    uint32_t style = decode32(bytes + (extended ? 12 : 0));
    uint32_t exstyle = decode32(bytes + (extended ? 8 : 4));
    if (controls > 4096) return STATUS_ERROR;
    append(p, "%s dialog: controls=%u style=0x%08X exStyle=0x%08X; menu=", extended ? "Extended" : "Standard", controls, style, exstyle);
    if (dialog_field(p, bytes, size, &pos) != STATUS_SUCCESS) return STATUS_ERROR;
    append(p, "; class=");
    if (dialog_field(p, bytes, size, &pos) != STATUS_SUCCESS) return STATUS_ERROR;
    append(p, "; title=");
    if (wide_z(p, bytes, size, &pos) != STATUS_SUCCESS) return STATUS_ERROR;
    if (style & 0x40) {
        size_t font_size = extended ? 6 : 2;
        if (!file_range_valid(pos, font_size, size)) return STATUS_ERROR;
        append(p, "; font(size=%u", decode16(bytes + pos));
        if (extended) append(p, " weight=%u italic=%u charset=%u", decode16(bytes + pos + 2), bytes[pos + 4], bytes[pos + 5]);
        append(p, ")="); pos += font_size;
        if (wide_z(p, bytes, size, &pos) != STATUS_SUCCESS) return STATUS_ERROR;
    }
    for (unsigned i = 0; i < controls; ++i) {
        pos = (pos + 3) & ~(size_t)3;
        size_t header_size = extended ? 24 : 18;
        if (!file_range_valid(pos, header_size, size)) return STATUS_ERROR;
        const unsigned char *control = bytes + pos;
        uint32_t control_style = decode32(control + (extended ? 8 : 0));
        uint32_t control_exstyle = decode32(control + 4);
        uint32_t id = extended ? decode32(control + 20) : decode16(control + 16);
        size_t geometry = extended ? 12 : 8;
        append(p, "; control[%u] id=%u style=0x%08X exStyle=0x%08X rect=(%d,%d,%d,%d)", i + 1, id,
               control_style, control_exstyle, (int16_t)decode16(control + geometry), (int16_t)decode16(control + geometry + 2),
               (int16_t)decode16(control + geometry + 4), (int16_t)decode16(control + geometry + 6));
        if (extended) append(p, " helpID=%u", decode32(control));
        pos += header_size; append(p, " class=");
        if (control_class(p, bytes, size, &pos) != STATUS_SUCCESS) return STATUS_ERROR;
        append(p, " title=");
        if (dialog_field(p, bytes, size, &pos) != STATUS_SUCCESS || !file_range_valid(pos, 2, size)) return STATUS_ERROR;
        /*
         * Standard templates include the two-byte size field in a nonzero creation
         * size; extended templates count only the following bytes. Normalize both
         * representations before checking and skipping application-specific data.
         */
        size_t declared = decode16(bytes + pos), payload_size;
        if (extended) { pos += 2; payload_size = declared; }
        else if (!declared) { pos += 2; payload_size = 0; }
        else { if (declared < 2) return STATUS_ERROR; pos += 2; payload_size = declared - 2; }
        if (!file_range_valid(pos, payload_size, size)) return STATUS_ERROR;
        append(p, " creation-data=%zu bytes", payload_size);
        for (size_t j = 0; j < payload_size && j < 16; ++j) append(p, " %02X", bytes[pos + j]);
        if (payload_size > 16) append(p, " ...");
        pos += payload_size;
    }
    return STATUS_SUCCESS;
}

/*
 * Walk a standard/extended menu, recursively visiting popup submenus.
 * A position pointer lets a child consume bytes before its parent resumes.
 * The flags identify popups and the final item at each level. Bounds, depth,
 * and item counters ensure malformed flags cannot cause unbounded traversal.
 */
static int menu_items(Preview *p, const unsigned char *bytes, size_t size, size_t *pos,
                      int extended, unsigned depth, unsigned *work)
{
    if (depth > 16) return STATUS_ERROR;
    for (;;) {
        if (++*work > 4096) return STATUS_ERROR;
        unsigned flags; int popup;
        if (extended) {
            *pos = (*pos + 3) & ~(size_t)3;
            if (!file_range_valid(*pos, 14, size)) return STATUS_ERROR;
            flags = decode16(bytes + *pos + 12); popup = flags & 1;
            append(p, "[id=%u type=0x%X state=0x%X] ", decode32(bytes + *pos + 8),
                   decode32(bytes + *pos), decode32(bytes + *pos + 4));
            *pos += 14;
        } else {
            if (!file_range_valid(*pos, 2, size)) return STATUS_ERROR;
            flags = decode16(bytes + *pos); *pos += 2; popup = flags & 0x10;
            if (!popup) {
                if (!file_range_valid(*pos, 2, size)) return STATUS_ERROR;
                append(p, "[id=%u] ", decode16(bytes + *pos)); *pos += 2;
            }
        }
        if (wide_z(p, bytes, size, pos) != STATUS_SUCCESS) return STATUS_ERROR;
        append(p, "; ");
        if (popup) {
            if (extended) {
                *pos = (*pos + 3) & ~(size_t)3;
                if (!file_range_valid(*pos, 4, size)) return STATUS_ERROR;
                *pos += 4;
            }
            if (menu_items(p, bytes, size, pos, extended, depth + 1, work) != STATUS_SUCCESS)
                return STATUS_ERROR;
        }
        if (flags & 0x80) return STATUS_SUCCESS;
    }
}

/*
 * Read at most 1 MiB and select a decoder using the numeric resource type.
 * A Preview points directly into resource->decoded; the temporary payload buffer
 * is owned here and freed before returning. A malformed payload gets a fallback
 * message and still permits raw extraction; allocation/read failures return errors.
 */
int decode_resource_payload(const InputFile *input, PEResource *resource)
{
    Preview preview = {resource->decoded, sizeof(resource->decoded), 0, 0};
    if (!resource->size) { append(&preview, "Empty payload"); return STATUS_SUCCESS; }
    if (resource->size > PAYLOAD_LIMIT) {
        append(&preview, "Payload preview skipped: exceeds 1 MiB decode limit; raw extraction available");
        return STATUS_SUCCESS;
    }
    unsigned char *bytes = malloc(resource->size);
    if (!bytes) return STATUS_ERROR;
    if (read_at(input->file, resource->file_offset, bytes, resource->size, input->size) != STATUS_SUCCESS) {
        free(bytes); return STATUS_ERROR;
    }
    size_t size = resource->size;
    int valid = STATUS_SUCCESS;
    /*
     * These numbers are Windows resource type IDs, not arbitrary project tags:
     * 24 manifest, 16 version, 6 strings, 9 accelerators, 4 menu, 5 dialog,
     * 11 messages, 23 HTML, 1/2/3 cursor/bitmap/icon, 12/14 image groups.
     */
    if (resource->type_id == 24) {
        append(&preview, "Manifest text: ");
        if (size >= 2 && ((bytes[0] == 0xff && bytes[1] == 0xfe) || (bytes[0] == 0xfe && bytes[1] == 0xff)))
            valid = utf16(&preview, bytes + 2, size - 2, bytes[0] == 0xfe);
        else {
            size_t bom = size >= 3 && !memcmp(bytes, "\xef\xbb\xbf", 3) ? 3 : 0;
            valid = legacy_text(&preview, bytes + bom, size - bom, bom ? 65001 :
                                (resource->codepage ? resource->codepage : (input->text_code_page ? input->text_code_page : 65001)));
        }
    } else if (resource->type_id == 16) {
        unsigned work = 0;
        append(&preview, "Version info: ");
        valid = version_block(&preview, bytes, 0, size, 0, &work);
    } else if (resource->type_id == 6) {
        size_t pos = 0;
        append(&preview, "String table: ");
        /*
         * One Windows string-table resource contains exactly 16 length-prefixed
         * UTF-16 slots. Its resource ID selects the group; this slot selects the
         * individual string. Empty slots still consume a length field.
         */
        for (unsigned i = 0; i < 16; ++i) {
            if (!file_range_valid(pos, 2, size)) { valid = STATUS_ERROR; break; }
            size_t length = (size_t)decode16(bytes + pos) * 2; pos += 2;
            if (!file_range_valid(pos, length, size)) { valid = STATUS_ERROR; break; }
            if (length) {
                unsigned id = resource->name_id ? (resource->name_id - 1) * 16 + i : i;
                append(&preview, "[%u]=", id);
                if (utf16(&preview, bytes + pos, length, 0) != STATUS_SUCCESS) { valid = STATUS_ERROR; break; }
                append(&preview, "; ");
            }
            pos += length;
        }
    } else if (resource->type_id == 9) {
        append(&preview, "Accelerators: ");
        int ended = 0;
        for (size_t pos = 0; file_range_valid(pos, 8, size); pos += 8) {
            unsigned flags = decode16(bytes + pos);
            append(&preview, "[command=%u key=0x%04X %s%s%s%s]; ", decode16(bytes + pos + 4),
                   decode16(bytes + pos + 2), flags & 1 ? "virtual-key " : "character ",
                   flags & 4 ? "shift " : "", flags & 8 ? "control " : "", flags & 16 ? "alt" : "");
            if (flags & 0x80) { ended = 1; break; }
        }
        if (!ended) valid = STATUS_ERROR;
    } else if (resource->type_id == 4) {
        append(&preview, "Menu: ");
        unsigned work = 0;
        if (size < 4 || decode16(bytes) > 1) valid = STATUS_ERROR;
        else {
            int extended = decode16(bytes) == 1;
            size_t pos = 4 + (size_t)decode16(bytes + 2);
            if ((extended && (size < 8 || pos < 8)) || pos >= size) valid = STATUS_ERROR;
            else valid = menu_items(&preview, bytes, size, &pos, extended, 0, &work);
        }
    } else if (resource->type_id == 5) {
        valid = dialog_payload(&preview, bytes, size);
    } else if (resource->type_id == 11) {
        append(&preview, "Message table: ");
        if (size < 4 || !file_range_valid(4, (uint64_t)decode32(bytes) * 12, size)) valid = STATUS_ERROR;
        else {
            unsigned work = 0;
            uint32_t blocks = decode32(bytes);
            for (uint32_t block = 0; block < blocks && valid == STATUS_SUCCESS; ++block) {
                const unsigned char *entry = bytes + 4 + block * 12;
                uint32_t low = decode32(entry), high = decode32(entry + 4);
                size_t pos = decode32(entry + 8);
                if (low > high || pos < 4 + (uint64_t)blocks * 12) { valid = STATUS_ERROR; break; }
                for (uint64_t id = low; id <= high; ++id) {
                    if (++work > 4096 || !file_range_valid(pos, 4, size)) { valid = STATUS_ERROR; break; }
                    size_t length = decode16(bytes + pos); unsigned flags = decode16(bytes + pos + 2);
                    if (length < 4 || !file_range_valid(pos, length, size) || flags > 1) { valid = STATUS_ERROR; break; }
                    append(&preview, "[%llu]=", (unsigned long long)id);
                    size_t text_size = length - 4;
                    /*
                     * The message-entry Unicode flag overrides legacy code-page conversion.
                     * Trim a text terminator, not arbitrary trailing bytes, before displaying it.
                     */
                    if (flags) {
                        if (text_size >= 2 && !decode16(bytes + pos + length - 2)) text_size -= 2;
                        valid = utf16(&preview, bytes + pos + 4, text_size, 0);
                    } else {
                        const unsigned char *start = bytes + pos + 4;
                        uint32_t page = resource->codepage ? resource->codepage : input->text_code_page;
                        if (page == 1200 || page == 1201) {
                            for (size_t j = 0; j + 2 <= text_size; j += 2)
                                if (!start[j] && !start[j + 1]) { text_size = j; break; }
                        } else {
                            const unsigned char *end = memchr(start, 0, text_size);
                            if (end) text_size = (size_t)(end - start);
                        }
                        valid = legacy_text(&preview, start, text_size, page);
                    }
                    if (valid != STATUS_SUCCESS) break;
                    append(&preview, "; "); pos += length;
                }
            }
        }
    } else if (resource->type_id == 23) {
        append(&preview, "HTML text: ");
        if (size >= 2 && ((bytes[0] == 0xff && bytes[1] == 0xfe) || (bytes[0] == 0xfe && bytes[1] == 0xff)))
            valid = utf16(&preview, bytes + 2, size - 2, bytes[0] == 0xfe);
        else {
            size_t bom = size >= 3 && !memcmp(bytes, "\xef\xbb\xbf", 3) ? 3 : 0;
            valid = legacy_text(&preview, bytes + bom, size - bom, bom ? 65001 :
                                (resource->codepage ? resource->codepage : (input->text_code_page ? input->text_code_page : 65001)));
        }
    } else if (resource->type_id == 2 || resource->type_id == 3 || resource->type_id == 1) {
        /*
         * Cursor payloads begin with two 16-bit hotspot coordinates; image bytes
         * follow. Icon DIB heights include both the color image and its mask, so
         * the reported image height is half the stored height (not so for bitmaps).
         */
        size_t offset = resource->type_id == 1 ? 4 : 0;
        if (size >= offset + 24 && !memcmp(bytes + offset, "\x89PNG\r\n\x1a\n", 8) &&
            !memcmp(bytes + offset + 12, "IHDR", 4)) {
            const unsigned char *p = bytes + offset + 16;
            uint32_t width = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
            uint32_t height = (uint32_t)p[4] << 24 | (uint32_t)p[5] << 16 | (uint32_t)p[6] << 8 | p[7];
            append(&preview, "PNG image metadata: %u x %u", width, height);
        } else if (size >= offset + 12 && decode32(bytes + offset) == 12) {
            append(&preview, "DIB metadata: %u x %u, %u bits per pixel", decode16(bytes + offset + 4),
                   decode16(bytes + offset + 6) / (resource->type_id == 2 ? 1 : 2), decode16(bytes + offset + 10));
        } else if (size >= offset + 40 && decode32(bytes + offset) >= 40 && decode32(bytes + offset) <= size - offset) {
            int32_t width = (int32_t)decode32(bytes + offset + 4), height = (int32_t)decode32(bytes + offset + 8);
            append(&preview, "DIB metadata: %lld x %lld, %u bits per pixel", (long long)width,
                   (long long)height / (resource->type_id == 2 ? 1 : 2), decode16(bytes + offset + 14));
        } else valid = STATUS_ERROR;
    } else if (resource->type_id == 12 || resource->type_id == 14) {
        if (size < 6 || !file_range_valid(6, (uint64_t)decode16(bytes + 4) * 14, size)) valid = STATUS_ERROR;
        else append(&preview, "Image group: %u entries (raw resource format)", decode16(bytes + 4));
    } else {
        append(&preview, "Raw payload preview:");
        for (size_t i = 0; i < size && i < 32; ++i) append(&preview, " %02X", bytes[i]);
        if (size > 32) append(&preview, " ...");
    }
    if (valid != STATUS_SUCCESS)
        snprintf(resource->decoded, sizeof(resource->decoded),
                 "Malformed or unsupported payload encoding for resource type %u; raw extraction available", resource->type_id);
    else if (preview.truncated) {
        /* A bounded preview never changes the underlying extracted bytes. */
    }
    free(bytes);
    return STATUS_SUCCESS;
}

/*
 * Write raw PE resources, optional ICO/CUR reconstructions, and a TSV index.
 * Extraction is the inspection path that creates files. It requires a new output
 * directory and uses generated filenames instead of names supplied by the input.
 * File descriptors (int) are OS handles; FILE * streams add C buffered I/O.
 * Each successful open/fdopen must eventually have a matching close/fclose.
 */

#define _DARWIN_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "peparser.h"

/*
 * Choose an extension hint for known raw resource types.
 * These extensions do not imply conversion: a raw bitmap payload is still a DIB,
 * and a manifest preserves its original encoding.
 */
static const char *suffix(uint32_t type)
{
    switch (type) {
    case 24: return "manifest.xml";
    case 16: return "version.bin";
    case 6: return "strings.bin";
    case 2: return "dib";
    default: return "bin";
    }
}

/*
 * Copy every resource into a newly created private directory and write index.tsv.
 * Check the raw-output budget first, then account for reconstructed images too.
 * Use directory-relative openat and O_EXCL/O_NOFOLLOW to avoid overwriting files
 * or following symbolic links. Failures may leave earlier completed outputs.
 */
int extract_pe_resources(const InputFile *input, const PEInfo *info, const char *directory)
{
    PEResource *resources = NULL;
    if (collect_pe_resources(input, info, &resources) != STATUS_SUCCESS) {
        fprintf(stderr, "Cannot collect all resource entries for extraction\n"); return STATUS_ERROR;
    }
    uint64_t total = 0;
    for (unsigned i = 0; i < info->resource_total; ++i) total += resources[i].size;
    if (total > UINT64_C(256) * 1024 * 1024) {
        fprintf(stderr, "Resource extraction exceeds the 256 MiB total output limit\n");
        free(resources); return STATUS_ERROR;
    }
    if (mkdir(directory, 0700) != 0) {
        perror("Cannot create resource directory (destination must not exist)");
        free(resources); return STATUS_ERROR;
    }
    /*
     * Keep an open handle to the directory rather than constructing paths from
     * resource names. O_DIRECTORY requires a directory and O_NOFOLLOW rejects
     * a symbolic link at this open. Generated names contain no input path parts.
     */
    int dir = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dir < 0) { print_path_error("Cannot open resource directory", directory); free(resources); return STATUS_ERROR; }
    int status = STATUS_ERROR;
    int index_fd = openat(dir, "index.tsv", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    /*
     * fdopen wraps an existing descriptor. Once it succeeds, fclose owns closing
     * the descriptor too; when it fails, we must close index_fd ourselves.
     */
    FILE *index = index_fd < 0 ? NULL : fdopen(index_fd, "w");
    if (!index) { if (index_fd >= 0) close(index_fd); goto done; }
    if (fprintf(index, "file\tresource_path\ttype\trva\tsize\tcode_page\treconstructed_file\n") < 0) goto close_index;
    for (unsigned i = 0; i < info->resource_total; ++i) {
        const PEResource *resource = &resources[i];
        char name[96];
        snprintf(name, sizeof(name), "resource-%04u-type-%u.%s", i + 1, resource->type_id, suffix(resource->type_id));
        int fd = openat(dir, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        if (fd < 0) goto close_index;
        FILE *out = fdopen(fd, "wb");
        if (!out) { close(fd); goto close_index; }
        unsigned char buffer[8192];
        uint64_t offset = resource->file_offset;
        size_t remaining = resource->size;
        int failed = 0;
        /*
         * Copy fixed-size chunks so a large resource does not require an equally
         * large memory allocation. A short write or read aborts this output; fclose
         * must also be checked because buffered write errors may appear only then.
         */
        while (remaining) {
            size_t chunk = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
            if (read_at(input->file, offset, buffer, chunk, input->size) != STATUS_SUCCESS ||
                fwrite(buffer, 1, chunk, out) != chunk) { failed = 1; break; }
            remaining -= chunk; offset += chunk;
        }
        if (fclose(out) != 0) failed = 1;
        if (failed) { unlinkat(dir, name, 0); goto close_index; }
        char reconstructed[96] = "-";
        if (resource->type_id == 1 || resource->type_id == 3 || resource->type_id == 12 || resource->type_id == 14) {
            unsigned char *image = NULL; size_t image_size = 0;
            if (reconstruct_resource_image(input, info, i, &image, &image_size) == STATUS_SUCCESS) {
                total += image_size;
                if (total > UINT64_C(256) * 1024 * 1024) { free(image); goto close_index; }
                snprintf(reconstructed, sizeof(reconstructed), "resource-%04u.%s", i + 1,
                         resource->type_id == 1 || resource->type_id == 12 ? "cur" : "ico");
                int image_fd = openat(dir, reconstructed, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
                FILE *image_file = image_fd < 0 ? NULL : fdopen(image_fd, "wb");
                if (!image_file) { if (image_fd >= 0) close(image_fd); free(image); goto close_index; }
                int image_failed = fwrite(image, 1, image_size, image_file) != image_size;
                if (fclose(image_file) != 0) image_failed = 1;
                free(image);
                if (image_failed) { unlinkat(dir, reconstructed, 0); goto close_index; }
            } else snprintf(reconstructed, sizeof(reconstructed), "unavailable-invalid-or-missing-image-data");
        }
        if (fprintf(index, "%s\t%s\t%u\t0x%08X\t%u\t%u\t%s\n", name, resource->path,
                    resource->type_id, resource->rva, resource->size, resource->codepage, reconstructed) < 0) goto close_index;
    }
    status = STATUS_SUCCESS;
/*
 * goto funnels all failures through the appropriate cleanup. Only streams
 * that were successfully opened reach close_index. No cleanup removes the
 * whole directory, so the user can inspect already completed extraction files.
 */
close_index:
    if (fclose(index) != 0) status = STATUS_ERROR;
done:
    if (status != STATUS_SUCCESS)
        fprintf(stderr, "Resource extraction failed; the new output directory may contain partial results\n");
    close(dir); free(resources);
    return status;
}

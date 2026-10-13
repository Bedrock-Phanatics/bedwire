#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "libdeflate.h"

#if LIBDEFLATE_VERSION_MAJOR != 1 || LIBDEFLATE_VERSION_MINOR != 26
#error "The codec benchmark requires libdeflate 1.26"
#endif

typedef union {
    size_t size;
    max_align_t alignment;
} Header;

static size_t allocations, live_bytes, peak_bytes;
static size_t compressor_bytes, decompressor_bytes;
static size_t fail_after = SIZE_MAX;

static void *tracked_malloc(size_t size) {
    if (allocations++ == fail_after) return NULL;
    if (size > SIZE_MAX - sizeof(Header)) return NULL;
    Header *header = malloc(sizeof(Header) + size);
    if (header == NULL) return NULL;
    header->size = size;
    live_bytes += size;
    if (live_bytes > peak_bytes) peak_bytes = live_bytes;
    return header + 1;
}

static void tracked_free(void *pointer) {
    if (pointer == NULL) return;
    Header *header = (Header *)pointer - 1;
    live_bytes -= header->size;
    free(header);
}

static const struct libdeflate_options options = {
    sizeof(struct libdeflate_options), tracked_malloc, tracked_free
};

struct libdeflate_compressor *bw_alloc_compressor(int level) {
    size_t before = live_bytes;
    struct libdeflate_compressor *compressor = libdeflate_alloc_compressor_ex(level, &options);
    if (compressor != NULL) compressor_bytes = live_bytes - before;
    return compressor;
}

struct libdeflate_decompressor *bw_alloc_decompressor(void) {
    size_t before = live_bytes;
    struct libdeflate_decompressor *decompressor = libdeflate_alloc_decompressor_ex(&options);
    if (decompressor != NULL) decompressor_bytes = live_bytes - before;
    return decompressor;
}

size_t bw_allocations(void) { return allocations; }
size_t bw_live_bytes(void) { return live_bytes; }
size_t bw_peak_bytes(void) { return peak_bytes; }
void bw_reset_peak(void) { peak_bytes = live_bytes; }
void bw_fail_after(size_t index) { fail_after = index; }
size_t bw_compressor_bytes(void) { return compressor_bytes; }
size_t bw_decompressor_bytes(void) { return decompressor_bytes; }

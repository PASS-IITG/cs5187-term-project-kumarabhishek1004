// Allocation-failure injection for libxml2 harnesses.
// Usage: call fuzzInstallAllocator() once (before xmlInitParser), then fuzzArmAllocFailure(n) at the start
// of each input so that the n-th allocation returns NULL (exactly once). Call fuzzDisarmAllocFailure() before cleanup.
// NOTE: xmlMemSetup() is deprecated in recent libxml2 but still present; adapt if your version removed it.
#ifndef FUZZ_ALLOCATOR_H
#define FUZZ_ALLOCATOR_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/xmlmemory.h>

static int64_t fuzzAllocCountdown = -1;

static inline int fuzzShouldFailAllocation(void) {
    if (fuzzAllocCountdown < 0) return 0;
    if (fuzzAllocCountdown == 0) {
        fuzzAllocCountdown = -1;
        return 1;
    }
    fuzzAllocCountdown--;
    return 0;
}

static void *fuzzMalloc(size_t size) {
    if (fuzzShouldFailAllocation()) return NULL;
    return malloc(size);
}

static void *fuzzRealloc(void *pointer, size_t size) {
    if (fuzzShouldFailAllocation()) return NULL;
    return realloc(pointer, size);
}

static char *fuzzStrdup(const char *text) {
    if (fuzzShouldFailAllocation()) return NULL;
    return strdup(text);
}

static void fuzzFree(void *pointer) { free(pointer); }

static inline void fuzzInstallAllocator(void) { xmlMemSetup(fuzzFree, fuzzMalloc, fuzzRealloc, fuzzStrdup); }
static inline void fuzzArmAllocFailure(uint32_t allocationIndex) { fuzzAllocCountdown = (int64_t)allocationIndex; }
static inline void fuzzDisarmAllocFailure(void) { fuzzAllocCountdown = -1; }

#endif

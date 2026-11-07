#ifndef PF_MACH_HANDOFF_PATTERN_H
#define PF_MACH_HANDOFF_PATTERN_H
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

enum {
    PF_HANDOFF_WIDTH = 128,
    PF_HANDOFF_HEIGHT = 128,
    PF_HANDOFF_BPP = 4,
    PF_HANDOFF_STRIDE = PF_HANDOFF_WIDTH * PF_HANDOFF_BPP,
    PF_HANDOFF_BYTES = PF_HANDOFF_STRIDE * PF_HANDOFF_HEIGHT
};

// The test only edits the pixels of an IOSurface created by this app.
// BGRA, little-endian, opaque alpha. No out-of-bounds access.
static inline bool PFHandoffFill(uint8_t *base, size_t size) {
    if (!base || size < PF_HANDOFF_BYTES) return false;
    for (size_t y = 0; y < PF_HANDOFF_HEIGHT; ++y) {
        for (size_t x = 0; x < PF_HANDOFF_WIDTH; ++x) {
            size_t i = y * PF_HANDOFF_STRIDE + x * PF_HANDOFF_BPP;
            base[i] = (uint8_t)(2 * x);
            base[i + 1] = (uint8_t)(2 * y);
            base[i + 2] = (uint8_t)(x ^ y);
            base[i + 3] = 255;
        }
    }
    return true;
}

// The cyan patch is drawn only AFTER the surface has been reacquired from
// its Mach port. The exported image makes the write physically observable.
static inline bool PFHandoffStamp(uint8_t *base, size_t size) {
    if (!base || size < PF_HANDOFF_BYTES) return false;
    for (size_t y = 8; y < 40; ++y) {
        for (size_t x = 8; x < 40; ++x) {
            size_t i = y * PF_HANDOFF_STRIDE + x * PF_HANDOFF_BPP;
            base[i] = 255;      // blue
            base[i + 1] = 255;  // green
            base[i + 2] = 0;    // red
            base[i + 3] = 255;  // alpha
        }
    }
    return true;
}

static inline uint64_t PFHandoffHash(const uint8_t *base, size_t size) {
    if (!base) return 0;
    uint64_t hash = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < size; ++i) {
        hash ^= base[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}
#endif

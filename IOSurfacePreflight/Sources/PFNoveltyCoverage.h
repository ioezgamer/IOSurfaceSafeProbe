#ifndef PF_NOVELTY_COVERAGE_H
#define PF_NOVELTY_COVERAGE_H

// Standalone deterministic instrumentation for public IOSurface API input
// coverage. This file does not perform any IPC or kernel/memory operations.
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

enum {
    PF_NOVELTY_TARGET_CASES = 50000,
    PF_NOVELTY_CANDIDATE_MULTIPLIER = 4,
    PF_NOVELTY_HISTORY_ROW_LIMIT = 250000,
    PF_NOVELTY_HISTORY_FILE_LIMIT = 6,
    PF_NOVELTY_TABLE_SLOTS = 1 << 19
};

// Canonicalize the ACTUAL sent dictionary. Values removed from the
// dictionary cannot distinguish two API calls, regardless of their
// pre-omission random values. Flags distinguish omitted versus literal zero.
typedef struct {
    uint32_t width;
    uint32_t height;
    uint32_t bytesPerElement;
    uint32_t bytesPerRow;
    uint32_t allocationSize;
    uint32_t pixelFormat;
    uint32_t flags;
} PFEffectiveInputKey;

static inline PFEffectiveInputKey PFEffectiveKey(
    uint32_t width, uint32_t height, uint32_t element,
    uint32_t row, uint32_t allocation, uint32_t format,
    bool omitRow, bool omitAlloc) {
    PFEffectiveInputKey key = {
        width, height, element,
        omitRow ? 0U : row,
        omitAlloc ? 0U : allocation,
        format, (omitRow ? 1U : 0U) | (omitAlloc ? 2U : 0U)
    };
    return key;
}

static inline bool PFEffectiveKeyEqual(const PFEffectiveInputKey *a,
                                        const PFEffectiveInputKey *b) {
    return a->width == b->width &&
        a->height == b->height &&
        a->bytesPerElement == b->bytesPerElement &&
        a->bytesPerRow == b->bytesPerRow &&
        a->allocationSize == b->allocationSize &&
        a->pixelFormat == b->pixelFormat && a->flags == b->flags;
}

// Validate complete decimal/hex input fields before importing user-editable
// archived CSV. Reject negatives, truncations, and nonnumeric suffixes.
static inline bool PFNoveltyParseU32(const char *text,int base,uint32_t *value) {
    if(!text || !*text || !value || (*text<'0' || *text>'9')) return false;
    errno=0;
    char *end=NULL;
    unsigned long long parsed=strtoull(text,&end,base);
    if(errno!=0 || end==text || *end!='\0' || parsed>UINT32_MAX) return false;
    *value=(uint32_t)parsed;
    return true;
}

// Mix every exact field explicitly. Open addressing checks complete keys
// on hash collisions, so a 64-bit hash collision never silently deduplicates
// two distinct configurations.
static inline uint64_t PFEffectiveKeyHash(const PFEffectiveInputKey *key) {
    const uint32_t words[7] = {
        key->width,key->height,key->bytesPerElement,key->bytesPerRow,
        key->allocationSize,key->pixelFormat,key->flags
    };
    uint64_t x = UINT64_C(1469598103934665603);
    for(size_t i=0;i<7;i++) {
        uint32_t v=words[i];
        for(unsigned j=0;j<4;j++) {
            x ^= (uint8_t)((v >> (8*j)) & 0xffU);
            x *= UINT64_C(1099511628211);
        }
    }
    return x;
}

typedef struct {
    PFEffectiveInputKey key;
    uint8_t occupied;
    uint8_t origin; // 1: loaded from history; 2: generated this campaign.
} PFNoveltySlot;

typedef struct {
    PFNoveltySlot *slots;
    size_t capacity;
    size_t used;
} PFNoveltySet;

static inline PFNoveltySet *PFNoveltyCreate(size_t capacity) {
    if(capacity<8 || (capacity&(capacity-1)) || capacity>PF_NOVELTY_TABLE_SLOTS)
        return NULL;
    PFNoveltySet *set=(PFNoveltySet *)calloc(1,sizeof(*set));
    if(!set) return NULL;
    set->slots=(PFNoveltySlot *)calloc(capacity,sizeof(PFNoveltySlot));
    if(!set->slots) {
        free(set);
        return NULL;
    }
    set->capacity=capacity;
    return set;
}
static inline void PFNoveltyDestroy(PFNoveltySet *set) {
    if(set) {
        free(set->slots);
        free(set);
    }
}

// 1: inserted a new effective config. 0: previously seen. -1: table full.
// At most 80% table utilization avoids pathological probe chains.
static inline int PFNoveltyInsertWithOrigin(
    PFNoveltySet *set,const PFEffectiveInputKey *key,
    uint8_t origin,uint8_t *existingOrigin) {

    if(existingOrigin) *existingOrigin=0;
    if(!set || !key || !set->slots || !set->capacity ||
       (origin!=1 && origin!=2)) return -1;
    size_t mask=set->capacity-1;
    size_t index=(size_t)PFEffectiveKeyHash(key)&mask;
    for(size_t probes=0;probes<set->capacity;probes++) {
        PFNoveltySlot *slot=&set->slots[index];
        if(!slot->occupied) {
            if(set->used >= (set->capacity*4U)/5U) return -1;
            slot->key=*key;
            slot->occupied=1;
            slot->origin=origin;
            set->used++;
            return 1;
        }
        if(PFEffectiveKeyEqual(&slot->key,key)) {
            if(existingOrigin) *existingOrigin=slot->origin;
            return 0;
        }
        index=(index+1)&mask;
    }
    return -1;
}
static inline int PFNoveltyInsert(PFNoveltySet *set,const PFEffectiveInputKey *key) {
    return PFNoveltyInsertWithOrigin(set,key,2,NULL);
}

// SplitMix64 has substantially better low-bit behavior than the legacy
// xorshift32 sequence. Its state is seeded only from the exported uint32 seed.
// Deterministic across arm64/macOS/Linux for replay and regression tests.
static inline uint32_t PFNoveltyRandom(uint64_t *state) {
    uint64_t z=(*state += UINT64_C(0x9E3779B97F4A7C15));
    z=(z^(z>>30))*UINT64_C(0xBF58476D1CE4E5B9);
    z=(z^(z>>27))*UINT64_C(0x94D049BB133111EB);
    z^=z>>31;
    return (uint32_t)(z>>32);
}
static inline uint64_t PFNoveltySeed(uint32_t seed) {
    return ((uint64_t)seed << 32) ^ UINT64_C(0x9E3779B97F4A7C15);
}

// v2 stratification: preserve boundaries, include nearby values and the
// bounded 0..256 range. Input novelty is not a kernel-coverage measurement.
static inline uint32_t PFNoveltyDimension(uint64_t *state) {
    const uint32_t lengths[16] = {
        0,1,2,3,7,8,15,16,31,32,63,64,127,128,255,256
    };
    uint32_t route=PFNoveltyRandom(state)%4U;
    if(route<2U) return lengths[PFNoveltyRandom(state)%16U];
    if(route==2U) {
        int32_t base=(int32_t)lengths[PFNoveltyRandom(state)%16U];
        int32_t jitter=(int32_t)(PFNoveltyRandom(state)%17U)-8;
        int32_t value=base+jitter;
        if(value<0) value=0;
        if(value>256) value=256;
        return (uint32_t)value;
    }
    return PFNoveltyRandom(state)%257U;
}

#endif

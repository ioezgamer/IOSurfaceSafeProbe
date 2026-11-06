#ifndef PF_TARGETED_REPLAY_H
#define PF_TARGETED_REPLAY_H

// Strict, read-only parser for the app's OWN archived public-IOSurface CSV.
// No private selectors, raw addresses, IPC or kernel access.
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "PFNoveltyCoverage.h"

enum { PF_REPLAY_COLS = 23, PF_REPLAY_MAX_ITERATIONS = 3 };

typedef struct {
    uint32_t seed;
    uint32_t caseNumber;
    uint32_t candidateIndex;
    uint32_t width, height, element, row, allocation, format;
    uint32_t omitRow, omitAllocation;
    uint32_t originalWidth, originalHeight, originalRow, originalAllocation;
    bool originallyAccepted;
} PFTargetedCase;

static inline bool PFReplayAllowedElement(uint32_t element) {
    return element==1 || element==2 || element==3 || element==4 || element==8;
}

static inline bool PFReplayAllowedFormat(uint32_t format) {
    return format==0x42475241U || format==0x52474241U ||
           format==0U || format==0x41414141U;
}

// 23 fields from boundary-trace.csv, with the existing unquoted schema.
// The limits prevent unexpected/untrusted CSV content from allocating large
// surfaces. A zero width/height is legal and intentionally left as an input.
static inline bool PFReplayParseCSV(const char *const *parts,
                                    size_t count, PFTargetedCase *dst) {
    if(!parts || !dst || count!=PF_REPLAY_COLS) return false;
    for(size_t i=0;i<count;i++) if(!parts[i]) return false;
    PFTargetedCase x={0};
    if(!PFNoveltyParseU32(parts[1],10,&x.seed) ||
       !PFNoveltyParseU32(parts[2],10,&x.caseNumber) ||
       !PFNoveltyParseU32(parts[3],10,&x.width) ||
       !PFNoveltyParseU32(parts[4],10,&x.height) ||
       !PFNoveltyParseU32(parts[5],10,&x.element) ||
       !PFNoveltyParseU32(parts[6],10,&x.row) ||
       !PFNoveltyParseU32(parts[7],10,&x.allocation) ||
       !PFNoveltyParseU32(parts[8],0,&x.format) ||
       !PFNoveltyParseU32(parts[9],10,&x.omitRow) ||
       !PFNoveltyParseU32(parts[10],10,&x.omitAllocation) ||
       !PFNoveltyParseU32(parts[13],10,&x.originalWidth) ||
       !PFNoveltyParseU32(parts[14],10,&x.originalHeight) ||
       !PFNoveltyParseU32(parts[15],10,&x.originalRow) ||
       !PFNoveltyParseU32(parts[16],10,&x.originalAllocation) ||
       !PFNoveltyParseU32(parts[22],10,&x.candidateIndex))
        return false;
    if(x.caseNumber==0 || x.candidateIndex==0 ||
       x.width>256 || x.height>256 ||
       !PFReplayAllowedElement(x.element) ||
       x.row>4096 || x.allocation>2097152 ||
       !PFReplayAllowedFormat(x.format) ||
       x.omitRow>1 || x.omitAllocation>1 ||
       x.originalWidth>4096 || x.originalHeight>4096 ||
       x.originalRow>16777216U) return false;
    if(strcmp(parts[19],"ACCEPTED")==0) x.originallyAccepted=true;
    else if(strcmp(parts[19],"REJECTED")==0) x.originallyAccepted=false;
    else return false; // Don't auto-replay exceptions or unknown outcomes.
    *dst=x;
    return true;
}

static inline bool PFReplaySameOutcome(const PFTargetedCase *x,
                                       bool wasAccepted,
                                       uint32_t width,uint32_t height,
                                       uint32_t row,uint32_t allocation) {
    if(!x || wasAccepted!=x->originallyAccepted) return false;
    if(!wasAccepted) return true;
    return width==x->originalWidth && height==x->originalHeight &&
           row==x->originalRow && allocation==x->originalAllocation;
}
#endif

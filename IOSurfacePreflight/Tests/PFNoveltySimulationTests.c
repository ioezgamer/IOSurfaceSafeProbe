#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "../Sources/PFNoveltyCoverage.h"

// Compare against the candidate generator used by the iOS v19.5 mode.
// No IOSurface calls occur; this is a deterministic integration test.
static void replay(PFNoveltySet *seen, uint32_t seed,
                   unsigned total, bool expectAllDuplicates,
                   unsigned *distinct, unsigned *repeats) {
    const uint32_t elements[]={1,2,3,4,8};
    const uint32_t formats[]={0x42475241,0x52474241,0,0x41414141};
    uint64_t state=PFNoveltySeed(seed);
    *distinct=0;
    *repeats=0;
    for(unsigned candidate=1;candidate<=total;candidate++) {
        uint32_t w=PFNoveltyDimension(&state);
        uint32_t h=PFNoveltyDimension(&state);
        assert(w<=256 && h<=256);
        uint32_t elem=elements[PFNoveltyRandom(&state)%5];
        uint32_t rowOptions[6]={
            0,w*elem>0?w*elem-1:0,w*elem,
            w*elem+1,((w*elem+15)/16)*16,w*elem+64
        };
        uint32_t row=rowOptions[PFNoveltyRandom(&state)%6];
        uint32_t nominalAlloc=row*h;
        uint32_t allocOptions[6]={
            0,nominalAlloc>0?nominalAlloc-1:0,nominalAlloc,
            nominalAlloc+1,nominalAlloc+64,nominalAlloc+256
        };
        uint32_t alloc=allocOptions[PFNoveltyRandom(&state)%6];
        uint32_t format=formats[PFNoveltyRandom(&state)%4];
        bool omitRow=candidate%37==0,omitAlloc=candidate%41==0;
        PFEffectiveInputKey key=PFEffectiveKey(w,h,elem,row,alloc,format,
                                                omitRow,omitAlloc);
        int result=PFNoveltyInsert(seen,&key);
        assert(result>=0);
        if(result==1) (*distinct)++;
        else (*repeats)++;
        assert((*distinct)+(*repeats)==candidate);
        if(expectAllDuplicates) assert(result==0);
    }
}

int main(void) {
    PFNoveltySet *seen=PFNoveltyCreate(PF_NOVELTY_TABLE_SLOTS);
    assert(seen);
    unsigned distinct=0,repeat=0;
    replay(seen,0xA1152026U,200000,false,&distinct,&repeat);
    assert(distinct>=50000 && distinct<200000);
    assert(distinct+repeat==200000);
    assert(seen->used==distinct);
    unsigned againNew=0,againRepeat=0;
    replay(seen,0xA1152026U,200000,true,&againNew,&againRepeat);
    assert(againNew==0 && againRepeat==200000);
    assert(seen->used==distinct);
    printf("200000 candidates: %u distinct, %u repeats; deterministic replay 200000/200000 detected\n",
           distinct,repeat);
    PFNoveltyDestroy(seen);
    return 0;
}

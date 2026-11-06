#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../Sources/PFNoveltyCoverage.h"

int main(void) {
    PFNoveltySet *set=PFNoveltyCreate(128);
    assert(set && set->capacity==128 && set->used==0);
    const PFEffectiveInputKey a=PFEffectiveKey(8,16,4,32,512,0x42475241,false,false);
    const PFEffectiveInputKey a2=PFEffectiveKey(8,16,4,32,512,0x42475241,false,false);
    const PFEffectiveInputKey b=PFEffectiveKey(8,16,4,33,512,0x42475241,false,false);
    const PFEffectiveInputKey omitRowA=PFEffectiveKey(8,16,4,32,512,0x42475241,true,false);
    const PFEffectiveInputKey omitRowB=PFEffectiveKey(8,16,4,999,512,0x42475241,true,false);
    const PFEffectiveInputKey omitAllocA=PFEffectiveKey(8,16,4,32,512,0x42475241,false,true);
    const PFEffectiveInputKey omitAllocB=PFEffectiveKey(8,16,4,32,1111,0x42475241,false,true);
    const PFEffectiveInputKey literalZeroRow=PFEffectiveKey(8,16,4,0,512,0x42475241,false,false);
    const PFEffectiveInputKey formatDiff=PFEffectiveKey(8,16,4,32,512,0x52474241,false,false);
    assert(PFEffectiveKeyEqual(&a,&a2));
    assert(PFEffectiveKeyHash(&a)==PFEffectiveKeyHash(&a2));
    assert(!PFEffectiveKeyEqual(&a,&b));
    assert(PFEffectiveKeyEqual(&omitRowA,&omitRowB));
    assert(PFEffectiveKeyEqual(&omitAllocA,&omitAllocB));
    assert(!PFEffectiveKeyEqual(&omitRowA,&literalZeroRow));
    assert(!PFEffectiveKeyEqual(&a,&formatDiff));
    assert(PFNoveltyInsert(set,&a)==1);
    assert(PFNoveltyInsert(set,&a2)==0);
    assert(PFNoveltyInsert(set,&b)==1);
    assert(PFNoveltyInsert(set,&omitRowA)==1);
    assert(PFNoveltyInsert(set,&omitRowB)==0);
    assert(PFNoveltyInsert(set,&omitAllocA)==1);
    assert(PFNoveltyInsert(set,&omitAllocB)==0);
    assert(set->used==4);

    uint8_t origin=0;
    const PFEffectiveInputKey old=PFEffectiveKey(7,7,4,28,196,0x42475241,false,false);
    assert(PFNoveltyInsertWithOrigin(set,&old,1,&origin)==1);
    assert(PFNoveltyInsertWithOrigin(set,&old,2,&origin)==0);
    assert(origin==1); // historic duplicate is distinguishable
    assert(PFNoveltyInsertWithOrigin(set,&a,2,&origin)==0);
    assert(origin==2); // same-campaign duplicate
    assert(PFNoveltyInsertWithOrigin(set,&old,3,&origin)==-1);

    uint64_t state1=PFNoveltySeed(123456789U);
    uint64_t state2=PFNoveltySeed(123456789U);
    uint64_t state3=PFNoveltySeed(123456790U);
    uint32_t seq1[16]={0};
    bool differs=false;
    for(int i=0;i<16;i++) {
        seq1[i]=PFNoveltyRandom(&state1);
        assert(seq1[i]==PFNoveltyRandom(&state2));
        if(seq1[i]!=PFNoveltyRandom(&state3)) differs=true;
    }
    assert(differs);
    assert(PFNoveltyCreate(0)==NULL);
    assert(PFNoveltyCreate(7)==NULL);
    assert(PFNoveltyCreate(129)==NULL);
    assert(PFNoveltyInsert(NULL,&a)==-1);
    assert(PFNoveltyInsert(set,NULL)==-1);

    // Verify the real table's fullness cap without ever writing out of bounds.
    PFNoveltySet *small=PFNoveltyCreate(8);
    assert(small);
    for(uint32_t i=0;i<6;i++) {
        PFEffectiveInputKey k=PFEffectiveKey(i+1,1,4,64,256,0,false,false);
        assert(PFNoveltyInsert(small,&k)==1);
    }
    PFEffectiveInputKey overflow=PFEffectiveKey(999,1,4,64,256,0,false,false);
    assert(PFNoveltyInsert(small,&overflow)==-1);
    assert(small->used==6);
    PFNoveltyDestroy(small);
    PFNoveltyDestroy(set);
    puts("deterministic effective-input/seed/guard assertions passed");
    return 0;
}

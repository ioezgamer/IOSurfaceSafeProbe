#include <assert.h>
#include <stdio.h>
#include "../Sources/PFBoundedBatch.h"
int main(void) {
    const uint32_t seen[]={17,42,0xA1172026};
    assert(PF_BATCH_RUNS==3);
    assert(PF_BATCH_CASES_PER_RUN==50000);
    assert(!PFBatchUniqueSeed(0,seen,3));
    assert(!PFBatchUniqueSeed(17,seen,3));
    assert(!PFBatchUniqueSeed(42,seen,3));
    assert(!PFBatchUniqueSeed(0xA1172026,seen,3));
    assert(PFBatchUniqueSeed(99,seen,3));
    assert(PFBatchCanAdvance(1,3,false,false,false));
    assert(!PFBatchCanAdvance(3,3,false,false,false));
    assert(!PFBatchCanAdvance(0,3,true,false,false));
    assert(!PFBatchCanAdvance(0,3,false,true,false));
    assert(!PFBatchCanAdvance(0,3,false,false,true));
    puts("11/11 bounded batch tests passed");
    return 0;
}

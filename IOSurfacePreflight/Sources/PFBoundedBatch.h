#ifndef PF_BOUNDED_BATCH_H
#define PF_BOUNDED_BATCH_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum { PF_BATCH_RUNS = 3, PF_BATCH_CASES_PER_RUN = 50000 };
static inline bool PFBatchUniqueSeed(uint32_t candidate,const uint32_t *seen,size_t count) {
    if(candidate==0) return false;
    for(size_t i=0;i<count;i++) if(seen[i]==candidate) return false;
    return true;
}
static inline bool PFBatchCanAdvance(size_t completed,size_t planned,bool cancellationRequested,
                                     bool hadException,bool integrityError) {
    return !cancellationRequested && !hadException && !integrityError && completed<planned;
}
#endif

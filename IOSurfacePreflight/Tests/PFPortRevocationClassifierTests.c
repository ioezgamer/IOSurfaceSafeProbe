#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../Sources/PFPortRevocationClassifier.h"

int main(void) {
    PFPortEvidence v={0};
    assert(PFPortClassify(v)==PF_PORT_UNAVAILABLE);
    v.symbolsAvailable=true;
    assert(PFPortClassify(v)==PF_PORT_BASELINE_FAILED);
    v.surfaceCreated=true;
    v.initialLookupValid=true;
    assert(PFPortClassify(v)==PF_PORT_INCONCLUSIVE);
    v.rightsDuplicated=true;
    v.lookupWithLastRightValid=true;
    v.invalidPortNameConfirmed=true;
    v.unrelatedPortTested=true;
    v.nullPortTested=true;
    assert(PFPortClassify(v)==PF_PORT_EXPECTED_REJECTION);
    v.revokedLookupReturnedSurface=true;
    assert(PFPortClassify(v)==PF_PORT_REVIEW_UNEXPECTED_SURFACE);
    v.revokedLookupReturnedSurface=false;
    v.unrelatedLookupReturnedSurface=true;
    assert(PFPortClassify(v)==PF_PORT_REVIEW_UNEXPECTED_SURFACE);
    v.unrelatedLookupReturnedSurface=false;
    v.nullLookupReturnedSurface=true;
    assert(PFPortClassify(v)==PF_PORT_REVIEW_UNEXPECTED_SURFACE);
    v.nullLookupReturnedSurface=false;
    v.invalidPortNameConfirmed=false;
    assert(PFPortClassify(v)==PF_PORT_INCONCLUSIVE);
    v.invalidPortNameConfirmed=true;
    v.lookupWithLastRightValid=false;
    assert(PFPortClassify(v)==PF_PORT_INCONCLUSIVE);
    assert(strcmp(PFPortVerdictName(PF_PORT_EXPECTED_REJECTION),"EXPECTED_REJECTION")==0);
    puts("PFPortRevocationClassifierTests PASS");
    return 0;
}

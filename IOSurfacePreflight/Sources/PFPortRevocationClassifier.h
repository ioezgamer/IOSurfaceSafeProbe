#ifndef PF_PORT_REVOCATION_CLASSIFIER_H
#define PF_PORT_REVOCATION_CLASSIFIER_H
#include <stdbool.h>

typedef enum {
    PF_PORT_UNAVAILABLE,
    PF_PORT_BASELINE_FAILED,
    PF_PORT_INCONCLUSIVE,
    PF_PORT_EXPECTED_REJECTION,
    PF_PORT_REVIEW_UNEXPECTED_SURFACE
} PFPortVerdict;

typedef struct {
    bool symbolsAvailable;
    bool surfaceCreated;
    bool rightsDuplicated;
    bool initialLookupValid;
    bool lookupWithLastRightValid;
    bool invalidPortNameConfirmed;
    bool revokedLookupReturnedSurface;
    bool unrelatedPortTested;
    bool unrelatedLookupReturnedSurface;
    bool nullPortTested;
    bool nullLookupReturnedSurface;
} PFPortEvidence;

static inline PFPortVerdict PFPortClassify(PFPortEvidence v) {
    if (!v.symbolsAvailable) return PF_PORT_UNAVAILABLE;
    if (!v.surfaceCreated || !v.initialLookupValid) return PF_PORT_BASELINE_FAILED;
    if (v.revokedLookupReturnedSurface ||
        v.unrelatedLookupReturnedSurface ||
        v.nullLookupReturnedSurface)
        return PF_PORT_REVIEW_UNEXPECTED_SURFACE;
    if (!v.rightsDuplicated || !v.lookupWithLastRightValid ||
        !v.invalidPortNameConfirmed || !v.unrelatedPortTested ||
        !v.nullPortTested)
        return PF_PORT_INCONCLUSIVE;
    return PF_PORT_EXPECTED_REJECTION;
}

static inline const char *PFPortVerdictName(PFPortVerdict v) {
    switch (v) {
        case PF_PORT_UNAVAILABLE: return "UNAVAILABLE";
        case PF_PORT_BASELINE_FAILED: return "BASELINE_FAILED";
        case PF_PORT_INCONCLUSIVE: return "INCONCLUSIVE";
        case PF_PORT_EXPECTED_REJECTION: return "EXPECTED_REJECTION";
        case PF_PORT_REVIEW_UNEXPECTED_SURFACE: return "REVIEW_UNEXPECTED_SURFACE";
    }
    return "UNKNOWN";
}
#endif

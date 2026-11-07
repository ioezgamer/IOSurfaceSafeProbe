#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Passive assessment of app-owned diagnostic snapshots. Produces a comparative
// report; never attempts to access, exploit or modify the iOS kernel.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *PFBuildSecurityResearchTriage(
    NSDictionary<NSString *, id> *currentForensicSnapshot,
    NSDictionary<NSString *, id> * _Nullable priorTriageReport
);

NS_ASSUME_NONNULL_END

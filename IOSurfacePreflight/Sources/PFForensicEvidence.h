#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Non-invasive evidence from the application's sandbox. These APIs never
// observe OSObject refcounts, kernel pointers, or a last-release event.
FOUNDATION_EXPORT void PFAppendForensicEvent(NSString *directory,
    NSString *sessionID, NSString *event, NSString *outcome);

FOUNDATION_EXPORT NSDictionary<NSString *, id> *PFBuildForensicSnapshot(
    NSString *directory, NSString *sessionID, NSString *device,
    NSString *systemVersion);

NS_ASSUME_NONNULL_END

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Offline analysis only: import a trace exported by an independently
// instrumented, authorized kernel-debug environment. iOS App Sandbox cannot
// record final OSObject releases or kernel notification pointer reads.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *PFAnalyzeInstrumentedKernelTrace(
    NSURL *fileURL
);

NS_ASSUME_NONNULL_END

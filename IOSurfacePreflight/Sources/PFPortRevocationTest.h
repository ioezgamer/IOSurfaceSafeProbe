#import <Foundation/Foundation.h>

// Single bounded verification of public IOSurface Mach send-right revocation.
// Never targets third-party surfaces, raw kernel addresses or private selectors.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *PFRunPortRevocationTest(void);

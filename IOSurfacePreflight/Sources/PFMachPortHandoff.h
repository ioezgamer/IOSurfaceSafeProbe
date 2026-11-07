#import <UIKit/UIKit.h>

// Performs an actual public IOSurface Mach-port lifetime handoff.
// Returns a structured report; on PASS returns a real rendered image.
// Runtime symbol checks make unsupported iOS configurations explicit.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *PFRunMachPortHandoff(UIImage * __autoreleasing *outputImage);

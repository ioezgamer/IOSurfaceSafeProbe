//
//  WorseQueryGroup.h
//  IOSurfaceSafeProbe
//
//  Reads App Groups from the app's signed entitlements at runtime,
//  so the correct group is used after re-signing.
//

#ifndef WorseQueryGroup_h
#define WorseQueryGroup_h

#import <Foundation/Foundation.h>

/// Returns the first usable App Group from this app's signed entitlements.
/// Each candidate is checked with containerURLForSecurityApplicationGroupIdentifier:.
NSString * _Nullable KMWorseQueryAppGroup(void);

/// Returns App Groups found in the signed entitlements for display/debugging.
NSArray<NSString *> * _Nullable KMWorseQuerySignatureGroups(void);

/// Clears the cached group so the next call re-reads from the signature.
void KMWorseQueryResetGroupCache(void);

#endif

//
//  WorseQueryGroup.m
//  IOSurfaceSafeProbe
//
//  Reads App Groups from the app's signed entitlements at runtime
//  using Security.framework (SecTaskCopyValueForEntitlement).
//  Falls back to hardcoded group for TrollStore installs where
//  the sideloader's runtime entitlements differ from embedded ones.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <dlfcn.h>
#include "WorseQueryGroup.h"

typedef void *SecTaskRef;
extern SecTaskRef SecTaskCreateFromSelf(CFAllocatorRef allocator);
extern CFTypeRef SecTaskCopyValueForEntitlement(SecTaskRef task, CFStringRef entitlement, CFErrorRef *error);

static NSString *const kSystemGroup = @"group.com.apple.mobilegestaltcache";
static NSString *const kHardcodedGroup = @"group.com.ioezgamer.cachewipe";

static NSString *_cachedGroup = nil;
static NSArray<NSString *> *_cachedSignatureGroups = nil;
static BOOL _cacheValid = NO;
static BOOL _usingSideloaderGroups = NO;

static BOOL _isSideloaderGroup(NSString *group) {
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"^group\\.[0-9a-f]{16}\\." options:0 error:nil];
    NSRange range = NSMakeRange(0, group.length);
    return [regex numberOfMatchesInString:group options:0 range:range] > 0;
}

static void _loadSignatureGroups(void) {
    if (_cacheValid) return;

    _cachedGroup = nil;
    _cachedSignatureGroups = nil;
    _usingSideloaderGroups = NO;

    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableArray<NSString *> *allGroups = [NSMutableArray array];

    // 1) Try SYSTEM group first — exists on every iOS device
    NSURL *systemContainer = [fm containerURLForSecurityApplicationGroupIdentifier:kSystemGroup];
    if (systemContainer) {
        NSLog(@"[WorseQueryGroup] System group OK: %@ -> %@", kSystemGroup, systemContainer.path);
        _cachedGroup = kSystemGroup;
        [allGroups addObject:kSystemGroup];
    } else {
        NSLog(@"[WorseQueryGroup] System group %@ not accessible", kSystemGroup);
    }

    // 2) Try custom hardcoded group (works when installed via TrollStore)
    NSURL *hardcodedContainer = [fm containerURLForSecurityApplicationGroupIdentifier:kHardcodedGroup];
    if (hardcodedContainer) {
        NSLog(@"[WorseQueryGroup] Hardcoded group OK: %@ -> %@", kHardcodedGroup, hardcodedContainer.path);
        if (!_cachedGroup) _cachedGroup = kHardcodedGroup;
        [allGroups addObject:kHardcodedGroup];
    }

    // 3) Read groups from code signature (includes FlareStore hex groups)
    SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
    if (task) {
        CFErrorRef error = NULL;
        CFTypeRef value = SecTaskCopyValueForEntitlement(task, CFSTR("com.apple.security.application-groups"), &error);
        CFRelease(task);
        if (error) { CFRelease(error); error = NULL; }

        if (value && CFGetTypeID(value) == CFArrayGetTypeID()) {
            NSArray *signedGroups = (__bridge_transfer NSArray *)value;
            NSLog(@"[WorseQueryGroup] Signed groups: %@", signedGroups);

            for (NSString *group in signedGroups) {
                if ([group isEqualToString:kSystemGroup]) continue;
                if ([group isEqualToString:kHardcodedGroup]) continue;
                if (_isSideloaderGroup(group)) {
                    _usingSideloaderGroups = YES;
                }
                NSURL *container = [fm containerURLForSecurityApplicationGroupIdentifier:group];
                if (container) {
                    [allGroups addObject:group];
                    if (!_cachedGroup) _cachedGroup = group;
                }
            }
        } else if (value) {
            CFRelease(value);
        }
    }

    NSLog(@"[WorseQueryGroup] Final groups (%lu): %@", (unsigned long)allGroups.count, allGroups);
    _cachedSignatureGroups = [allGroups copy];
    _cacheValid = YES;
}

NSString * _Nullable KMWorseQueryAppGroup(void) {
    _loadSignatureGroups();
    return _cachedGroup;
}

NSArray<NSString *> * _Nullable KMWorseQuerySignatureGroups(void) {
    _loadSignatureGroups();
    return _cachedSignatureGroups;
}

void KMWorseQueryResetGroupCache(void) {
    _cachedGroup = nil;
    _cachedSignatureGroups = nil;
    _cacheValid = NO;
    _usingSideloaderGroups = NO;
}

BOOL KMWorseQueryUsingSideloaderGroups(void) {
    _loadSignatureGroups();
    return _usingSideloaderGroups;
}

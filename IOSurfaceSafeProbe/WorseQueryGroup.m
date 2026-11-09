//
//  WorseQueryGroup.m
//  IOSurfaceSafeProbe
//
//  Reads App Groups from the app's signed entitlements at runtime
//  using Security.framework (SecTaskCopyValueForEntitlement).
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <dlfcn.h>
#include "WorseQueryGroup.h"

// SecTask functions may not be declared in public iOS SDK headers.
typedef void *SecTaskRef;
extern SecTaskRef SecTaskCreateFromSelf(CFAllocatorRef allocator);
extern CFTypeRef SecTaskCopyValueForEntitlement(SecTaskRef task, CFStringRef entitlement, CFErrorRef *error);

static NSString *_cachedGroup = nil;
static NSArray<NSString *> *_cachedSignatureGroups = nil;
static BOOL _cacheValid = NO;

static void _loadSignatureGroups(void) {
    if (_cacheValid) return;

    _cachedGroup = nil;
    _cachedSignatureGroups = nil;

    SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
    if (!task) {
        NSLog(@"[WorseQueryGroup] SecTaskCreateFromSelf failed");
        _cacheValid = YES;
        return;
    }

    CFErrorRef error = NULL;
    CFTypeRef value = SecTaskCopyValueForEntitlement(
        task,
        CFSTR("com.apple.security.application-groups"),
        &error
    );
    CFRelease(task);

    if (error) {
        NSLog(@"[WorseQueryGroup] SecTaskCopyValueForEntitlement error: %@", (__bridge NSError *)error);
        CFRelease(error);
        _cacheValid = YES;
        return;
    }

    if (!value) {
        NSLog(@"[WorseQueryGroup] No application-groups entitlement in signature");
        _cacheValid = YES;
        return;
    }

    if (CFGetTypeID(value) != CFArrayGetTypeID()) {
        NSLog(@"[WorseQueryGroup] Unexpected entitlement type");
        CFRelease(value);
        _cacheValid = YES;
        return;
    }

    NSArray *groups = (__bridge_transfer NSArray *)value;
    _cachedSignatureGroups = groups;

    NSLog(@"[WorseQueryGroup] Signature groups: %@", groups);

    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *group in groups) {
        NSURL *container = [fm containerURLForSecurityApplicationGroupIdentifier:group];
        if (container) {
            _cachedGroup = group;
            NSLog(@"[WorseQueryGroup] Using group: %@ (container: %@)", group, container.path);
            break;
        } else {
            NSLog(@"[WorseQueryGroup] Group %@ has no container, skipping", group);
        }
    }

    if (!_cachedGroup) {
        NSLog(@"[WorseQueryGroup] No usable App Group found in %lu signed groups", (unsigned long)groups.count);
    }

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
}

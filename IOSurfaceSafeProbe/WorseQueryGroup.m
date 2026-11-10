//
//  WorseQueryGroup.m
//  IOSurfaceSafeProbe
//
//  Reads App Groups available to the process via containerURL checks.
//  No Security.framework — matches GestaltEdit's approach.
//

#import <Foundation/Foundation.h>
#include <stdio.h>
#include "WorseQueryGroup.h"

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

    // 1) Try SYSTEM group first
    NSURL *systemContainer = [fm containerURLForSecurityApplicationGroupIdentifier:kSystemGroup];
    if (systemContainer) {
        printf("[Group] System OK: %s -> %s\n", kSystemGroup.UTF8String, systemContainer.path.UTF8String);
        fflush(stdout);
        _cachedGroup = kSystemGroup;
        [allGroups addObject:kSystemGroup];
    } else {
        printf("[Group] System %s not accessible\n", kSystemGroup.UTF8String);
        fflush(stdout);
    }

    // 2) Try custom hardcoded group
    NSURL *hardcodedContainer = [fm containerURLForSecurityApplicationGroupIdentifier:kHardcodedGroup];
    if (hardcodedContainer) {
        printf("[Group] Hardcoded OK: %s -> %s\n", kHardcodedGroup.UTF8String, hardcodedContainer.path.UTF8String);
        fflush(stdout);
        if (!_cachedGroup) _cachedGroup = kHardcodedGroup;
        [allGroups addObject:kHardcodedGroup];
    }

    // 3) Read groups from embedded entitlements plist
    NSString *entPath = [[NSBundle mainBundle] pathForResource:@"embedded" ofType:@"mobileprovision"];
    NSDictionary *entitlements = nil;

    // Try reading entitlements from the code directory
    NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
    NSString *entPlistPath = [bundlePath stringByAppendingPathComponent:@"archived-expanded-entitlements.xcent"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:entPlistPath]) {
        entPlistPath = [bundlePath stringByAppendingPathComponent:@"Entitlements.plist"];
    }
    NSData *entData = [NSData dataWithContentsOfFile:entPlistPath];
    if (entData) {
        entitlements = [NSPropertyListSerialization propertyListWithData:entData options:NSPropertyListImmutable format:nil error:nil];
    }

    NSArray *embeddedGroups = entitlements[@"com.apple.security.application-groups"];
    if (embeddedGroups) {
        printf("[Group] Embedded groups: %lu\n", (unsigned long)embeddedGroups.count);
        fflush(stdout);
        for (NSString *group in embeddedGroups) {
            if ([group isEqualToString:kSystemGroup]) continue;
            if ([group isEqualToString:kHardcodedGroup]) continue;
            if (_isSideloaderGroup(group)) {
                _usingSideloaderGroups = YES;
            }
            NSURL *container = [fm containerURLForSecurityApplicationGroupIdentifier:group];
            if (container) {
                printf("[Group] Embedded group OK: %s\n", group.UTF8String);
                fflush(stdout);
                [allGroups addObject:group];
                if (!_cachedGroup) _cachedGroup = group;
            }
        }
    }

    // 4) Fallback: scan for FlareStore-style hex groups by checking known patterns
    if (allGroups.count == 0) {
        printf("[Group] No groups found via entitlements, trying bundle ID patterns\n");
        fflush(stdout);
        NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier] ?: @"com.unknown";
        NSString *guessGroup = [NSString stringWithFormat:@"group.%@", bundleID];
        NSURL *guessContainer = [fm containerURLForSecurityApplicationGroupIdentifier:guessGroup];
        if (guessContainer) {
            printf("[Group] Bundle group OK: %s\n", guessGroup.UTF8String);
            fflush(stdout);
            [allGroups addObject:guessGroup];
            if (!_cachedGroup) _cachedGroup = guessGroup;
        }
    }

    printf("[Group] Final (%lu): ", (unsigned long)allGroups.count);
    for (NSString *g in allGroups) { printf("%s ", g.UTF8String); }
    printf("\n");
    fflush(stdout);

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

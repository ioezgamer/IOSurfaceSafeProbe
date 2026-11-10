//
//  WorseQueryGroup.m
//  IOSurfaceSafeProbe
//
//  Reads App Groups from the kernel's entitlements via csops syscall.
//  No Security.framework needed — reads the same data SecTask would.
//

#import <Foundation/Foundation.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include "WorseQueryGroup.h"

#define CS_OPS_ENTITLEMENTS_BLOB 7

struct cs_blob {
    uint32_t magic;
    uint32_t length;
};

extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

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

static NSArray *_readEntitlementGroups(void) {
    // Read entitlements blob from kernel via csops
    size_t bufsize = 65536;
    void *buf = malloc(bufsize);
    if (!buf) return nil;

    int ret = csops(getpid(), CS_OPS_ENTITLEMENTS_BLOB, buf, bufsize);
    if (ret != 0) {
        printf("[Group] csops failed: %d\n", ret);
        fflush(stdout);
        free(buf);
        return nil;
    }

    struct cs_blob *blob = (struct cs_blob *)buf;
    uint32_t magic = ntohl(blob->magic);
    uint32_t length = ntohl(blob->length);

    if (magic != 0xFADE7171 || length <= sizeof(struct cs_blob) || length > bufsize) {
        printf("[Group] csops blob invalid magic=0x%x len=%u\n", magic, length);
        fflush(stdout);
        free(buf);
        return nil;
    }

    // XML plist starts after the 8-byte header
    NSData *plistData = [NSData dataWithBytes:(uint8_t *)buf + sizeof(struct cs_blob)
                                       length:length - sizeof(struct cs_blob)];
    free(buf);

    NSDictionary *entitlements = [NSPropertyListSerialization propertyListWithData:plistData
                                                                          options:NSPropertyListImmutable
                                                                           format:nil
                                                                            error:nil];
    if (!entitlements) {
        printf("[Group] csops plist parse failed\n");
        fflush(stdout);
        return nil;
    }

    NSArray *groups = entitlements[@"com.apple.security.application-groups"];
    printf("[Group] csops found %lu groups\n", (unsigned long)(groups ? groups.count : 0));
    fflush(stdout);
    return groups;
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

    // 3) Read groups from kernel entitlements via csops (includes FlareStore hex groups)
    NSArray *csopsGroups = _readEntitlementGroups();
    if (csopsGroups) {
        for (NSString *group in csopsGroups) {
            if ([group isEqualToString:kSystemGroup]) continue;
            if ([group isEqualToString:kHardcodedGroup]) continue;
            if (_isSideloaderGroup(group)) {
                _usingSideloaderGroups = YES;
            }
            NSURL *container = [fm containerURLForSecurityApplicationGroupIdentifier:group];
            if (container) {
                printf("[Group] csops group OK: %s\n", group.UTF8String);
                fflush(stdout);
                [allGroups addObject:group];
                if (!_cachedGroup) _cachedGroup = group;
            } else {
                printf("[Group] csops group no container: %s\n", group.UTF8String);
                fflush(stdout);
            }
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

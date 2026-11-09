//
//  worse_query.h
//  IOSurfaceSafeProbe
//
//  Based on worse_query by Taj C (forcequit) - GPL-3.0
//

#ifndef worse_query_h
#define worse_query_h

#import <Foundation/Foundation.h>
#include <stdint.h>
#include <stdbool.h>

int64_t worse_query(NSString *path, NSString *group, bool alt_flags, bool create_dir);
void worse_query_release(int64_t handle);

#endif

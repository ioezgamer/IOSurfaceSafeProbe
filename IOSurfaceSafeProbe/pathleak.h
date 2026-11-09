//
//  pathleak.h
//  IOSurfaceSafeProbe
//
//  Based on worse_query by Taj C (forcequit) - GPL-3.0
//

#ifndef pathleak_h
#define pathleak_h

#import <Foundation/Foundation.h>

NSArray<NSString *> *pathleak(NSString *filter, uint64_t max_inode);

#endif

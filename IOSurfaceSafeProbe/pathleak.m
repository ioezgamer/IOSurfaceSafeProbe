//
//  pathleak.m
//  IOSurfaceSafeProbe
//
//  Based on worse_query by Taj C (forcequit) - GPL-3.0
//

#import <Foundation/Foundation.h>
#include <sys/fsgetpath.h>
#include <sys/mount.h>

NSArray<NSString *> *pathleak(NSString *path, uint64_t max_inode) {
    if (path.length == 0 || max_inode < 1) return nil;
    NSString *dir = path;
    while (dir.length > 1 && [dir hasSuffix: @"/"]) {
        dir = [dir substringToIndex: dir.length - 1];
    }
    
    struct statfs sfs;
    if (statfs(dir.fileSystemRepresentation, &sfs) != 0) return nil;
    fsid_t fsid = sfs.f_fsid;
    
    char prefix[PATH_MAX];
    if (![dir getFileSystemRepresentation: prefix maxLength: sizeof(prefix)]) return nil;
    size_t prefix_length = strlen(prefix);
    if (prefix_length == 1 && prefix[0] == '/') prefix_length = 0;
    
    NSFileManager *files = [NSFileManager defaultManager];
    NSMutableArray<NSString *> *result = [NSMutableArray array];
    char buffer[PATH_MAX];
    
    for (uint64_t inode = 1; inode <= max_inode; inode++) {
        ssize_t n = fsgetpath(buffer, sizeof(buffer), &fsid, inode);
        if (n <= 0) continue;
        
        if (strncmp(buffer, prefix, prefix_length) != 0) continue;
        if (buffer[prefix_length] != '/') continue;
        if (strchr(buffer + prefix_length + 1, '/')) continue;
        
        NSString *string = [files stringWithFileSystemRepresentation: buffer length: strlen(buffer)];
        if (string) [result addObject: string];
    }
    return result;
}

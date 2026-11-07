#import "PFForensicEvidence.h"
#import <CommonCrypto/CommonDigest.h>
#import <math.h>

// The collector intentionally consumes only files owned by this application.
// None of the results are presented as observations of a kernel object.
static NSString *PFISODate(void) {
    NSISO8601DateFormatter *fmt = [NSISO8601DateFormatter new];
    fmt.formatOptions = NSISO8601DateFormatWithInternetDateTime |
                        NSISO8601DateFormatWithFractionalSeconds;
    return [fmt stringFromDate:[NSDate date]];
}

static NSString *PFCSVValue(NSString *value) {
    NSString *s = value ?: @"";
    s = [s stringByReplacingOccurrencesOfString:@"," withString:@" "];
    s = [s stringByReplacingOccurrencesOfString:@"\r" withString:@" "];
    return [s stringByReplacingOccurrencesOfString:@"\n" withString:@" "];
}

void PFAppendForensicEvent(NSString *directory, NSString *sessionID,
                           NSString *event, NSString *outcome) {
    if (!directory.length) return;
    NSString *file = [directory stringByAppendingPathComponent:
                      @"IOSurfaceForensicEvents-v19_10.csv"];
    NSString *header = @"timestamp,session,event,system_uptime_seconds,outcome,source\n";
    NSString *line = [NSString stringWithFormat:@"%@,%@,%@,%.6f,%@,user_space\n",
        PFISODate(), PFCSVValue(sessionID), PFCSVValue(event),
        [NSProcessInfo processInfo].systemUptime, PFCSVValue(outcome)];
    @synchronized([NSFileManager defaultManager]) {
        NSData *before = [NSData dataWithContentsOfFile:file];
        NSMutableData *out = before && before.length < 128 * 1024
            ? [before mutableCopy]
            : [[header dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
        [out appendData:[line dataUsingEncoding:NSUTF8StringEncoding]];
        [out writeToFile:file options:NSDataWritingAtomic error:NULL];
    }
}

static NSDictionary *PFReadJSON(NSString *directory, NSString *filename) {
    NSString *path = [directory stringByAppendingPathComponent:filename];
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data || data.length > 1024 * 1024) return nil;
    id object = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    return [object isKindOfClass:[NSDictionary class]] ? object : nil;
}

static NSArray<NSArray<NSString *> *> *PFReadCSV(NSString *directory,
                                                NSString *filename) {
    NSString *path = [directory stringByAppendingPathComponent:filename];
    NSDictionary *attrs = [[NSFileManager defaultManager]
        attributesOfItemAtPath:path error:NULL];
    if (!attrs || [attrs fileSize] > 512 * 1024) return @[];
    NSString *text = [NSString stringWithContentsOfFile:path
        encoding:NSUTF8StringEncoding error:NULL];
    if (!text.length) return @[];
    NSMutableArray<NSArray<NSString *> *> *records = [NSMutableArray new];
    NSArray<NSString *> *lines = [text componentsSeparatedByCharactersInSet:
        [NSCharacterSet newlineCharacterSet]];
    for (NSString *line in lines) {
        if (!line.length) continue;
        [records addObject:[line componentsSeparatedByString:@","]];
    }
    return records;
}

static NSArray<NSDictionary *> *PFSourceManifest(NSString *directory) {
    NSArray<NSString *> *names = @[
        @"IOSurfaceBootMonitor-checkpoint.json",
        @"IOSurfaceBootMonitor-trace.csv",
        @"IOSurfaceSameClient-checkpoint.json",
        @"IOSurfaceSameClient-trace.csv",
        @"IOSurfacePortRevocation-v19_9.json",
        @"IOSurfaceAsyncObserver-checkpoint.json",
        @"IOSurfaceAsyncObserver-trace.csv",
        @"IOSurfaceControlledClose-checkpoint.json",
        @"IOSurfaceIPCControls-checkpoint.json",
        @"IOSurfaceForensicEvents-v19_10.csv"
    ];
    NSMutableArray<NSDictionary *> *files = [NSMutableArray new];
    for (NSString *name in names) {
        NSString *path = [directory stringByAppendingPathComponent:name];
        NSData *data = [NSData dataWithContentsOfFile:path
                                             options:NSDataReadingMappedIfSafe error:NULL];
        if (!data) continue;
        unsigned char digest[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
        NSMutableString *hex = [NSMutableString new];
        for (NSUInteger i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
            [hex appendFormat:@"%02x", digest[i]];
        [files addObject:@{@"name":name, @"size_bytes":@(data.length),
                           @"sha256":hex}];
    }
    return files;
}

static NSDictionary *PFBootSummary(NSString *directory) {
    NSArray<NSArray<NSString *> *> *rows =
        PFReadCSV(directory, @"IOSurfaceBootMonitor-trace.csv");
    NSMutableDictionary<NSString *, NSNumber *> *statuses = [NSMutableDictionary new];
    NSMutableSet<NSString *> *sessions = [NSMutableSet new];
    NSUInteger events = 0;
    NSUInteger corruptRows = 0;
    for (NSUInteger i = 1; i < rows.count; i++) {
        NSArray<NSString *> *r = rows[i];
        if (r.count < 8) { corruptRows++; continue; }
        NSString *status = r[6];
        if (r[1].length) [sessions addObject:r[1]];
        statuses[status] = @([statuses[status] unsignedIntegerValue] + 1);
        events++;
    }
    NSDictionary *checkpoint =
        PFReadJSON(directory, @"IOSurfaceBootMonitor-checkpoint.json");
    return @{
        @"event_rows":@(events),
        @"session_count":@(sessions.count),
        @"invalid_rows":@(corruptRows),
        @"status_counts":statuses,
        @"latest_public_status":checkpoint[@"status"] ?: NSNull.null,
        @"kernel_panic_proven_by_app":@NO,
        @"interpretation":@"Uptime comparison is not kernel object lifetime evidence."
    };
}

static NSDictionary *PFSameClientSummary(NSString *directory) {
    NSArray<NSArray<NSString *> *> *rows =
        PFReadCSV(directory, @"IOSurfaceSameClient-trace.csv");
    NSUInteger observed = 0;
    NSUInteger withOverlap = 0;
    NSUInteger invalidRows = 0;
    double longestOverlap = 0.0;
    NSMutableArray *samples = [NSMutableArray new];
    for (NSUInteger i = 1; i < rows.count; i++) {
        NSArray<NSString *> *r = rows[i];
        if (r.count < 12) { invalidRows++; continue; }
        double callStart = [r[7] doubleValue], callEnd = [r[8] doubleValue];
        double closeStart = [r[9] doubleValue], closeEnd = [r[10] doubleValue];
        if (!isfinite(callStart) || !isfinite(callEnd) ||
            !isfinite(closeStart) || !isfinite(closeEnd) ||
            callEnd < callStart || closeEnd < closeStart) {
            invalidRows++;
            continue;
        }
        observed++;
        double overlap = fmax(0, fmin(callEnd,closeEnd) - fmax(callStart,closeStart));
        if (overlap > 0) withOverlap++;
        longestOverlap = fmax(longestOverlap, overlap);
        if (samples.count < 20) {
            [samples addObject:@{@"trial":r[2],@"call_result":r[5],
                                 @"close_result":r[6],
                                 @"overlap_microseconds":@(overlap)}];
        }
    }
    return @{
        @"trials":@(observed),
        @"overlapping_trails_user_space":@(withOverlap),
        @"max_overlap_microseconds":@(longestOverlap),
        @"invalid_rows":@(invalidRows),
        @"samples":samples,
        @"kernel_client_identity_observed":@NO,
        @"interpretation":@"Overlapping user-space intervals do not prove an overlapping kernel callback."
    };
}

NSDictionary<NSString *, id> *PFBuildForensicSnapshot(
    NSString *directory, NSString *sessionID, NSString *device,
    NSString *systemVersion) {
    NSDictionary *port = PFReadJSON(directory,
        @"IOSurfacePortRevocation-v19_9.json");
    NSDictionary *async = PFReadJSON(directory,
        @"IOSurfaceAsyncObserver-checkpoint.json");
    NSDictionary *close = PFReadJSON(directory,
        @"IOSurfaceControlledClose-checkpoint.json");
    return @{
        @"schema":@"iosurface-preflight-forensic-v19.10",
        @"snapshot_id":[NSUUID UUID].UUIDString,
        @"created_utc":PFISODate(),
        @"device_model":device ?: @"UNKNOWN",
        @"ios_version":systemVersion ?: @"UNKNOWN",
        @"session_id":sessionID ?: @"UNKNOWN",
        @"app_uptime_seconds":@([NSProcessInfo processInfo].systemUptime),
        @"observation_scope":@"app_sandbox_public_APIs",
        @"sources":PFSourceManifest(directory),
        @"boot_monitor":PFBootSummary(directory),
        @"same_client":PFSameClientSummary(directory),
        @"mach_revocation":@{
            @"available":@(port!=nil),
            @"verdict":port[@"verdict"] ?: NSNull.null,
            @"revoked_port_lookup":port[@"revoked_port_lookup"] ?: NSNull.null,
            @"app_reported_uaf":port[@"use_after_free_proven"] ?: NSNull.null,
            @"interpretation":@"Port revocation does not prove last release of IOSurfaceRootUserClient."
        },
        @"async_observer":@{
            @"available":@(async!=nil),
            @"status":async[@"status"] ?: NSNull.null,
            @"messages_received":async[@"messages"] ?: NSNull.null
        },
        @"controlled_close":@{
            @"available":@(close!=nil),
            @"status":close[@"status"] ?: NSNull.null,
            @"interpretation":@"IOServiceClose does not prove final OSObject release."
        },
        @"kernel_lifetime_correlator":@{
            @"client_generation_identity_available":@NO,
            @"kernel_last_release_observed":@NO,
            @"notification_survived_final_release_observed":@NO,
            @"post_free_dispatch_observed":@NO,
            @"uaf_proven":@NO,
            @"status":@"NOT_ESTABLISHED_WITH_PUBLIC_IOS_APIS",
            @"limitations":@"iOS app sandbox cannot directly inspect kernel refcounts or a final OSObject release."
        }
    };
}

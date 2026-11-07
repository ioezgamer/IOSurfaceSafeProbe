#import <Foundation/Foundation.h>
#import "PFForensicEvidence.h"
#import <math.h>

static void writeText(NSString *directory, NSString *name, NSString *value) {
    NSString *path=[directory stringByAppendingPathComponent:name];
    NSCAssert([value writeToFile:path atomically:YES
        encoding:NSUTF8StringEncoding error:NULL], @"fixture write failed");
}

int main(void) {
    @autoreleasepool {
        NSString *dir=[NSTemporaryDirectory() stringByAppendingPathComponent:
            [NSString stringWithFormat:@"PFForensicEvidence-%@",
                [NSUUID UUID].UUIDString]];
        NSCAssert([[NSFileManager defaultManager] createDirectoryAtPath:dir
            withIntermediateDirectories:YES attributes:nil error:NULL],
            @"cannot create fixture directory");

        // 1. Empty source directory must not claim a kernel after-free.
        NSDictionary *empty=PFBuildForensicSnapshot(dir,@"S1",@"iPhone14,3",@"27.0");
        NSCAssert([empty[@"kernel_lifetime_correlator"][@"uaf_proven"] boolValue]==NO,
            @"missing evidence cannot mean a UAF");
        NSCAssert([empty[@"sources"] count]==0,@"empty manifest");

        // 2. App-only observations must remain explicitly classified as such.
        PFAppendForensicEvent(dir,@"S1",@"APP_ACTIVE",@"OK");
        NSDictionary *observation=PFBuildForensicSnapshot(dir,@"S1",@"iPhone14,3",@"27.0");
        NSCAssert([observation[@"sources"] count]==1,@"app observation missing");
        NSCAssert([observation[@"kernel_lifetime_correlator"][@"kernel_last_release_observed"]
                   boolValue]==NO,@"app observation not a kernel release");

        // 3. Exactly 174.167 microseconds overlap in an earlier same-client trace.
        writeText(dir,@"IOSurfaceSameClient-trace.csv",
            @"index,run,trial,open_kr,port_kr,call_kr,close_kr,call_start_us,call_end_us,close_start_us,close_end_us,user_space_overlap\n"
             @"0,R1,1,0x00000000,0x00000000,0x10000003,0x00000000,0.0,537.833,21.458,195.625,1\n");
        NSDictionary *model=PFBuildForensicSnapshot(dir,@"S1",@"iPhone14,3",@"27.0");
        NSCAssert([model[@"same_client"][@"trials"] integerValue]==1,@"trial count");
        NSCAssert(fabs([model[@"same_client"][@"max_overlap_microseconds"]
                    doubleValue]-174.167)<0.001,@"overlap mismatch");
        NSCAssert([model[@"same_client"][@"samples"][0][@"call_result"]
                    isEqualToString:@"0x10000003"],@"API outcome");

        // 4. A normal port revocation report must not imply UAF or kernel RW.
        writeText(dir,@"IOSurfacePortRevocation-v19_9.json",
            @"{\"verdict\":\"EXPECTED_REJECTION\","
             @"\"use_after_free_proven\":false,"
             @"\"revoked_port_lookup\":\"NULL_REJECTED\"}");
        NSDictionary *ports=PFBuildForensicSnapshot(dir,@"S1",@"iPhone14,3",@"27.0");
        NSCAssert([ports[@"mach_revocation"][@"available"] boolValue],@"port report missing");
        NSCAssert([ports[@"mach_revocation"][@"verdict"]
                    isEqualToString:@"EXPECTED_REJECTION"],@"port outcome mismatch");
        NSCAssert([ports[@"kernel_lifetime_correlator"][@"post_free_dispatch_observed"]
                    boolValue]==NO,@"no post-free dispatch observed");

        // 5. Check manifest SHA-256 lengths and user-space boot event count.
        writeText(dir,@"IOSurfaceBootMonitor-trace.csv",
            @"timestamp,session,event,uptime_seconds,boot_epoch_seconds,previous_uptime_seconds,status,checkpoint_saved\n"
             @"t1,S1,DID_BECOME_ACTIVE,100,1,99,NO_UPTIME_ROLLBACK_OBSERVED,1\n"
             @"t2,S1,DID_ENTER_BACKGROUND,101,1,100,NO_UPTIME_ROLLBACK_OBSERVED,1\n");
        NSDictionary *full=PFBuildForensicSnapshot(dir,@"S1",@"iPhone14,3",@"27.0");
        NSCAssert([full[@"boot_monitor"][@"event_rows"] integerValue]==2,@"boot event count");
        for (NSDictionary *source in full[@"sources"])
            NSCAssert([source[@"sha256"] length]==64,@"sha256 digest incorrect");
        NSCAssert([NSJSONSerialization isValidJSONObject:full],@"not JSON safe");
        [[NSFileManager defaultManager] removeItemAtPath:dir error:NULL];
        puts("PFForensicEvidence: 5/5 PASS");
    }
    return 0;
}

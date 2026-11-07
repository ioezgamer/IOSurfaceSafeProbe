#import <Foundation/Foundation.h>
#import "PFSecurityResearchTriage.h"

static void check(BOOL condition,NSString *description) {
    if (!condition) {
        fprintf(stderr,"TEST FAILURE: %s\n",description.UTF8String);
        abort();
    }
}
static NSDictionary *fixture(NSString *hash,NSUInteger bootEvents,
                             BOOL callSucceeded) {
    return @{
        @"snapshot_id":@"snapshot-device-1",
        @"sources":@[
            @{@"name":@"IOSurfaceSameClient-trace.csv",@"sha256":hash},
            @{@"name":@"IOSurfaceBootMonitor-trace.csv",
              @"sha256":@"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
        ],
        @"boot_monitor":@{
            @"event_rows":@(bootEvents),
            @"status_counts":@{@"NO_UPTIME_ROLLBACK_OBSERVED":@(bootEvents)}
        },
        @"same_client":@{
            @"trials":@1, @"successful_api_calls":@(callSucceeded?1:0),
            @"overlapping_trails_user_space":@1, @"invalid_rows":@0,
            @"max_overlap_microseconds":@174.167,
            @"samples":@[
                @{@"call_result":callSucceeded?@"0x00000000":@"0x10000003",
                  @"close_result":@"0x00000000",
                  @"overlap_microseconds":@174.167}
            ]
        },
        @"mach_revocation":@{
            @"available":@YES,@"verdict":@"EXPECTED_REJECTION"
        },
        @"async_observer":@{@"available":@YES,@"messages_received":@0},
        @"kernel_lifetime_correlator":@{@"uaf_proven":@NO}
    };
}
static BOOL hasFinding(NSDictionary *report,NSString *code) {
    for(NSDictionary *item in report[@"findings"])
        if ([item[@"code"] isEqualToString:code]) return YES;
    return NO;
}
int main(void) {
    @autoreleasepool {
        // 1. Empty input must still produce valid JSON and never claim kernel access.
        NSDictionary *empty=PFBuildSecurityResearchTriage(@{},nil);
        check([empty[@"kernel_evidence"][@"uaf_proven"] boolValue]==NO,
              @"empty snapshot cannot prove UAF");
        check([NSJSONSerialization isValidJSONObject:empty],@"JSON output");

        // 2. Real device pattern: rejected RPC and 174.167us overlap.
        NSString *hashA=@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        NSString *hashB=@"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        NSDictionary *initial=PFBuildSecurityResearchTriage(
            fixture(hashA,122,NO),nil);
        check([initial[@"same_client_triage"][@"classification"]
            isEqualToString:@"USER_SPACE_OVERLAP_WITH_REJECTED_CALLS"],
            @"rejected call should not become a successful registration");
        check([initial[@"same_client_triage"][@"accepted_rpc_count"]
            integerValue]==0,@"no successful call");
        check([initial[@"same_client_triage"][@"distinct_outcomes"]
            integerValue]==1,@"stable outcome fingerprint");
        check(hasFinding(initial,@"REJECTED_RPC_WITH_USER_SPACE_OVERLAP"),
              @"explain user-space overlap");
        check(![initial[@"change_analysis"][@"has_previous_report"] boolValue],
              @"first capture has no baseline");

        // 3. Same source set must be detected and not presented as novelty.
        NSDictionary *same=PFBuildSecurityResearchTriage(
            fixture(hashA,122,NO),initial);
        check([same[@"change_analysis"][@"identical_source_set"] boolValue],
              @"repeated capture should be identical");
        check([same[@"change_analysis"][@"new_boot_monitor_events"]
              integerValue]==0,@"no new events");
        check([same[@"change_analysis"][@"modified_sources"] count]==0,
              @"no modified sources");

        // 4. Changed hashes and cumulative events must be reflected, not guessed.
        NSDictionary *changed=PFBuildSecurityResearchTriage(
            fixture(hashB,130,NO),initial);
        check([changed[@"change_analysis"][@"modified_sources"] count]==1,
              @"only one file modified");
        check([changed[@"change_analysis"][@"new_boot_monitor_events"]
              integerValue]==8,@"eight cumulative new events");

        // 5. A successful API response remains only a review finding, NOT a UAF.
        NSDictionary *accepted=PFBuildSecurityResearchTriage(
            fixture(hashB,130,YES),initial);
        check([accepted[@"same_client_triage"][@"classification"]
            isEqualToString:@"USER_SPACE_OVERLAP_WITH_API_SUCCESS"],
            @"success classification");
        check(hasFinding(accepted,@"APP_SIDE_OVERLAP_WITH_SUCCESS"),
              @"successful response is review candidate");
        check(![accepted[@"kernel_evidence"][@"uaf_proven"] boolValue],
              @"success cannot prove kernel UAF");

        // 6. Malformed rows and unexpected revocation deserve distinct labels.
        NSMutableDictionary *data=[fixture(hashB,130,NO) mutableCopy];
        NSMutableDictionary *sc=[data[@"same_client"] mutableCopy];
        sc[@"invalid_rows"]=@2; data[@"same_client"]=sc;
        data[@"mach_revocation"]=@{@"available":@YES,
                                   @"verdict":@"REVIEW_UNEXPECTED_SURFACE"};
        data[@"async_observer"]=@{@"messages_received":@1};
        NSDictionary *warnings=PFBuildSecurityResearchTriage(data,initial);
        check(hasFinding(warnings,@"TRACE_ROWS_REJECTED"),
              @"data-quality finding");
        check(hasFinding(warnings,@"MACH_REVOCATION_UNEXPECTED"),
              @"revocation finding");
        check(hasFinding(warnings,@"ASYNC_MESSAGE_DELIVERED"),
              @"async is not kernel after-free evidence");

        // 7. A changed baseline can reflect rotation, not a proven panic.
        data[@"boot_monitor"]=@{
            @"event_rows":@12,
            @"status_counts":@{@"UPTIME_ROLLBACK_OBSERVED":@1}
        };
        NSDictionary *reset=PFBuildSecurityResearchTriage(data,initial);
        check(hasFinding(reset,@"BOOT_MONITOR_COUNTER_RESET"),
              @"trace rotation warning");
        check(hasFinding(reset,@"UPTIME_ROLLBACK_REPORT"),
              @"public uptime warning");
        check([reset[@"change_analysis"][@"boot_trace_counter_reset"]
              boolValue],@"reset classification");

        // 8. Even malicious synthetic flags must never authenticate kernel facts.
        data[@"kernel_lifetime_correlator"]=@{
            @"kernel_last_release_observed":@YES,
            @"post_free_dispatch_observed":@YES,
            @"uaf_proven":@YES
        };
        NSDictionary *claims=PFBuildSecurityResearchTriage(data,initial);
        check([claims[@"kernel_evidence"][@"last_release_claim"]
            isEqualToString:@"DECLARED_BY_SNAPSHOT_NOT_VERIFIED"],
            @"unverified last release");
        check(![claims[@"kernel_evidence"][@"authentic_kernel_events_observed"]
            boolValue],@"never authenticate imported claim");
        check(![claims[@"kernel_evidence"][@"kernel_privileges_acquired"]
            boolValue],@"no escalation from parser");

        // 9. If a manifest source disappears, report its name once.
        NSMutableDictionary *shortened=[fixture(hashA,123,NO) mutableCopy];
        shortened[@"sources"]=@[];
        NSDictionary *missing=PFBuildSecurityResearchTriage(shortened,initial);
        check([missing[@"change_analysis"][@"removed_sources"] count]==2,
              @"missing source detection");

        puts("PFSecurityResearchTriage: 9/9 PASS");
    }
    return 0;
}

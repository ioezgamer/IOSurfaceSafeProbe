#import "PFSecurityResearchTriage.h"

static NSDictionary *PFRTDict(id value) {
    return [value isKindOfClass:NSDictionary.class] ? value : @{};
}
static NSArray *PFRTArray(id value) {
    return [value isKindOfClass:NSArray.class] ? value : @[];
}
static NSString *PFRTString(id value) {
    return [value isKindOfClass:NSString.class] ? value : @"";
}
static NSUInteger PFRTCount(id value) {
    if (![value isKindOfClass:NSNumber.class]) return 0;
    NSInteger x=[value integerValue];
    return x>0 ? (NSUInteger)x : 0;
}
static NSString *PFRTDate(void) {
    NSISO8601DateFormatter *formatter=[NSISO8601DateFormatter new];
    formatter.formatOptions=NSISO8601DateFormatWithInternetDateTime |
                            NSISO8601DateFormatWithFractionalSeconds;
    return [formatter stringFromDate:[NSDate date]];
}
static NSDictionary<NSString *,NSString *> *PFRTDigests(NSArray *manifest) {
    NSMutableDictionary *digests=[NSMutableDictionary new];
    for (id entry in manifest) {
        NSDictionary *item=PFRTDict(entry);
        NSString *name=PFRTString(item[@"name"]);
        NSString *sha=PFRTString(item[@"sha256"]);
        if (name.length && sha.length==64 && !digests[name])
            digests[name]=sha;
    }
    return [digests copy];
}
static NSDictionary *PFRTFinding(NSString *code,NSString *type,
                                 NSString *description) {
    return @{@"code":code,@"type":type,@"description":description};
}

NSDictionary<NSString *, id> *PFBuildSecurityResearchTriage(
    NSDictionary<NSString *, id> *currentForensicSnapshot,
    NSDictionary<NSString *, id> *priorTriageReport) {

    NSDictionary *snapshot=PFRTDict(currentForensicSnapshot);
    NSDictionary *same=PFRTDict(snapshot[@"same_client"]);
    NSDictionary *boot=PFRTDict(snapshot[@"boot_monitor"]);
    NSDictionary *observer=PFRTDict(snapshot[@"async_observer"]);
    NSDictionary *revocation=PFRTDict(snapshot[@"mach_revocation"]);
    NSDictionary *kernel=PFRTDict(snapshot[@"kernel_lifetime_correlator"]);
    NSDictionary *sourceHashes=PFRTDigests(PFRTArray(snapshot[@"sources"]));

    NSDictionary *prior=PFRTDict(priorTriageReport);
    BOOL havePrior=[PFRTString(prior[@"schema"]) isEqualToString:
                    @"iosurface-security-research-triage-v19.13"];
    NSDictionary *oldHashes=havePrior ?
        PFRTDict(prior[@"source_hashes"]):@{};
    NSMutableArray *changed=[NSMutableArray new];
    NSMutableArray *added=[NSMutableArray new];
    NSMutableArray *removed=[NSMutableArray new];
    if (havePrior) {
        for (NSString *name in sourceHashes) {
            NSString *old=PFRTString(oldHashes[name]);
            if (!old.length) [added addObject:name];
            else if (![old isEqualToString:sourceHashes[name]])
                [changed addObject:name];
        }
        for (NSString *name in oldHashes) {
            if (!sourceHashes[name]) [removed addObject:name];
        }
    }
    [changed sortUsingSelector:@selector(compare:)];
    [added sortUsingSelector:@selector(compare:)];
    [removed sortUsingSelector:@selector(compare:)];

    NSUInteger bootEvents=PFRTCount(boot[@"event_rows"]);
    NSUInteger oldEvents=havePrior ?
        PFRTCount(PFRTDict(prior[@"observed_counters"])[@"boot_event_rows"]):0;
    BOOL bootRowsReset=havePrior && bootEvents<oldEvents;
    NSUInteger newBootEvents=(havePrior && bootEvents>=oldEvents) ?
        (bootEvents-oldEvents):0;

    NSUInteger sameTrials=PFRTCount(same[@"trials"]);
    NSUInteger successful=PFRTCount(same[@"successful_api_calls"]);
    NSUInteger overlapping=PFRTCount(same[@"overlapping_trails_user_space"]);
    NSUInteger invalidRows=PFRTCount(same[@"invalid_rows"]);
    successful=MIN(successful,sameTrials);
    overlapping=MIN(overlapping,sameTrials);

    NSString *sameStatus=@"NO_VALID_USER_SPACE_CALLS";
    if (sameTrials>0 && overlapping>0 && successful==0)
        sameStatus=@"USER_SPACE_OVERLAP_WITH_REJECTED_CALLS";
    else if (sameTrials>0 && overlapping>0 && successful>0)
        sameStatus=@"USER_SPACE_OVERLAP_WITH_API_SUCCESS";
    else if (sameTrials>0)
        sameStatus=@"NO_USER_SPACE_OVERLAP_OBSERVED";

    NSMutableDictionary<NSString *,NSNumber *> *outcomes=[NSMutableDictionary new];
    for (id v in PFRTArray(same[@"samples"])) {
        NSDictionary *sample=PFRTDict(v);
        NSString *call=PFRTString(sample[@"call_result"]);
        NSString *close=PFRTString(sample[@"close_result"]);
        if (call.length && close.length) {
            NSString *key=[NSString stringWithFormat:@"call=%@;close=%@",call,close];
            outcomes[key]=@([outcomes[key] unsignedIntegerValue]+1);
        }
    }
    NSArray *fingerprints=[[outcomes allKeys] sortedArrayUsingSelector:
                            @selector(compare:)];

    NSDictionary *statusCounts=PFRTDict(boot[@"status_counts"]);
    NSUInteger possibleRollbackCount=0;
    for(NSString *key in statusCounts) {
        if (![key isKindOfClass:NSString.class]) continue;
        NSString *up=key.uppercaseString;
        if (([up containsString:@"ROLLBACK"] || [up containsString:@"ROLLED_BACK"]) &&
             ![up hasPrefix:@"NO_"])
            possibleRollbackCount+=PFRTCount(statusCounts[key]);
    }

    NSString *revocationVerdict=PFRTString(revocation[@"verdict"]);
    BOOL hasRevocation=[revocation[@"available"] respondsToSelector:@selector(boolValue)] &&
                       [revocation[@"available"] boolValue];
    BOOL unexpectedRevocation=hasRevocation && revocationVerdict.length>0 &&
        ![revocationVerdict isEqualToString:@"EXPECTED_REJECTION"];
    NSUInteger messages=PFRTCount(observer[@"messages_received"]);

    NSMutableArray *findings=[NSMutableArray new];
    if (sameTrials>0 && overlapping>0 && successful==0)
        [findings addObject:PFRTFinding(
            @"REJECTED_RPC_WITH_USER_SPACE_OVERLAP",@"context",
            @"Overlapping app-side intervals were observed, but no accepted RPC was recorded. This is not a successful kernel notification registration.")];
    if (sameTrials>0 && overlapping>0 && successful>0)
        [findings addObject:PFRTFinding(
            @"APP_SIDE_OVERLAP_WITH_SUCCESS",@"review",
            @"An RPC reported success while app-side intervals overlapped. Kernel callback lifetime remains unknown; inspect exact API semantics and reproducibility.")];
    if (invalidRows>0)
        [findings addObject:PFRTFinding(
            @"TRACE_ROWS_REJECTED",@"data_quality",
            @"At least one SameClient CSV row is malformed or unsupported. Preserve the source and verify its schema.")];
    if (bootRowsReset)
        [findings addObject:PFRTFinding(
            @"BOOT_MONITOR_COUNTER_RESET",@"data_quality",
            @"The new trace has fewer rows than the prior report. This can reflect trace rotation, not necessarily a reboot.")];
    if (possibleRollbackCount>0)
        [findings addObject:PFRTFinding(
            @"UPTIME_ROLLBACK_REPORT",@"review",
            @"App-side uptime suggests a restart between observations; neither its cause nor a kernel panic is established.")];
    if (unexpectedRevocation)
        [findings addObject:PFRTFinding(
            @"MACH_REVOCATION_UNEXPECTED",@"review",
            @"Unexpected Mach lookup result. Confirm ownership, reference counts and controls before interpreting it as a security issue.")];
    if (messages>0)
        [findings addObject:PFRTFinding(
            @"ASYNC_MESSAGE_DELIVERED",@"context",
            @"Asynchronous messages were delivered in the app. Their delivery alone is not a post-free kernel dereference.")];
    if (findings.count==0)
        [findings addObject:PFRTFinding(
            @"NO_NEW_ANOMALIES_IN_SNAPSHOT",@"context",
            @"The supplied snapshot contains no classified anomaly requiring review.")];

    BOOL kernelRelease=[kernel[@"kernel_last_release_observed"]
        respondsToSelector:@selector(boolValue)] &&
        [kernel[@"kernel_last_release_observed"] boolValue];
    BOOL kernelPostFree=[kernel[@"post_free_dispatch_observed"]
        respondsToSelector:@selector(boolValue)] &&
        [kernel[@"post_free_dispatch_observed"] boolValue];
    // Never authenticate or promote kernel claims based on sandbox-visible data.
    NSString *releaseClaim=kernelRelease?@"DECLARED_BY_SNAPSHOT_NOT_VERIFIED":
        @"NOT_OBSERVED";
    NSString *postFreeClaim=kernelPostFree?@"DECLARED_BY_SNAPSHOT_NOT_VERIFIED":
        @"NOT_OBSERVED";

    NSMutableArray *steps=[NSMutableArray arrayWithArray:@[
        @"Archive the source logs and compare changes in their SHA-256 digests.",
        @"Review API return codes before treating any app-side timing overlap as meaningful.",
        @"Avoid repeating identical revocation or rejected-call tests without a new hypothesis."
    ]];
    if (invalidRows)
        [steps addObject:@"Repair the malformed CSV schema before drawing conclusions."];
    if (unexpectedRevocation)
        [steps addObject:@"Recheck the unexpected result with a known-valid control."];
    if (messages>0)
        [steps addObject:@"Inspect the documented asynchronous callback contract."];

    return @{
        @"schema":@"iosurface-security-research-triage-v19.13",
        @"report_id":NSUUID.UUID.UUIDString,
        @"created_utc":PFRTDate(),
        @"origin":@"app_sandbox_diagnostic_snapshot",
        @"source_snapshot_id":PFRTString(snapshot[@"snapshot_id"]),
        @"source_hashes":sourceHashes,
        @"observed_counters":@{
            @"boot_event_rows":@(bootEvents),
            @"same_client_trials":@(sameTrials),
            @"same_client_overlaps":@(overlapping),
            @"same_client_accepted_calls":@(successful),
            @"same_client_invalid_rows":@(invalidRows),
            @"async_messages":@(messages)
        },
        @"change_analysis":@{
            @"has_previous_report":@(havePrior),
            @"previous_report_id":havePrior?PFRTString(prior[@"report_id"]):@"",
            @"new_sources":added,
            @"modified_sources":changed,
            @"removed_sources":removed,
            @"new_boot_monitor_events":@(newBootEvents),
            @"boot_trace_counter_reset":@(bootRowsReset),
            @"identical_source_set":@(havePrior && !added.count &&
                                      !changed.count && !removed.count),
            @"comparison_scope":@"App-owned file hashes and cumulative public observations only."
        },
        @"same_client_triage":@{
            @"classification":sameStatus,
            @"trial_count":@(sameTrials),
            @"invalid_rows":@(invalidRows),
            @"overlapping_user_space_intervals":@(overlapping),
            @"accepted_rpc_count":@(successful),
            @"max_app_side_overlap_microseconds":same[@"max_overlap_microseconds"]?:@0,
            @"outcome_fingerprints":fingerprints,
            @"distinct_outcomes":@(fingerprints.count),
            @"outcome_sample_counts":outcomes
        },
        @"mach_revocation":@{
            @"verdict":revocationVerdict.length?revocationVerdict:@"NO_CAPTURE",
            @"unexpected_result":@(unexpectedRevocation)
        },
        @"findings":findings,
        @"recommended_review_steps":steps,
        @"kernel_evidence":@{
            @"last_release_claim":releaseClaim,
            @"post_free_dispatch_claim":postFreeClaim,
            @"authentic_kernel_events_observed":@NO,
            @"kernel_privileges_acquired":@NO,
            @"uaf_proven":@NO,
            @"reason":@"The app sandbox cannot observe OSObject refcounts, prove final kernel deallocation or authenticate post-free notification dispatch."
        },
        @"conclusion":@"RESEARCH_TRIAGE_ONLY_NOT_A_KERNEL_EXPLOIT"
    };
}

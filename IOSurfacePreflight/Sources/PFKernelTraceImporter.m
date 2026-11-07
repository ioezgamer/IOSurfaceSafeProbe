#import "PFKernelTraceImporter.h"
#import <CommonCrypto/CommonDigest.h>
#import <math.h>

// This is a passive, untrusted trace parser. It does NOT read, instrument,
// or modify iOS kernel memory. Consistent user-supplied JSON is not proof that
// the events occurred on a real device.

static NSString *PFString(id value) {
    return [value isKindOfClass:[NSString class]] ? value : @"";
}
static BOOL PFNonEmptyString(id value) {
    return [value isKindOfClass:[NSString class]] &&
           [((NSString *)value) length] > 0 &&
           [((NSString *)value) length] <= 128;
}
static NSString *PFHash(NSData *data) {
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *hex=[NSMutableString new];
    for (NSUInteger i=0;i<CC_SHA256_DIGEST_LENGTH;i++)
        [hex appendFormat:@"%02x",digest[i]];
    return hex;
}
static NSDictionary *PFResult(NSString *status, NSString *detail,
                              NSString *sha256, NSUInteger bytes,
                              NSUInteger count, NSArray *candidates,
                              NSDictionary *provenance) {
    return @{
        @"schema":@"iosurface-offline-lifetime-analysis-v1",
        @"status":status,
        @"detail":detail,
        @"input_sha256":sha256?:@"",
        @"input_bytes":@(bytes),
        @"event_count":@(count),
        @"candidate_count":@(candidates.count),
        @"candidate_chains":candidates,
        @"declared_provenance":provenance?:@{},
        @"provenance_authenticated":@NO,
        @"kernel_uaf_proven":@NO,
        @"kernel_instrumentation_performed":@NO,
        @"last_release_observed_by_app":@NO,
        @"interpretation":@"Candidate sequences are only assertions in an imported, untrusted file. A normal iOS IPA cannot verify kernel refcounts, kernel deallocation, or a later kernel dereference."
    };
}
static NSString *PFObjectKey(NSDictionary *e) {
    return [NSString stringWithFormat:@"%@|%@|%@",
       PFString(e[@"boot_id"]),PFString(e[@"object_id"]),
       PFString(e[@"generation"])];
}
static NSString *PFNodeKey(NSDictionary *e) {
    return [NSString stringWithFormat:@"%@|%@",
            PFObjectKey(e), PFString(e[@"notification_id"])];
}
static BOOL PFUInt(id x, uint64_t *out) {
    if (![x isKindOfClass:NSNumber.class]) return NO;
    NSNumber *n=(NSNumber *)x;
    double d=n.doubleValue;
    if (!isfinite(d)||d<0.0||d>9007199254740991.0||floor(d)!=d) return NO;
    uint64_t u=n.unsignedLongLongValue;
    if ((double)u!=d) return NO;
    *out=u;return YES;
}

NSDictionary<NSString *, id> *PFAnalyzeInstrumentedKernelTrace(NSURL *fileURL) {
    NSString *invalid=@"INVALID_EXTERNAL_TRACE";
    if (!fileURL.isFileURL)
        return PFResult(invalid,@"Only local files can be imported.",@"",0,0,@[],nil);
    NSDictionary *attrs=[[NSFileManager defaultManager]
        attributesOfItemAtPath:fileURL.path error:NULL];
    unsigned long long length=[attrs fileSize];
    if (length == 0 || length > 1024ULL*1024ULL)
        return PFResult(invalid,@"Missing or oversized trace (limit: 1 MiB).",
                        @"",0,0,@[],nil);
    NSData *data=[NSData dataWithContentsOfURL:fileURL options:0 error:NULL];
    if (!data || data.length != (NSUInteger)length)
        return PFResult(invalid,@"File could not be read completely.",
                        @"",0,0,@[],nil);
    NSString *digest=PFHash(data);
    id root=[NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    if (![root isKindOfClass:NSDictionary.class])
        return PFResult(invalid,@"Root must be a JSON object.",
                        digest,data.length,0,@[],nil);
    NSDictionary *dict=(NSDictionary *)root;
    NSArray *events=dict[@"events"];
    NSDictionary *meta=[dict[@"provenance"] isKindOfClass:NSDictionary.class]
       ? dict[@"provenance"] : @{};
    if (![dict[@"schema"] isEqual:@"iosurface-instrumented-lifetime-v1"] ||
        ![events isKindOfClass:NSArray.class] ||
        events.count>4096 || events.count==0)
        return PFResult(invalid,@"Unsupported schema or event count.",
                        digest,data.length,0,@[],meta);
    for (NSString *key in @[@"environment",@"capture_id"]) {
        if (!PFNonEmptyString(meta[key]))
            return PFResult(invalid,@"External capture metadata is incomplete.",
                            digest,data.length,0,@[],meta);
    }

    NSSet *known=[NSSet setWithArray:@[
       @"object_created",@"notification_registered",
       @"last_release",@"object_deallocated",
       @"notification_still_linked",@"notification_removed",
       @"notification_dispatch_dereference"]];
    NSSet *nodeKinds=[NSSet setWithArray:@[
       @"notification_registered",@"notification_still_linked",
       @"notification_removed",@"notification_dispatch_dereference"]];
    NSMutableDictionary<NSString *,NSMutableDictionary *> *objects =
       [NSMutableDictionary new];
    NSMutableDictionary<NSString *,NSMutableDictionary *> *nodes =
       [NSMutableDictionary new];
    NSMutableArray<NSDictionary *> *candidates=[NSMutableArray new];
    uint64_t previousSequence=0, previousTime=0;
    BOOL first=YES;

    for (id element in events) {
        if (![element isKindOfClass:NSDictionary.class])
            return PFResult(invalid,@"Each event must be an object.",
                            digest,data.length,0,@[],meta);
        NSDictionary *e=(NSDictionary *)element;
        NSString *kind=PFString(e[@"event"]);
        uint64_t seq=0,time=0;
        if (![known containsObject:kind] ||
            !PFNonEmptyString(e[@"boot_id"]) ||
            !PFNonEmptyString(e[@"object_id"]) ||
            !PFNonEmptyString(e[@"generation"]) ||
            !PFUInt(e[@"seq"],&seq) || !PFUInt(e[@"monotonic_ns"],&time) ||
            (!first && (seq<=previousSequence || time<previousTime)) ||
            ([nodeKinds containsObject:kind] &&
             !PFNonEmptyString(e[@"notification_id"]))) {
            return PFResult(invalid,@"Malformed event, missing identity, or non-monotonic sequence.",
                            digest,data.length,0,@[],meta);
        }
        first=NO; previousSequence=seq; previousTime=time;
        NSString *objectKey=PFObjectKey(e), *nodeKey=PFNodeKey(e);
        NSMutableDictionary *obj=objects[objectKey];
        if (!obj) {obj=[NSMutableDictionary new]; objects[objectKey]=obj;}
        NSMutableDictionary *node=nodes[nodeKey];
        if (!node) {node=[NSMutableDictionary new];nodes[nodeKey]=node;}
        if ([kind isEqual:@"object_created"]) {
            obj[@"created"]=@(seq);
        } else if ([kind isEqual:@"last_release"]) {
            obj[@"last_release"]=@(seq);
        } else if ([kind isEqual:@"object_deallocated"]) {
            obj[@"deallocated"]=@(seq);
        } else if ([kind isEqual:@"notification_registered"]) {
            node[@"registered"]=@(seq);
            [node removeObjectForKey:@"removed"];
            [node removeObjectForKey:@"linked_after_free"];
        } else if ([kind isEqual:@"notification_removed"]) {
            node[@"removed"]=@(seq);
        } else if ([kind isEqual:@"notification_still_linked"]) {
            NSNumber *f=obj[@"deallocated"];
            NSNumber *r=node[@"registered"];
            if (f && r && f.unsignedLongLongValue<seq &&
                r.unsignedLongLongValue<seq && !node[@"removed"])
                node[@"linked_after_free"]=@(seq);
        } else if ([kind isEqual:@"notification_dispatch_dereference"]) {
            NSNumber *c=obj[@"created"], *l=obj[@"last_release"],
                    *f=obj[@"deallocated"], *r=node[@"registered"],
                    *linked=node[@"linked_after_free"];
            if (c && l && f && r && linked && !node[@"removed"] &&
                c.unsignedLongLongValue<r.unsignedLongLongValue &&
                r.unsignedLongLongValue<l.unsignedLongLongValue &&
                l.unsignedLongLongValue<f.unsignedLongLongValue &&
                f.unsignedLongLongValue<linked.unsignedLongLongValue &&
                linked.unsignedLongLongValue<seq &&
                candidates.count<20) {
                [candidates addObject:@{
                    @"boot_id":PFString(e[@"boot_id"]),
                    @"object_id":PFString(e[@"object_id"]),
                    @"generation":PFString(e[@"generation"]),
                    @"notification_id":PFString(e[@"notification_id"]),
                    @"sequence_indexes":@{
                        @"object_created":c,
                        @"notification_registered":r,
                        @"last_release":l,
                        @"object_deallocated":f,
                        @"notification_still_linked":linked,
                        @"notification_dispatch_dereference":@(seq)
                    }
                }];
            }
        }
    }
    NSString *status=candidates.count ?
        @"CONSISTENT_EXTERNAL_CANDIDATE_UNAUTHENTICATED" :
        @"NO_CORRELATED_SEQUENCE_IN_IMPORTED_DATA";
    NSString *detail=candidates.count ?
        @"A claimed lifetime sequence is internally consistent. Its events are not independently authenticated." :
        @"No complete same-instance sequence exists in the supplied external trace.";
    return PFResult(status,detail,digest,data.length,events.count,
                    candidates,meta);
}

#import <Foundation/Foundation.h>
#import "PFKernelTraceImporter.h"

static NSDictionary *ev(NSUInteger seq, NSString *kind,
                        NSString *object, NSString *generation,
                        NSString *node) {
    NSMutableDictionary *d=[@{
       @"seq":@(seq),@"monotonic_ns":@(seq*1000),
       @"event":kind,@"boot_id":@"boot-debug-123",
       @"object_id":object,@"generation":generation
    } mutableCopy];
    if (node) d[@"notification_id"]=node;
    return d;
}
static NSArray *validEvents(void) {
    return @[
      ev(1,@"object_created",@"O1",@"G1",nil),
      ev(2,@"notification_registered",@"O1",@"G1",@"N1"),
      ev(3,@"last_release",@"O1",@"G1",nil),
      ev(4,@"object_deallocated",@"O1",@"G1",nil),
      ev(5,@"notification_still_linked",@"O1",@"G1",@"N1"),
      ev(6,@"notification_dispatch_dereference",@"O1",@"G1",@"N1")
    ];
}
static NSDictionary *root(NSArray *events) {
    return @{@"schema":@"iosurface-instrumented-lifetime-v1",
        @"provenance":@{@"environment":@"lab debug kernel (declared only)",
                        @"capture_id":@"debug-capture-01"},
        @"events":events};
}
static NSDictionary *analyze(NSString *folder, NSDictionary *source) {
    NSString *path=[folder stringByAppendingPathComponent:@"trace.json"];
    NSData *data=[NSJSONSerialization dataWithJSONObject:source
        options:0 error:NULL];
    NSCAssert(data != nil,@"fixture JSON encoding failed");
    NSCAssert([data writeToFile:path atomically:YES],@"fixture write failed");
    return PFAnalyzeInstrumentedKernelTrace([NSURL fileURLWithPath:path]);
}
static void check(BOOL value,NSString *name) {
    if (!value) {
        fprintf(stderr,"FAIL: %s\n",name.UTF8String);
        abort();
    }
}
int main(void) {
  @autoreleasepool {
    NSString *folder=[NSTemporaryDirectory() stringByAppendingPathComponent:
      [NSString stringWithFormat:@"PFKernelTrace-%@",
         [NSUUID UUID].UUIDString]];
    check([[NSFileManager defaultManager] createDirectoryAtPath:folder
       withIntermediateDirectories:YES attributes:nil error:NULL],
       @"create tmp");

    // 1. A complete synthetic sequence yields a candidate, NEVER a proven UAF.
    NSDictionary *candidate=analyze(folder,root(validEvents()));
    check([candidate[@"candidate_count"] integerValue]==1,
          @"candidate chain recognized");
    check([candidate[@"status"] isEqualToString:
          @"CONSISTENT_EXTERNAL_CANDIDATE_UNAUTHENTICATED"],@"unverified status");
    check(![candidate[@"kernel_uaf_proven"] boolValue],@"never claim kernel UAF");
    check(![candidate[@"provenance_authenticated"] boolValue],
          @"synthetic trace cannot be authenticated");

    // 2. Missing final release means no complete chain.
    NSMutableArray *missing=[validEvents() mutableCopy];
    [missing removeObjectAtIndex:2];
    NSDictionary *incomplete=analyze(folder,root(missing));
    check([incomplete[@"candidate_count"] integerValue]==0,
          @"missing final release rejected");

    // 3. A different generation of the same address is a DIFFERENT object.
    NSMutableArray *gen=[validEvents() mutableCopy];
    gen[5]=ev(6,@"notification_dispatch_dereference",@"O1",@"G2",@"N1");
    NSDictionary *generation=analyze(folder,root(gen));
    check([generation[@"candidate_count"] integerValue]==0,
          @"generation mismatch rejected");

    // 4. Removing the node before dispatch invalidates the correlation.
    NSMutableArray *unlinked=[validEvents() mutableCopy];
    [unlinked insertObject:ev(6,@"notification_removed",@"O1",@"G1",@"N1")
                  atIndex:5];
    unlinked[6]=ev(7,@"notification_dispatch_dereference",@"O1",@"G1",@"N1");
    NSDictionary *removed=analyze(folder,root(unlinked));
    check([removed[@"candidate_count"] integerValue]==0,
          @"removed node rejected");

    // 5. Source seq must be strictly increasing.
    NSMutableArray *unordered=[validEvents() mutableCopy];
    unordered[5]=ev(5,@"notification_dispatch_dereference",@"O1",@"G1",@"N1");
    NSDictionary *order=analyze(folder,root(unordered));
    check([order[@"status"] isEqualToString:@"INVALID_EXTERNAL_TRACE"],
          @"duplicate sequence invalid");

    // 6. Another boot session cannot be silently linked.
    NSMutableArray *boot=[validEvents() mutableCopy];
    NSMutableDictionary *dispatch=[boot[5] mutableCopy];
    dispatch[@"boot_id"]=@"other-boot";
    boot[5]=dispatch;
    NSDictionary *mismatched=analyze(folder,root(boot));
    check([mismatched[@"candidate_count"] integerValue]==0,
          @"boot mismatch rejected");

    // 7. Incomplete provenance must be explicitly rejected.
    NSMutableDictionary *meta=[root(validEvents()) mutableCopy];
    meta[@"provenance"]=@{@"capture_id":@"debug-capture-01"};
    NSDictionary *noProvenance=analyze(folder,meta);
    check([noProvenance[@"status"] isEqualToString:@"INVALID_EXTERNAL_TRACE"],
          @"missing capture metadata invalid");

    // 8. Empty source is invalid and never yields a candidate.
    NSDictionary *empty=analyze(folder,root(@[]));
    check([empty[@"status"] isEqualToString:@"INVALID_EXTERNAL_TRACE"] &&
          [empty[@"candidate_count"] integerValue]==0,
          @"empty events invalid");

    // 9. Candidate output has no kernel-memory access or trusted provenance.
    check(![candidate[@"kernel_instrumentation_performed"] boolValue] &&
          ![candidate[@"last_release_observed_by_app"] boolValue],
          @"no fabricated internal kernel access");

    [[NSFileManager defaultManager] removeItemAtPath:folder error:NULL];
    puts("PFKernelTraceImporter: 9/9 PASS");
  }
  return 0;
}

//
//  IOSurfaceResearch.m
//  IOSurfaceSafeProbe
//
//  IOSurface vulnerability research module for iOS 27.
//  Detects anomalies without intentionally crashing the kernel.
//  Checkpoint files record exact state so a crash pinpoints the trigger.
//  GPL-3.0-or-later.
//

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <mach/mach_time.h>
#import <dlfcn.h>
#import <stdatomic.h>
#import <pthread.h>
#import <sys/time.h>
#import "IOSurfaceResearch.h"

#pragma mark - IOSurface / IOKit symbol types

typedef struct __IOSurface *IOSurfaceRef;
typedef uint32_t IOSurfaceID;
typedef IOSurfaceRef (*ISR_CreateFn)(CFDictionaryRef);
typedef IOSurfaceID  (*ISR_GetIDFn)(IOSurfaceRef);
typedef IOSurfaceRef (*ISR_LookupFn)(IOSurfaceID);
typedef size_t       (*ISR_DimFn)(IOSurfaceRef);
typedef void *       (*ISR_BaseFn)(IOSurfaceRef);
typedef kern_return_t(*ISR_LockFn)(IOSurfaceRef, uint32_t, uint32_t *);

typedef uint32_t io_object_t;
typedef io_object_t io_service_t;
typedef io_object_t io_connect_t;
typedef CFMutableDictionaryRef (*ISR_MatchFn)(const char *);
typedef io_service_t  (*ISR_GetMatchFn)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*ISR_OpenFn)(io_service_t, task_t, uint32_t, io_connect_t *);
typedef kern_return_t (*ISR_CloseFn)(io_connect_t);
typedef kern_return_t (*ISR_ReleaseFn)(io_object_t);
typedef kern_return_t (*ISR_CallFn)(io_connect_t, uint32_t,
                                     const uint64_t *, uint32_t,
                                     const void *, size_t,
                                     uint64_t *, uint32_t *,
                                     void *, size_t *);

#pragma mark - Symbol loader

typedef struct {
    void *iosurface;
    void *iokit;
    ISR_CreateFn create;
    ISR_GetIDFn  getID;
    ISR_LookupFn lookup;
    ISR_DimFn    getWidth;
    ISR_DimFn    getHeight;
    ISR_DimFn    getAllocSize;
    ISR_BaseFn   getBase;
    ISR_LockFn   lock;
    ISR_LockFn   unlock;
    ISR_MatchFn  matching;
    ISR_GetMatchFn getMatch;
    ISR_OpenFn   open;
    ISR_CloseFn  close;
    ISR_ReleaseFn release;
    ISR_CallFn   call;
} ISRSymbols;

static BOOL isr_load(ISRSymbols *s) {
    memset(s, 0, sizeof(*s));
    s->iosurface = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface",
                          RTLD_LAZY | RTLD_LOCAL);
    s->iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",
                      RTLD_LAZY | RTLD_LOCAL);
    if (!s->iosurface || !s->iokit) return NO;
    s->create    = (ISR_CreateFn)dlsym(s->iosurface, "IOSurfaceCreate");
    s->getID     = (ISR_GetIDFn)dlsym(s->iosurface, "IOSurfaceGetID");
    s->lookup    = (ISR_LookupFn)dlsym(s->iosurface, "IOSurfaceLookup");
    s->getWidth  = (ISR_DimFn)dlsym(s->iosurface, "IOSurfaceGetWidth");
    s->getHeight = (ISR_DimFn)dlsym(s->iosurface, "IOSurfaceGetHeight");
    s->getAllocSize = (ISR_DimFn)dlsym(s->iosurface, "IOSurfaceGetAllocSize");
    s->getBase   = (ISR_BaseFn)dlsym(s->iosurface, "IOSurfaceGetBaseAddress");
    s->lock      = (ISR_LockFn)dlsym(s->iosurface, "IOSurfaceLock");
    s->unlock    = (ISR_LockFn)dlsym(s->iosurface, "IOSurfaceUnlock");
    s->matching  = (ISR_MatchFn)dlsym(s->iokit, "IOServiceMatching");
    s->getMatch  = (ISR_GetMatchFn)dlsym(s->iokit, "IOServiceGetMatchingService");
    s->open      = (ISR_OpenFn)dlsym(s->iokit, "IOServiceOpen");
    s->close     = (ISR_CloseFn)dlsym(s->iokit, "IOServiceClose");
    s->release   = (ISR_ReleaseFn)dlsym(s->iokit, "IOObjectRelease");
    s->call      = (ISR_CallFn)dlsym(s->iokit, "IOConnectCallMethod");
    return s->create && s->getID && s->lookup && s->getWidth && s->getHeight &&
           s->getAllocSize && s->getBase && s->lock && s->unlock &&
           s->matching && s->getMatch && s->open && s->close && s->release && s->call;
}

static void isr_unload(ISRSymbols *s) {
    if (s->iosurface) dlclose(s->iosurface);
    if (s->iokit) dlclose(s->iokit);
    memset(s, 0, sizeof(*s));
}

#pragma mark - Stop flag

static atomic_bool g_isr_stop = false;

void iosurface_research_stop(void) {
    atomic_store(&g_isr_stop, true);
}

static BOOL isr_stopped(void) {
    return atomic_load(&g_isr_stop);
}

#pragma mark - Checkpoint helpers

static NSString *isr_docs_path(NSString *name) {
    return [NSHomeDirectory() stringByAppendingPathComponent:
            [NSString stringWithFormat:@"Documents/%@", name]];
}

static void isr_checkpoint(NSString *name, NSDictionary *state) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:state options:NSJSONWritingSortedKeys error:nil];
    if (data) [data writeToFile:isr_docs_path(name) atomically:YES];
}

static NSDictionary *isr_default_surface_params(size_t w, size_t h) {
    size_t rowBytes = w * 4;
    return @{
        @"IOSurfaceWidth": @(w),
        @"IOSurfaceHeight": @(h),
        @"IOSurfaceBytesPerElement": @4,
        @"IOSurfaceBytesPerRow": @(rowBytes),
        @"IOSurfaceAllocSize": @(rowBytes * h),
        @"IOSurfacePixelFormat": @(0x42475241)
    };
}

#pragma mark - Probe 1: Race Condition Detector

typedef struct {
    ISRSymbols *sym;
    ISRLogBlock log;
    atomic_uint *anomalyCount;
    atomic_uint *idReuseCount;
    unsigned threadIndex;
    unsigned iterations;
    uint32_t *allIDs;
    atomic_uint *idWriteIndex;
    unsigned maxIDs;
} ISRRaceCtx;

static void *isr_race_worker(void *arg) {
    ISRRaceCtx *ctx = (ISRRaceCtx *)arg;
    ISRSymbols *s = ctx->sym;
    NSDictionary *params = isr_default_surface_params(64, 64);

    for (unsigned i = 0; i < ctx->iterations && !isr_stopped(); i++) {
        @autoreleasepool {
            IOSurfaceRef surf = s->create((__bridge CFDictionaryRef)params);
            if (!surf) continue;
            IOSurfaceID sid = s->getID(surf);

            unsigned idx = atomic_fetch_add(ctx->idWriteIndex, 1);
            if (idx < ctx->maxIDs) ctx->allIDs[idx] = sid;

            IOSurfaceRef ref2 = s->lookup(sid);
            CFRelease(surf);

            if (ref2) {
                size_t w = s->getWidth(ref2);
                if (w != 64) {
                    atomic_fetch_add(ctx->anomalyCount, 1);
                    ctx->log([NSString stringWithFormat:
                        @"RACE[%u]: ANOMALY width=%zu (expected 64) ID=%u iter=%u",
                        ctx->threadIndex, w, (unsigned)sid, i]);
                }
                CFRelease(ref2);
            }

            IOSurfaceRef post = s->lookup(sid);
            if (post) {
                size_t w2 = s->getWidth(post);
                if (w2 != 64) {
                    atomic_fetch_add(ctx->anomalyCount, 1);
                    ctx->log([NSString stringWithFormat:
                        @"RACE[%u]: ANOMALY post-release width=%zu ID=%u",
                        ctx->threadIndex, w2, (unsigned)sid]);
                }
                CFRelease(post);
            }
        }
    }
    return NULL;
}

void iosurface_research_race(ISRLogBlock log, ISRDoneBlock done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            log(@"RACE: === IOSurface Create/Destroy Race Detector ===");
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"RACE: FAIL cannot load symbols");
                done(@{@"status": @"FAIL", @"reason": @"symbols"});
                return;
            }

            const unsigned threadCount = 6;
            const unsigned iterPerThread = 2000;
            const unsigned maxIDs = threadCount * iterPerThread;
            uint32_t *allIDs = calloc(maxIDs, sizeof(uint32_t));
            atomic_uint idWriteIndex = 0;
            atomic_uint anomalyCount = 0;
            atomic_uint idReuseCount = 0;

            isr_checkpoint(@"ISR-Race-checkpoint.json", @{
                @"status": @"RUNNING",
                @"threads": @(threadCount),
                @"iterPerThread": @(iterPerThread)
            });

            log([NSString stringWithFormat:
                @"RACE: launching %u threads x %u iterations", threadCount, iterPerThread]);

            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            pthread_t threads[6];
            ISRRaceCtx ctxs[6];
            for (unsigned t = 0; t < threadCount; t++) {
                ctxs[t] = (ISRRaceCtx){
                    .sym = &sym, .log = log,
                    .anomalyCount = &anomalyCount, .idReuseCount = &idReuseCount,
                    .threadIndex = t, .iterations = iterPerThread,
                    .allIDs = allIDs, .idWriteIndex = &idWriteIndex, .maxIDs = maxIDs
                };
                pthread_create(&threads[t], NULL, isr_race_worker, &ctxs[t]);
            }
            for (unsigned t = 0; t < threadCount; t++) {
                pthread_join(threads[t], NULL);
            }
            double elapsed = CFAbsoluteTimeGetCurrent() - start;

            unsigned totalIDs = atomic_load(&idWriteIndex);
            if (totalIDs > maxIDs) totalIDs = maxIDs;
            NSMutableSet *seen = [NSMutableSet setWithCapacity:totalIDs];
            unsigned dupes = 0;
            for (unsigned i = 0; i < totalIDs; i++) {
                NSNumber *n = @(allIDs[i]);
                if ([seen containsObject:n]) dupes++;
                else [seen addObject:n];
            }
            free(allIDs);

            unsigned anomalies = atomic_load(&anomalyCount);

            log([NSString stringWithFormat:
                @"RACE: DONE elapsed=%.3fs totalSurfaces=%u uniqueIDs=%lu duplicateIDs=%u anomalies=%u",
                elapsed, totalIDs, (unsigned long)seen.count, dupes, anomalies]);

            if (dupes > 0) {
                log([NSString stringWithFormat:
                    @"RACE: WARNING %u surfaces received recycled IDs during concurrent operation", dupes]);
            }
            if (anomalies > 0) {
                log([NSString stringWithFormat:
                    @"RACE: CRITICAL %u dimension anomalies detected — possible UAF indicator", anomalies]);
            }

            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"threads": @(threadCount),
                @"totalSurfaces": @(totalIDs),
                @"uniqueIDs": @(seen.count),
                @"duplicateIDs": @(dupes),
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-Race-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

#pragma mark - Probe 2: Property Corruption Scanner

void iosurface_research_properties(ISRLogBlock log, ISRDoneBlock done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            log(@"PROPS: === IOSurface Property Corruption Scanner ===");
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"PROPS: FAIL cannot load symbols");
                done(@{@"status": @"FAIL", @"reason": @"symbols"});
                return;
            }

            isr_checkpoint(@"ISR-Props-checkpoint.json", @{@"status": @"RUNNING"});

            unsigned attempted = 0, created = 0, anomalies = 0, overflowRejects = 0;
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();

            // Phase A: Integer overflow in dimension calculations
            log(@"PROPS: Phase A — integer overflow dimension tests");
            const size_t overflowDims[] = {
                0, 1, 2, 7, 8, 15, 16, 255, 256, 1024, 4096, 16384, 65535, 65536,
                0x7FFF, 0xFFFF, 0x10000, 0x1FFFF, 0x7FFFFFFF, 0xFFFFFFFF,
                (size_t)0x100000001ULL
            };
            const unsigned nDims = sizeof(overflowDims) / sizeof(overflowDims[0]);

            for (unsigned wi = 0; wi < nDims && !isr_stopped(); wi++) {
                for (unsigned hi = 0; hi < nDims && !isr_stopped(); hi++) {
                    @autoreleasepool {
                        size_t w = overflowDims[wi], h = overflowDims[hi];
                        if (w == 0 || h == 0) {
                            // Test zero-dimension handling
                        }
                        size_t bpe = 4;
                        __uint128_t product = (__uint128_t)w * h * bpe;
                        BOOL wouldOverflow = product > (size_t)-1 || product > 256 * 1024 * 1024;
                        size_t rowBytes = (w > 0 && w <= 0x10000) ? w * bpe : 256;
                        size_t allocSize = (wouldOverflow || h == 0 || w == 0) ? 4096 : (size_t)(w * bpe * h);
                        if (allocSize > 256 * 1024 * 1024) allocSize = 256 * 1024 * 1024;

                        NSDictionary *params = @{
                            @"IOSurfaceWidth": @(w),
                            @"IOSurfaceHeight": @(h),
                            @"IOSurfaceBytesPerElement": @(bpe),
                            @"IOSurfaceBytesPerRow": @(rowBytes),
                            @"IOSurfaceAllocSize": @(allocSize),
                            @"IOSurfacePixelFormat": @(0x42475241)
                        };

                        isr_checkpoint(@"ISR-Props-checkpoint.json", @{
                            @"status": @"RUNNING",
                            @"phase": @"A",
                            @"case": @(attempted),
                            @"width": @(w),
                            @"height": @(h)
                        });

                        attempted++;
                        IOSurfaceRef surf = sym.create((__bridge CFDictionaryRef)params);
                        if (!surf) {
                            if (wouldOverflow || w == 0 || h == 0) overflowRejects++;
                            else {
                                log([NSString stringWithFormat:
                                    @"PROPS:A UNEXPECTED_REJECT w=%zu h=%zu alloc=%zu",
                                    w, h, allocSize]);
                            }
                            continue;
                        }
                        created++;
                        IOSurfaceID sid = sym.getID(surf);
                        size_t gotW = sym.getWidth(surf);
                        size_t gotH = sym.getHeight(surf);
                        size_t gotAlloc = sym.getAllocSize(surf);

                        if (wouldOverflow && gotAlloc < allocSize) {
                            anomalies++;
                            log([NSString stringWithFormat:
                                @"PROPS:A ANOMALY overflow accepted: w=%zu h=%zu gotAlloc=%zu (asked %zu) ID=%u",
                                w, h, gotAlloc, allocSize, (unsigned)sid]);
                        }

                        // Check dimension consistency
                        if (gotW != w && w > 0 && w <= 0x10000) {
                            log([NSString stringWithFormat:
                                @"PROPS:A INFO dimension clamped: asked w=%zu got w=%zu ID=%u", w, gotW, (unsigned)sid]);
                        }
                        if (gotH != h && h > 0 && h <= 0x10000) {
                            log([NSString stringWithFormat:
                                @"PROPS:A INFO dimension clamped: asked h=%zu got h=%zu ID=%u", h, gotH, (unsigned)sid]);
                        }

                        CFRelease(surf);
                    }
                }
                if (attempted % 50 == 0) {
                    log([NSString stringWithFormat:@"PROPS:A progress %u cases", attempted]);
                }
            }

            // Phase B: Lock/unlock consistency after property read
            log(@"PROPS: Phase B — lock/unlock consistency with mismatched bytesPerRow");
            const size_t bprTests[][3] = {
                // {width, bytesPerRow, expected_behavior}
                {64, 256, 1},   // normal: 64*4=256
                {64, 128, 0},   // too small: should reject or clamp
                {64, 512, 1},   // padded: OK
                {64, 1, 0},     // absurdly small
                {64, 0, 0},     // zero
                {64, 0x7FFFFFFF, 0}, // huge
                {1, 4, 1},      // minimal
                {1, 3, 0},      // too small for 4 bpe
            };
            const unsigned nBpr = sizeof(bprTests) / sizeof(bprTests[0]);
            unsigned bprAnomalies = 0;

            for (unsigned i = 0; i < nBpr && !isr_stopped(); i++) {
                @autoreleasepool {
                    size_t w = bprTests[i][0], bpr = bprTests[i][1];
                    BOOL expectOK = bprTests[i][2] != 0;
                    size_t h = 64;
                    size_t allocSize = (bpr > 0 && bpr < 0x100000) ? bpr * h : 4096;
                    if (allocSize > 64 * 1024 * 1024) allocSize = 64 * 1024 * 1024;

                    NSDictionary *params = @{
                        @"IOSurfaceWidth": @(w),
                        @"IOSurfaceHeight": @(h),
                        @"IOSurfaceBytesPerElement": @4,
                        @"IOSurfaceBytesPerRow": @(bpr),
                        @"IOSurfaceAllocSize": @(allocSize),
                        @"IOSurfacePixelFormat": @(0x42475241)
                    };

                    isr_checkpoint(@"ISR-Props-checkpoint.json", @{
                        @"status": @"RUNNING",
                        @"phase": @"B",
                        @"case": @(i),
                        @"width": @(w),
                        @"bytesPerRow": @(bpr)
                    });

                    IOSurfaceRef surf = sym.create((__bridge CFDictionaryRef)params);
                    if (!surf) {
                        if (expectOK) {
                            bprAnomalies++;
                            log([NSString stringWithFormat:
                                @"PROPS:B ANOMALY expected creation OK but got NULL: w=%zu bpr=%zu", w, bpr]);
                        }
                        continue;
                    }

                    // Lock, write, unlock, then verify
                    uint32_t seed = 0;
                    kern_return_t kr1 = sym.lock(surf, 0, &seed);
                    if (kr1 == KERN_SUCCESS) {
                        void *base = sym.getBase(surf);
                        if (base) {
                            uint64_t marker = 0xDEADBEEF00C0FFEELL;
                            memcpy(base, &marker, sizeof(marker));
                        }
                        sym.unlock(surf, 0, NULL);

                        // Re-lock read-only and verify
                        kern_return_t kr2 = sym.lock(surf, 1, NULL);
                        if (kr2 == KERN_SUCCESS) {
                            void *base2 = sym.getBase(surf);
                            if (base2) {
                                uint64_t readback = 0;
                                memcpy(&readback, base2, sizeof(readback));
                                if (readback != 0xDEADBEEF00C0FFEELL) {
                                    bprAnomalies++;
                                    anomalies++;
                                    log([NSString stringWithFormat:
                                        @"PROPS:B ANOMALY marker corrupted: wrote 0xDEADBEEF00C0FFEE "
                                        @"read 0x%016llx w=%zu bpr=%zu",
                                        (unsigned long long)readback, w, bpr]);
                                }
                            }
                            sym.unlock(surf, 1, NULL);
                        }
                    }
                    CFRelease(surf);
                }
            }
            anomalies += bprAnomalies;

            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:
                @"PROPS: DONE attempted=%u created=%u overflowRejects=%u anomalies=%u bprAnomalies=%u elapsed=%.3fs",
                attempted, created, overflowRejects, anomalies, bprAnomalies, elapsed]);

            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"attempted": @(attempted),
                @"created": @(created),
                @"overflowRejects": @(overflowRejects),
                @"anomalies": @(anomalies),
                @"bprAnomalies": @(bprAnomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-Props-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

#pragma mark - Probe 3: Reference Count Probe

void iosurface_research_refcount(ISRLogBlock log, ISRDoneBlock done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            log(@"REFCOUNT: === IOSurface Reference Count Probe ===");
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"REFCOUNT: FAIL cannot load symbols");
                done(@{@"status": @"FAIL", @"reason": @"symbols"});
                return;
            }

            isr_checkpoint(@"ISR-Refcount-checkpoint.json", @{@"status": @"RUNNING"});

            const unsigned nConnections = 4;
            const unsigned nTrials = 12;
            unsigned anomalies = 0;
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();

            CFMutableDictionaryRef criteria = sym.matching("IOSurfaceRoot");
            if (!criteria) {
                log(@"REFCOUNT: FAIL IOServiceMatching returned NULL");
                isr_unload(&sym);
                done(@{@"status": @"FAIL", @"reason": @"matching"});
                return;
            }
            io_service_t service = sym.getMatch(MACH_PORT_NULL, criteria);
            if (!service) {
                log(@"REFCOUNT: FAIL IOSurfaceRoot not visible");
                isr_unload(&sym);
                done(@{@"status": @"FAIL", @"reason": @"service"});
                return;
            }

            for (unsigned trial = 0; trial < nTrials && !isr_stopped(); trial++) {
                @autoreleasepool {
                    isr_checkpoint(@"ISR-Refcount-checkpoint.json", @{
                        @"status": @"RUNNING",
                        @"trial": @(trial),
                        @"phase": @"OPEN_CONNECTIONS"
                    });

                    // Open multiple connections
                    io_connect_t conns[4] = {0};
                    BOOL allOpened = YES;
                    for (unsigned c = 0; c < nConnections; c++) {
                        kern_return_t kr = sym.open(service, mach_task_self(), 0, &conns[c]);
                        if (kr != KERN_SUCCESS) {
                            log([NSString stringWithFormat:
                                @"REFCOUNT[%u]: FAIL open conn[%u] kr=0x%08x", trial, c, (unsigned)kr]);
                            allOpened = NO;
                            break;
                        }
                    }
                    if (!allOpened) {
                        for (unsigned c = 0; c < nConnections; c++)
                            if (conns[c]) sym.close(conns[c]);
                        continue;
                    }

                    // Create a surface and get its ID
                    NSDictionary *params = isr_default_surface_params(64, 64);
                    IOSurfaceRef creator = sym.create((__bridge CFDictionaryRef)params);
                    if (!creator) {
                        log([NSString stringWithFormat:@"REFCOUNT[%u]: FAIL create surface", trial]);
                        for (unsigned c = 0; c < nConnections; c++) sym.close(conns[c]);
                        continue;
                    }
                    IOSurfaceID sid = sym.getID(creator);

                    // Lookup from each context to add references
                    IOSurfaceRef refs[4] = {0};
                    for (unsigned c = 0; c < nConnections; c++) {
                        refs[c] = sym.lookup(sid);
                    }

                    // Write a marker while fully referenced
                    uint64_t marker = 0x00BADC0DE00FULL;
                    kern_return_t lk = sym.lock(creator, 0, NULL);
                    if (lk == KERN_SUCCESS) {
                        void *base = sym.getBase(creator);
                        if (base) memcpy(base, &marker, sizeof(marker));
                        sym.unlock(creator, 0, NULL);
                    }

                    // Release creator reference
                    CFRelease(creator);
                    creator = NULL;

                    isr_checkpoint(@"ISR-Refcount-checkpoint.json", @{
                        @"status": @"RUNNING",
                        @"trial": @(trial),
                        @"phase": @"CLOSE_ORDERED"
                    });

                    // Close connections in different orders per trial
                    unsigned closeOrder[4];
                    switch (trial % 4) {
                        case 0: closeOrder[0]=0; closeOrder[1]=1; closeOrder[2]=2; closeOrder[3]=3; break;
                        case 1: closeOrder[0]=3; closeOrder[1]=2; closeOrder[2]=1; closeOrder[3]=0; break;
                        case 2: closeOrder[0]=0; closeOrder[1]=3; closeOrder[2]=1; closeOrder[3]=2; break;
                        case 3: closeOrder[0]=2; closeOrder[1]=0; closeOrder[2]=3; closeOrder[3]=1; break;
                    }

                    for (unsigned step = 0; step < nConnections; step++) {
                        unsigned idx = closeOrder[step];

                        // Release the lookup ref before closing the connection
                        if (refs[idx]) {
                            // Check if the marker is still readable
                            if (step < nConnections - 1) {
                                kern_return_t rl = sym.lock(refs[idx], 1, NULL);
                                if (rl == KERN_SUCCESS) {
                                    void *base = sym.getBase(refs[idx]);
                                    if (base) {
                                        uint64_t readback = 0;
                                        memcpy(&readback, base, sizeof(readback));
                                        if (readback != marker) {
                                            anomalies++;
                                            log([NSString stringWithFormat:
                                                @"REFCOUNT[%u]: ANOMALY marker changed at step %u "
                                                @"(conn %u closed): wrote 0x%llx read 0x%llx",
                                                trial, step, idx,
                                                (unsigned long long)marker,
                                                (unsigned long long)readback]);
                                        }
                                    }
                                    sym.unlock(refs[idx], 1, NULL);
                                }
                            }
                            CFRelease(refs[idx]);
                            refs[idx] = NULL;
                        }

                        kern_return_t ck = sym.close(conns[idx]);
                        if (ck != KERN_SUCCESS) {
                            log([NSString stringWithFormat:
                                @"REFCOUNT[%u]: WARNING close conn[%u] at step %u kr=0x%08x",
                                trial, idx, step, (unsigned)ck]);
                        }
                        conns[idx] = 0;

                        // Can we still look it up after this connection closed?
                        IOSurfaceRef probe = sym.lookup(sid);
                        BOOL alive = probe != NULL;
                        if (probe) CFRelease(probe);

                        log([NSString stringWithFormat:
                            @"REFCOUNT[%u]: step %u closed conn[%u] surface_alive=%@",
                            trial, step, idx, alive ? @"YES" : @"NO"]);
                    }

                    // Final: surface should not be accessible
                    IOSurfaceRef finalProbe = sym.lookup(sid);
                    if (finalProbe) {
                        log([NSString stringWithFormat:
                            @"REFCOUNT[%u]: WARNING surface ID=%u still alive after all refs+conns released",
                            trial, (unsigned)sid]);
                        CFRelease(finalProbe);
                    }
                }
            }

            sym.release(service);
            double elapsed = CFAbsoluteTimeGetCurrent() - start;

            log([NSString stringWithFormat:
                @"REFCOUNT: DONE trials=%u anomalies=%u elapsed=%.3fs",
                nTrials, anomalies, elapsed]);

            if (anomalies > 0) {
                log([NSString stringWithFormat:
                    @"REFCOUNT: CRITICAL %u marker-corruption events — possible refcount imbalance", anomalies]);
            }

            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"trials": @(nTrials),
                @"connections": @(nConnections),
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-Refcount-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

#pragma mark - Probe 4: Cross-Process Surface Sharing Probe

void iosurface_research_sharing(ISRLogBlock log, ISRDoneBlock done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            log(@"SHARING: === Cross-Process Surface Sharing Probe ===");
            log(@"SHARING: simulates cross-process sharing via lookup-before-destroy patterns");
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"SHARING: FAIL cannot load symbols");
                done(@{@"status": @"FAIL", @"reason": @"symbols"});
                return;
            }

            isr_checkpoint(@"ISR-Sharing-checkpoint.json", @{@"status": @"RUNNING"});

            const unsigned nTrials = 24;
            unsigned anomalies = 0, danglingDetected = 0;
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();

            for (unsigned trial = 0; trial < nTrials && !isr_stopped(); trial++) {
                @autoreleasepool {
                    isr_checkpoint(@"ISR-Sharing-checkpoint.json", @{
                        @"status": @"RUNNING",
                        @"trial": @(trial),
                        @"phase": @"CREATE"
                    });

                    // Create surface with a known marker
                    size_t w = 64, h = 64;
                    NSDictionary *params = isr_default_surface_params(w, h);
                    IOSurfaceRef creator = sym.create((__bridge CFDictionaryRef)params);
                    if (!creator) { continue; }
                    IOSurfaceID sid = sym.getID(creator);

                    uint64_t marker = 0xCA5EFACE00000000ULL | trial;
                    kern_return_t lk = sym.lock(creator, 0, NULL);
                    if (lk == KERN_SUCCESS) {
                        void *base = sym.getBase(creator);
                        if (base) memcpy(base, &marker, sizeof(marker));
                        sym.unlock(creator, 0, NULL);
                    }

                    // Simulate "other process" getting a reference via lookup
                    unsigned nLookups = 1 + (trial % 4);
                    IOSurfaceRef lookups[4] = {0};
                    for (unsigned i = 0; i < nLookups; i++) {
                        lookups[i] = sym.lookup(sid);
                    }

                    isr_checkpoint(@"ISR-Sharing-checkpoint.json", @{
                        @"status": @"RUNNING",
                        @"trial": @(trial),
                        @"phase": @"CREATOR_RELEASE"
                    });

                    // Creator releases — simulating the creating process dying
                    CFRelease(creator);
                    creator = NULL;

                    // Check all lookup references still work
                    BOOL anyCorrupted = NO;
                    for (unsigned i = 0; i < nLookups; i++) {
                        if (!lookups[i]) continue;
                        size_t gotW = sym.getWidth(lookups[i]);
                        if (gotW != w) {
                            anomalies++;
                            anyCorrupted = YES;
                            log([NSString stringWithFormat:
                                @"SHARING[%u]: ANOMALY width=%zu (expected %zu) on lookup[%u] after creator release",
                                trial, gotW, w, i]);
                        }

                        kern_return_t rl = sym.lock(lookups[i], 1, NULL);
                        if (rl == KERN_SUCCESS) {
                            void *base = sym.getBase(lookups[i]);
                            if (base) {
                                uint64_t readback = 0;
                                memcpy(&readback, base, sizeof(readback));
                                if (readback != marker) {
                                    anomalies++;
                                    anyCorrupted = YES;
                                    log([NSString stringWithFormat:
                                        @"SHARING[%u]: ANOMALY marker corrupted: expected 0x%llx got 0x%llx "
                                        @"on lookup[%u] after creator release",
                                        trial, (unsigned long long)marker,
                                        (unsigned long long)readback, i]);
                                }
                            }
                            sym.unlock(lookups[i], 1, NULL);
                        }
                    }

                    // Release lookups one by one, checking remaining ones each time
                    for (unsigned step = 0; step < nLookups; step++) {
                        if (lookups[step]) {
                            CFRelease(lookups[step]);
                            lookups[step] = NULL;
                        }

                        isr_checkpoint(@"ISR-Sharing-checkpoint.json", @{
                            @"status": @"RUNNING",
                            @"trial": @(trial),
                            @"phase": [NSString stringWithFormat:@"RELEASE_LOOKUP_%u", step]
                        });

                        // Check remaining lookups
                        for (unsigned j = step + 1; j < nLookups; j++) {
                            if (!lookups[j]) continue;
                            size_t rw = sym.getWidth(lookups[j]);
                            if (rw != w) {
                                danglingDetected++;
                                anomalies++;
                                log([NSString stringWithFormat:
                                    @"SHARING[%u]: DANGLING width=%zu on lookup[%u] after releasing lookup[%u]",
                                    trial, rw, j, step]);
                            }
                        }
                    }

                    // Final: can we still access the surface by ID?
                    IOSurfaceRef ghost = sym.lookup(sid);
                    if (ghost) {
                        log([NSString stringWithFormat:
                            @"SHARING[%u]: INFO surface ID=%u still accessible after all refs released",
                            trial, (unsigned)sid]);
                        CFRelease(ghost);
                    }

                    log([NSString stringWithFormat:
                        @"SHARING[%u]: %@ lookups=%u",
                        trial, anyCorrupted ? @"ANOMALIES_FOUND" : @"PASS", nLookups]);
                }
            }

            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:
                @"SHARING: DONE trials=%u anomalies=%u danglingDetected=%u elapsed=%.3fs",
                nTrials, anomalies, danglingDetected, elapsed]);

            if (anomalies > 0) {
                log([NSString stringWithFormat:
                    @"SHARING: CRITICAL %u anomalies — lookup references may outlive backing memory", anomalies]);
            }

            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"trials": @(nTrials),
                @"anomalies": @(anomalies),
                @"danglingDetected": @(danglingDetected),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-Sharing-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

#pragma mark - Probe 5: Mach Port IOKit Selector Scanner

void iosurface_research_mach(ISRLogBlock log, ISRDoneBlock done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            log(@"MACH: === IOSurfaceRoot Selector Scanner ===");
            log(@"MACH: testing IOConnectCallMethod selectors 0-32 with empty/small inputs");
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"MACH: FAIL cannot load symbols");
                done(@{@"status": @"FAIL", @"reason": @"symbols"});
                return;
            }

            isr_checkpoint(@"ISR-Mach-checkpoint.json", @{@"status": @"RUNNING"});

            CFMutableDictionaryRef criteria = sym.matching("IOSurfaceRoot");
            if (!criteria) {
                log(@"MACH: FAIL matching returned NULL");
                isr_unload(&sym);
                done(@{@"status": @"FAIL", @"reason": @"matching"});
                return;
            }
            io_service_t service = sym.getMatch(MACH_PORT_NULL, criteria);
            if (!service) {
                log(@"MACH: FAIL IOSurfaceRoot not visible");
                isr_unload(&sym);
                done(@{@"status": @"FAIL", @"reason": @"service"});
                return;
            }
            io_connect_t conn = MACH_PORT_NULL;
            kern_return_t openKr = sym.open(service, mach_task_self(), 0, &conn);
            if (openKr != KERN_SUCCESS || conn == MACH_PORT_NULL) {
                log([NSString stringWithFormat:@"MACH: FAIL open kr=0x%08x", (unsigned)openKr]);
                sym.release(service);
                isr_unload(&sym);
                done(@{@"status": @"FAIL", @"reason": @"open"});
                return;
            }

            unsigned attempted = 0, accepted = 0, rejected = 0, anomalies = 0;
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();

            const unsigned maxSelector = 32;

            // Input patterns to try per selector
            typedef struct {
                const char *label;
                unsigned nScalarIn;
                uint64_t scalarIn[4];
                size_t structInSize;
            } ISRInput;

            ISRInput inputs[] = {
                {"empty",     0, {0},          0},
                {"zero_1",    1, {0},          0},
                {"one_1",     1, {1},          0},
                {"max_1",     1, {UINT64_MAX}, 0},
                {"two_zeros", 2, {0, 0},       0},
                {"mixed",     2, {1, UINT64_MAX}, 0},
                {"struct_24", 0, {0},          24},
                {"struct_64", 0, {0},          64},
            };
            const unsigned nInputs = sizeof(inputs) / sizeof(inputs[0]);

            uint8_t structBuf[256];
            memset(structBuf, 0, sizeof(structBuf));

            for (unsigned sel = 0; sel <= maxSelector && !isr_stopped(); sel++) {
                for (unsigned inp = 0; inp < nInputs && !isr_stopped(); inp++) {
                    @autoreleasepool {
                        ISRInput *in = &inputs[inp];

                        isr_checkpoint(@"ISR-Mach-checkpoint.json", @{
                            @"status": @"RUNNING",
                            @"selector": @(sel),
                            @"input": [NSString stringWithUTF8String:in->label],
                            @"case": @(attempted)
                        });

                        uint64_t scalarOut[4] = {0};
                        uint32_t scalarOutCount = 4;
                        uint8_t structOut[256] = {0};
                        size_t structOutSize = sizeof(structOut);

                        attempted++;
                        kern_return_t kr = sym.call(
                            conn, sel,
                            in->nScalarIn > 0 ? in->scalarIn : NULL,
                            in->nScalarIn,
                            in->structInSize > 0 ? structBuf : NULL,
                            in->structInSize,
                            scalarOut, &scalarOutCount,
                            structOut, &structOutSize
                        );

                        if (kr == KERN_SUCCESS) {
                            accepted++;
                            log([NSString stringWithFormat:
                                @"MACH: ACCEPTED sel=%u input=%s scalarOut=%u structOut=%zu",
                                sel, in->label, scalarOutCount, structOutSize]);

                            // Log scalar outputs
                            for (uint32_t i = 0; i < scalarOutCount && i < 4; i++) {
                                log([NSString stringWithFormat:
                                    @"MACH:   scalarOut[%u] = 0x%016llx", i, scalarOut[i]]);
                            }

                            // Check if struct output contains interesting data
                            if (structOutSize > 0) {
                                BOOL allZero = YES;
                                for (size_t i = 0; i < structOutSize && i < 64; i++) {
                                    if (structOut[i] != 0) { allZero = NO; break; }
                                }
                                if (!allZero) {
                                    NSMutableString *hex = [NSMutableString new];
                                    size_t showBytes = MIN(structOutSize, 64);
                                    for (size_t i = 0; i < showBytes; i++) {
                                        [hex appendFormat:@"%02x", structOut[i]];
                                        if ((i + 1) % 8 == 0) [hex appendString:@" "];
                                    }
                                    log([NSString stringWithFormat:
                                        @"MACH:   structOut[%zu]: %@%s",
                                        structOutSize, hex, structOutSize > 64 ? "..." : ""]);
                                }
                            }
                        } else {
                            rejected++;
                        }

                        // Detect anomalous return codes
                        if (kr != KERN_SUCCESS &&
                            kr != KERN_INVALID_ARGUMENT &&
                            kr != KERN_NOT_SUPPORTED &&
                            kr != 0xe00002c2 && // kIOReturnBadArgument
                            kr != 0xe00002bc && // kIOReturnUnsupported
                            kr != 0xe00002be && // kIOReturnNotPermitted
                            kr != 0xe0000001 && // kIOReturnError
                            kr != 0xe00002cd)   // kIOReturnNotReady
                        {
                            anomalies++;
                            log([NSString stringWithFormat:
                                @"MACH: ANOMALY sel=%u input=%s unexpected kr=0x%08x",
                                sel, in->label, (unsigned)kr]);
                        }
                    }
                }
                log([NSString stringWithFormat:@"MACH: selector %u complete (%u/%u)", sel, attempted, (maxSelector+1)*nInputs]);
            }

            sym.close(conn);
            sym.release(service);

            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:
                @"MACH: DONE attempted=%u accepted=%u rejected=%u anomalies=%u elapsed=%.3fs",
                attempted, accepted, rejected, anomalies, elapsed]);

            if (accepted > 0) {
                log([NSString stringWithFormat:
                    @"MACH: %u selectors accepted calls — review output for information leaks", accepted]);
            }
            if (anomalies > 0) {
                log([NSString stringWithFormat:
                    @"MACH: %u unexpected return codes — may indicate unhandled edge cases", anomalies]);
            }

            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"attempted": @(attempted),
                @"accepted": @(accepted),
                @"rejected": @(rejected),
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-Mach-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

#pragma mark - Probe 6: Timed Race (Round 2)

void iosurface_research_timed_race(ISRLogBlock log, ISRDoneBlock done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"TIMED_RACE: ERROR — failed to load symbols");
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            log(@"TIMED_RACE: === Precision UAF Window Detector ===");
            log(@"TIMED_RACE: Creating surfaces, measuring destroy-to-reuse timing");

            mach_timebase_info_data_t tbi;
            mach_timebase_info(&tbi);

            uint32_t uafWindows = 0;
            uint32_t staleHits = 0;
            uint32_t anomalies = 0;
            uint32_t trials = 200;
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();

            for (uint32_t t = 0; t < trials && !isr_stopped(); t++) {
                isr_checkpoint(@"ISR-TimedRace-checkpoint.json", @{
                    @"trial": @(t), @"uafWindows": @(uafWindows), @"staleHits": @(staleHits)
                });

                NSDictionary *params = isr_default_surface_params(64, 64);
                IOSurfaceRef s1 = sym.create((__bridge CFDictionaryRef)params);
                if (!s1) continue;
                IOSurfaceID id1 = sym.getID(s1);

                // Lock and write a marker pattern
                sym.lock(s1, 0, NULL);
                void *base1 = sym.getBase(s1);
                if (base1) {
                    memset(base1, 0xAB, MIN(sym.getAllocSize(s1), (size_t)256));
                }
                sym.unlock(s1, 0, NULL);

                // Measure time from release to reuse
                uint64_t t_before = mach_absolute_time();
                CFRelease(s1);
                // Immediately try to create a new one
                IOSurfaceRef s2 = sym.create((__bridge CFDictionaryRef)params);
                uint64_t t_after = mach_absolute_time();

                if (!s2) continue;
                IOSurfaceID id2 = sym.getID(s2);

                uint64_t delta_ns = (t_after - t_before) * tbi.numer / tbi.denom;

                if (id2 == id1) {
                    uafWindows++;
                    // Check if old data persists in new surface (kernel memory leak)
                    sym.lock(s2, 3, NULL); // read-only
                    void *base2 = sym.getBase(s2);
                    BOOL staleData = NO;
                    if (base2) {
                        uint8_t *p = (uint8_t *)base2;
                        int markerCount = 0;
                        for (int i = 0; i < 256 && i < (int)sym.getAllocSize(s2); i++) {
                            if (p[i] == 0xAB) markerCount++;
                        }
                        if (markerCount > 128) {
                            staleData = YES;
                            staleHits++;
                            anomalies++;
                        }
                    }
                    sym.unlock(s2, 0, NULL);

                    if (t % 20 == 0 || staleData) {
                        log([NSString stringWithFormat:
                            @"TIMED_RACE: trial=%u ID_REUSED id=%u delta=%lluns staleData=%s",
                            t, id1, delta_ns, staleData ? "YES" : "NO"]);
                    }
                }
                CFRelease(s2);
            }

            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:
                @"TIMED_RACE: DONE trials=%u uafWindows=%u staleHits=%u anomalies=%u elapsed=%.3fs",
                trials, uafWindows, staleHits, anomalies, elapsed]);

            if (staleHits > 0) {
                log([NSString stringWithFormat:
                    @"TIMED_RACE: CRITICAL — %u surfaces retained stale data after recycle (kernel memory leak)", staleHits]);
            }

            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"trials": @(trials),
                @"uafWindows": @(uafWindows),
                @"staleHits": @(staleHits),
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-TimedRace-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

#pragma mark - Probe 7: Pixel Buffer Leak (Round 2)

void iosurface_research_buffer_leak(ISRLogBlock log, ISRDoneBlock done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"BUFLEAK: ERROR — failed to load symbols");
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            log(@"BUFLEAK: === Pixel Buffer Cross-Surface Leak Detector ===");
            log(@"BUFLEAK: Tests if freed surface memory leaks into newly allocated surfaces");

            uint32_t anomalies = 0;
            uint32_t leaksDetected = 0;
            uint32_t partialLeaks = 0;
            uint32_t trials = 100;
            // Test multiple surface sizes — the allocator may behave differently
            size_t sizes[][2] = {{32,32},{64,64},{128,128},{256,256},{512,512},{1024,1024},{16,1024},{1024,16}};
            int nSizes = sizeof(sizes)/sizeof(sizes[0]);
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();

            for (int si = 0; si < nSizes && !isr_stopped(); si++) {
                size_t w = sizes[si][0], h = sizes[si][1];
                NSDictionary *params = isr_default_surface_params(w, h);
                uint32_t sizeLeaks = 0;
                uint32_t sizePartials = 0;

                log([NSString stringWithFormat:@"BUFLEAK: testing %zux%zu (%zu bytes)", w, h, w*4*h]);

                for (uint32_t t = 0; t < trials && !isr_stopped(); t++) {
                    isr_checkpoint(@"ISR-BufLeak-checkpoint.json", @{
                        @"size": [NSString stringWithFormat:@"%zux%zu", w, h],
                        @"trial": @(t), @"leaks": @(leaksDetected)
                    });

                    // Phase 1: Create surface, write unique pattern
                    uint8_t marker = (uint8_t)((t * 37 + si * 13) & 0xFF);
                    if (marker == 0) marker = 0xCD;

                    IOSurfaceRef victim = sym.create((__bridge CFDictionaryRef)params);
                    if (!victim) continue;

                    sym.lock(victim, 0, NULL);
                    void *vbase = sym.getBase(victim);
                    size_t allocSz = sym.getAllocSize(victim);
                    size_t fillSz = MIN(allocSz, (size_t)4096);
                    if (vbase) {
                        memset(vbase, marker, fillSz);
                    }
                    sym.unlock(victim, 0, NULL);

                    // Phase 2: Destroy victim
                    CFRelease(victim);

                    // Phase 3: Allocate N new surfaces, check each for stale marker
                    int sprayCount = 4;
                    IOSurfaceRef sprayed[4] = {};
                    for (int s = 0; s < sprayCount; s++) {
                        sprayed[s] = sym.create((__bridge CFDictionaryRef)params);
                    }

                    for (int s = 0; s < sprayCount; s++) {
                        if (!sprayed[s]) continue;
                        sym.lock(sprayed[s], 3, NULL);
                        void *sbase = sym.getBase(sprayed[s]);
                        if (sbase) {
                            uint8_t *p = (uint8_t *)sbase;
                            size_t checkSz = MIN(sym.getAllocSize(sprayed[s]), (size_t)4096);
                            int markerCount = 0;
                            for (size_t i = 0; i < checkSz; i++) {
                                if (p[i] == marker) markerCount++;
                            }
                            double ratio = (double)markerCount / checkSz;
                            if (ratio > 0.8) {
                                sizeLeaks++;
                                leaksDetected++;
                                anomalies++;
                                log([NSString stringWithFormat:
                                    @"BUFLEAK: LEAK %zux%zu trial=%u spray=%d marker=0x%02x ratio=%.1f%%",
                                    w, h, t, s, marker, ratio * 100]);
                            } else if (ratio > 0.1) {
                                sizePartials++;
                                partialLeaks++;
                                log([NSString stringWithFormat:
                                    @"BUFLEAK: PARTIAL %zux%zu trial=%u spray=%d marker=0x%02x ratio=%.1f%%",
                                    w, h, t, s, marker, ratio * 100]);
                            }
                        }
                        sym.unlock(sprayed[s], 0, NULL);
                    }
                    for (int s = 0; s < sprayCount; s++) {
                        if (sprayed[s]) CFRelease(sprayed[s]);
                    }
                }

                log([NSString stringWithFormat:
                    @"BUFLEAK: %zux%zu done — leaks=%u partial=%u", w, h, sizeLeaks, sizePartials]);
            }

            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:
                @"BUFLEAK: DONE trials=%u leaks=%u partial=%u anomalies=%u elapsed=%.3fs",
                trials * nSizes, leaksDetected, partialLeaks, anomalies, elapsed]);

            if (leaksDetected > 0) {
                log([NSString stringWithFormat:
                    @"BUFLEAK: CRITICAL — %u full leaks: freed surface data readable by new allocations", leaksDetected]);
            }

            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"totalTrials": @(trials * nSizes),
                @"leaksDetected": @(leaksDetected),
                @"partialLeaks": @(partialLeaks),
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-BufLeak-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

#pragma mark - Probe 8: IOKit Connection Types (Round 2)

void iosurface_research_conn_types(ISRLogBlock log, ISRDoneBlock done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"CONN: ERROR — failed to load symbols");
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            log(@"CONN: === IOKit Connection Type Scanner ===");
            log(@"CONN: Testing IOSurfaceRoot with connection types 0-15 and alternate tasks");

            CFDictionaryRef match = sym.matching("IOSurfaceRoot");
            if (!match) {
                log(@"CONN: ERROR — IOSurfaceRoot not found");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            // We need multiple match dicts since IOServiceGetMatchingService consumes them
            uint32_t accepted = 0;
            uint32_t rejected = 0;
            uint32_t anomalies = 0;
            uint32_t maxType = 15;
            CFAbsoluteTime startTime = CFAbsoluteTimeGetCurrent();

            // Phase A: Connection types 0-15 on IOSurfaceRoot
            log(@"CONN: Phase A — connection types 0-15");
            for (uint32_t connType = 0; connType <= maxType && !isr_stopped(); connType++) {
                isr_checkpoint(@"ISR-Conn-checkpoint.json", @{
                    @"phase": @"A", @"connType": @(connType), @"accepted": @(accepted)
                });

                CFDictionaryRef m = sym.matching("IOSurfaceRoot");
                if (!m) continue;
                io_service_t svc = sym.getMatch(MACH_PORT_NULL, m);
                if (!svc) continue;

                io_connect_t conn = 0;
                kern_return_t kr = sym.open(svc, mach_task_self(), connType, &conn);

                if (kr == KERN_SUCCESS && conn) {
                    accepted++;
                    log([NSString stringWithFormat:
                        @"CONN: ACCEPTED type=%u conn=0x%x", connType, conn]);

                    // Try selectors 0-5 on this connection type
                    for (uint32_t sel = 0; sel <= 5; sel++) {
                        uint64_t scalarOut[4] = {};
                        uint32_t scalarOutCnt = 4;
                        kern_return_t skr = sym.call(conn, sel, NULL, 0, NULL, 0,
                                                      scalarOut, &scalarOutCnt, NULL, NULL);
                        if (skr == KERN_SUCCESS) {
                            anomalies++;
                            log([NSString stringWithFormat:
                                @"CONN: ANOMALY type=%u sel=%u ACCEPTED scalarOut[0]=0x%llx",
                                connType, sel, scalarOut[0]]);
                        }
                    }
                    sym.close(conn);
                } else {
                    rejected++;
                    if (kr != KERN_INVALID_ARGUMENT &&
                        kr != 0xe00002be && // kIOReturnNotPermitted
                        kr != 0xe00002bc && // kIOReturnUnsupported
                        kr != 0xe0000001)   // kIOReturnError
                    {
                        anomalies++;
                        log([NSString stringWithFormat:
                            @"CONN: UNEXPECTED type=%u kr=0x%08x", connType, (unsigned)kr]);
                    }
                }
                sym.release(svc);
            }

            // Phase B: Try opening with different task ports
            log(@"CONN: Phase B — alternate task port variants");
            struct { mach_port_t port; const char *label; } tasks[] = {
                { mach_task_self(), "self" },
                { MACH_PORT_NULL, "null" },
                { 1, "port_1" },
                { MACH_PORT_DEAD, "dead" },
            };
            int nTasks = sizeof(tasks)/sizeof(tasks[0]);

            for (int ti = 0; ti < nTasks && !isr_stopped(); ti++) {
                CFDictionaryRef m2 = sym.matching("IOSurfaceRoot");
                if (!m2) continue;
                io_service_t svc2 = sym.getMatch(MACH_PORT_NULL, m2);
                if (!svc2) continue;

                io_connect_t conn2 = 0;
                kern_return_t kr2 = sym.open(svc2, tasks[ti].port, 0, &conn2);

                if (kr2 == KERN_SUCCESS && conn2) {
                    log([NSString stringWithFormat:
                        @"CONN: ACCEPTED task=%s conn=0x%x", tasks[ti].label, conn2]);
                    if (tasks[ti].port != mach_task_self()) {
                        anomalies++;
                        log([NSString stringWithFormat:
                            @"CONN: ANOMALY — non-self task '%s' accepted!", tasks[ti].label]);
                    }
                    sym.close(conn2);
                } else {
                    log([NSString stringWithFormat:
                        @"CONN: REJECTED task=%s kr=0x%08x", tasks[ti].label, (unsigned)kr2]);
                }
                sym.release(svc2);
            }

            // Phase C: Try other IOSurface-related services
            log(@"CONN: Phase C — related IOKit services");
            const char *services[] = {
                "IOSurfaceRoot",
                "IOSurfaceClient",
                "IOGraphicsAccelerator2",
                "IOMobileGraphicsFamily",
                "AppleCLCD",
                "IOAccelerator",
                "AGXAccelerator",
                "AGXFamilyAccelerator",
            };
            int nServices = sizeof(services)/sizeof(services[0]);

            for (int si = 1; si < nServices && !isr_stopped(); si++) {
                CFDictionaryRef m3 = sym.matching(services[si]);
                if (!m3) continue;
                io_service_t svc3 = sym.getMatch(MACH_PORT_NULL, m3);
                if (!svc3) {
                    log([NSString stringWithFormat:@"CONN: service '%s' not found", services[si]]);
                    continue;
                }

                io_connect_t conn3 = 0;
                kern_return_t kr3 = sym.open(svc3, mach_task_self(), 0, &conn3);
                if (kr3 == KERN_SUCCESS && conn3) {
                    anomalies++;
                    log([NSString stringWithFormat:
                        @"CONN: INTERESTING — '%s' opened! conn=0x%x", services[si], conn3]);
                    sym.close(conn3);
                } else {
                    log([NSString stringWithFormat:
                        @"CONN: '%s' rejected kr=0x%08x", services[si], (unsigned)kr3]);
                }
                sym.release(svc3);
            }

            double elapsed = CFAbsoluteTimeGetCurrent() - startTime;
            log([NSString stringWithFormat:
                @"CONN: DONE accepted=%u rejected=%u anomalies=%u elapsed=%.3fs",
                accepted, rejected, anomalies, elapsed]);

            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"accepted": @(accepted),
                @"rejected": @(rejected),
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-Conn-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

#pragma mark - Probe 9: Alloc Boundary (Round 2)

void iosurface_research_alloc_boundary(ISRLogBlock log, ISRDoneBlock done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"BOUNDARY: ERROR — failed to load symbols");
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            log(@"BOUNDARY: === Allocation Boundary Scanner ===");
            log(@"BOUNDARY: Probing exact rejection thresholds and mismatch behavior");

            uint32_t anomalies = 0;
            uint32_t created = 0;
            uint32_t rejected = 0;
            uint32_t mismatchHits = 0;
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();

            // Phase A: Binary search for exact max alloc threshold per width
            log(@"BOUNDARY: Phase A — binary search for max height at w=131071");
            size_t testW = 131071;
            size_t lo = 0, hi = 256;
            size_t lastAccepted = 0;

            while (lo <= hi && !isr_stopped()) {
                size_t mid = (lo + hi) / 2;
                if (mid == 0) { lo = 1; continue; }

                isr_checkpoint(@"ISR-Boundary-checkpoint.json", @{
                    @"phase": @"A", @"w": @(testW), @"testH": @(mid)
                });

                NSDictionary *params = isr_default_surface_params(testW, mid);
                IOSurfaceRef s = sym.create((__bridge CFDictionaryRef)params);
                if (s) {
                    lastAccepted = mid;
                    lo = mid + 1;
                    log([NSString stringWithFormat:@"BOUNDARY: w=%zu h=%zu ACCEPTED alloc=%zu",
                        testW, mid, sym.getAllocSize(s)]);
                    CFRelease(s);
                } else {
                    hi = mid - 1;
                    log([NSString stringWithFormat:@"BOUNDARY: w=%zu h=%zu REJECTED", testW, mid]);
                }
            }
            log([NSString stringWithFormat:@"BOUNDARY: w=%zu max_h=%zu", testW, lastAccepted]);

            // Phase B: Test bytesPerRow / allocSize mismatches near the boundary
            log(@"BOUNDARY: Phase B — bytesPerRow/allocSize mismatches at boundary");
            struct {
                size_t w, h, bpr, allocSz;
                const char *label;
            } mismatchTests[] = {
                // Correct bytesPerRow but undersized allocSize
                { 1024, 1024, 4096, 1024,        "undersized_alloc" },
                { 1024, 1024, 4096, 4096*1024+1,  "oversized_alloc_by_1" },
                { 1024, 1024, 4096, 4096*1024-1,  "undersized_alloc_by_1" },
                // bytesPerRow smaller than width*bpe
                { 1024, 1024, 1024, 1024*1024,    "bpr_too_small" },
                // bytesPerRow = 0
                { 1024, 1024, 0,    4096*1024,    "bpr_zero" },
                // Huge bytesPerRow but small alloc
                { 32, 32, 0x7FFFFFFF, 4096,        "bpr_huge" },
                // allocSize = 0
                { 64, 64, 256, 0,                  "alloc_zero" },
                // w*bpe overflow: w=0x40000000, bpe=4 => w*bpe = 0 (overflow)
                { 0x40000000, 1, 0, 4,              "width_overflow" },
                // h very large with small w
                { 1, 0x40000000, 4, 0x40000000UL*4, "height_overflow" },
                // Mismatched pixel format
                { 64, 64, 256, 64*4*64,            "normal_baseline" },
            };
            int nMismatch = sizeof(mismatchTests)/sizeof(mismatchTests[0]);

            for (int i = 0; i < nMismatch && !isr_stopped(); i++) {
                isr_checkpoint(@"ISR-Boundary-checkpoint.json", @{
                    @"phase": @"B", @"test": @(mismatchTests[i].label)
                });

                NSMutableDictionary *p = [NSMutableDictionary dictionary];
                p[@"IOSurfaceWidth"] = @(mismatchTests[i].w);
                p[@"IOSurfaceHeight"] = @(mismatchTests[i].h);
                p[@"IOSurfaceBytesPerElement"] = @4;
                p[@"IOSurfacePixelFormat"] = @(0x42475241);
                if (mismatchTests[i].bpr > 0)
                    p[@"IOSurfaceBytesPerRow"] = @(mismatchTests[i].bpr);
                if (mismatchTests[i].allocSz > 0)
                    p[@"IOSurfaceAllocSize"] = @(mismatchTests[i].allocSz);

                IOSurfaceRef s = sym.create((__bridge CFDictionaryRef)p);
                if (s) {
                    created++;
                    size_t actualW = sym.getWidth(s);
                    size_t actualH = sym.getHeight(s);
                    size_t actualAlloc = sym.getAllocSize(s);
                    BOOL wMismatch = (actualW != mismatchTests[i].w);
                    BOOL hMismatch = (actualH != mismatchTests[i].h);

                    log([NSString stringWithFormat:
                        @"BOUNDARY: CREATED '%s' w=%zu(req %zu) h=%zu(req %zu) alloc=%zu%s",
                        mismatchTests[i].label,
                        actualW, mismatchTests[i].w,
                        actualH, mismatchTests[i].h,
                        actualAlloc,
                        (wMismatch || hMismatch) ? " MISMATCH" : ""]);

                    if (wMismatch || hMismatch) {
                        mismatchHits++;
                    }

                    // Check if we can lock and access memory safely
                    kern_return_t lkr = sym.lock(s, 0, NULL);
                    if (lkr == KERN_SUCCESS) {
                        void *base = sym.getBase(s);
                        if (base && actualAlloc > 0) {
                            // Write and read back — detect if alloc is really that size
                            volatile uint8_t *vp = (volatile uint8_t *)base;
                            vp[0] = 0x42;
                            if (actualAlloc > 1) vp[actualAlloc - 1] = 0x43;
                            if (vp[0] != 0x42) {
                                anomalies++;
                                log([NSString stringWithFormat:
                                    @"BOUNDARY: ANOMALY '%s' — write/read mismatch at base!",
                                    mismatchTests[i].label]);
                            }
                        }
                        sym.unlock(s, 0, NULL);
                    }
                    CFRelease(s);
                } else {
                    rejected++;
                    log([NSString stringWithFormat:
                        @"BOUNDARY: REJECTED '%s'", mismatchTests[i].label]);
                }
            }

            // Phase C: Pixel format fuzzing — non-standard formats
            log(@"BOUNDARY: Phase C — pixel format edge cases");
            uint32_t formats[] = {
                0x42475241, // BGRA (normal)
                0x00000000, // zero
                0xFFFFFFFF, // max
                0x41524742, // ARGB (reversed)
                0x59555932, // YUV2
                0x4E563132, // NV12
                0x00000001, // unusual small value
                0x80000000, // high bit set
            };
            int nFormats = sizeof(formats)/sizeof(formats[0]);

            for (int fi = 0; fi < nFormats && !isr_stopped(); fi++) {
                NSDictionary *fp = @{
                    @"IOSurfaceWidth": @64,
                    @"IOSurfaceHeight": @64,
                    @"IOSurfaceBytesPerElement": @4,
                    @"IOSurfaceBytesPerRow": @(256),
                    @"IOSurfaceAllocSize": @(256 * 64),
                    @"IOSurfacePixelFormat": @(formats[fi])
                };
                IOSurfaceRef fs = sym.create((__bridge CFDictionaryRef)fp);
                if (fs) {
                    log([NSString stringWithFormat:
                        @"BOUNDARY: format=0x%08x CREATED alloc=%zu", formats[fi], sym.getAllocSize(fs)]);
                    CFRelease(fs);
                } else {
                    log([NSString stringWithFormat:
                        @"BOUNDARY: format=0x%08x REJECTED", formats[fi]]);
                }
            }

            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:
                @"BOUNDARY: DONE created=%u rejected=%u mismatches=%u anomalies=%u elapsed=%.3fs",
                created, rejected, mismatchHits, anomalies, elapsed]);

            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"created": @(created),
                @"rejected": @(rejected),
                @"mismatchHits": @(mismatchHits),
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-Boundary-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

#pragma mark - Probe 10: AGX Deep Scan (Round 3)

void iosurface_research_agx_scan(ISRLogBlock log, ISRDoneBlock done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"AGX: ERROR — failed to load symbols");
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            log(@"AGX: === GPU Driver Deep Scanner ===");
            log(@"AGX: Enumerating all GPU-related IOKit services and probing entry points");

            uint32_t anomalies = 0;
            uint32_t servicesFound = 0;
            uint32_t connectionsOpened = 0;
            uint32_t selectorsAccepted = 0;
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();

            // Phase A: Broad service enumeration — GPU-related class names
            const char *gpuServices[] = {
                "AGXAccelerator",
                "AGXFamilyAccelerator",
                "AGXAcceleratorG13G",
                "AGXAcceleratorG13P",
                "AGXAcceleratorG14P",
                "AGXAcceleratorG15",
                "IOGPUDevice",
                "IOGPUCommandQueue",
                "IOGPUResource",
                "IOGPU",
                "IOAccelerator",
                "IOAcceleratorFamily2",
                "IOSurfaceRoot",
                "IOSurfaceAccelerator",
                "AppleM1ANE",
                "AppleSPU",
                "IOMobileGraphicsFamily",
                "AppleAVE2",
                "AppleJPEG",
                "IOSurface",
                "AppleMobileDispH13G",
                "AppleCLCD2",
                "IOMobileFramebuffer",
            };
            int nServices = sizeof(gpuServices) / sizeof(gpuServices[0]);

            log([NSString stringWithFormat:@"AGX: Phase A — scanning %d GPU/media services", nServices]);

            for (int si = 0; si < nServices && !isr_stopped(); si++) {
                isr_checkpoint(@"ISR-AGX-checkpoint.json", @{
                    @"phase": @"A", @"service": @(gpuServices[si]), @"found": @(servicesFound)
                });

                CFDictionaryRef m = sym.matching(gpuServices[si]);
                if (!m) continue;
                io_service_t svc = sym.getMatch(MACH_PORT_NULL, m);
                if (!svc) {
                    continue;
                }

                servicesFound++;
                log([NSString stringWithFormat:@"AGX: FOUND '%s'", gpuServices[si]]);

                // Try connection types 0-7 on each found service
                for (uint32_t ct = 0; ct <= 7 && !isr_stopped(); ct++) {
                    io_connect_t conn = 0;
                    kern_return_t kr = sym.open(svc, mach_task_self(), ct, &conn);

                    if (kr == KERN_SUCCESS && conn) {
                        connectionsOpened++;
                        log([NSString stringWithFormat:
                            @"AGX: OPENED '%s' type=%u conn=0x%x", gpuServices[si], ct, conn]);

                        // Probe selectors 0-20 on opened connection
                        for (uint32_t sel = 0; sel <= 20 && !isr_stopped(); sel++) {
                            // Pattern 1: empty call
                            uint64_t scalarOut[8] = {};
                            uint32_t scalarOutCnt = 8;
                            kern_return_t skr = sym.call(conn, sel,
                                NULL, 0, NULL, 0,
                                scalarOut, &scalarOutCnt, NULL, NULL);

                            if (skr == KERN_SUCCESS) {
                                selectorsAccepted++;
                                NSMutableString *vals = [NSMutableString new];
                                for (uint32_t i = 0; i < scalarOutCnt; i++) {
                                    [vals appendFormat:@"0x%llx ", scalarOut[i]];
                                }
                                log([NSString stringWithFormat:
                                    @"AGX: ACCEPTED '%s' type=%u sel=%u out=[%@]",
                                    gpuServices[si], ct, sel, vals]);
                            }

                            // Pattern 2: scalar inputs
                            uint64_t scalarIn[4] = {0, 0, 0, 0};
                            scalarOutCnt = 8;
                            memset(scalarOut, 0, sizeof(scalarOut));
                            skr = sym.call(conn, sel,
                                scalarIn, 4, NULL, 0,
                                scalarOut, &scalarOutCnt, NULL, NULL);

                            if (skr == KERN_SUCCESS) {
                                selectorsAccepted++;
                                log([NSString stringWithFormat:
                                    @"AGX: ACCEPTED '%s' type=%u sel=%u (with scalars)",
                                    gpuServices[si], ct, sel]);
                            }

                            // Pattern 3: struct input with IOSurface-like properties
                            uint8_t structIn[64] = {};
                            *(uint32_t *)structIn = 64;        // size field
                            *(uint32_t *)(structIn + 4) = 0x1; // type field
                            uint8_t structOut[256] = {};
                            size_t structOutSz = sizeof(structOut);
                            scalarOutCnt = 8;
                            memset(scalarOut, 0, sizeof(scalarOut));
                            skr = sym.call(conn, sel,
                                NULL, 0, structIn, sizeof(structIn),
                                scalarOut, &scalarOutCnt, structOut, &structOutSz);

                            if (skr == KERN_SUCCESS) {
                                selectorsAccepted++;
                                BOOL hasData = NO;
                                for (size_t i = 0; i < structOutSz && i < 64; i++) {
                                    if (structOut[i] != 0) { hasData = YES; break; }
                                }
                                if (hasData) {
                                    NSMutableString *hex = [NSMutableString new];
                                    for (size_t i = 0; i < MIN(structOutSz, (size_t)32); i++) {
                                        [hex appendFormat:@"%02x", structOut[i]];
                                        if ((i + 1) % 8 == 0) [hex appendString:@" "];
                                    }
                                    log([NSString stringWithFormat:
                                        @"AGX: DATA '%s' sel=%u structOut[%zu]: %@",
                                        gpuServices[si], sel, structOutSz, hex]);
                                    anomalies++;
                                }
                            }

                            // Detect unexpected codes
                            if (skr != KERN_SUCCESS &&
                                skr != KERN_INVALID_ARGUMENT &&
                                skr != KERN_NOT_SUPPORTED &&
                                skr != 0xe00002c2 &&
                                skr != 0xe00002bc &&
                                skr != 0xe00002be &&
                                skr != 0xe0000001 &&
                                skr != 0xe00002cd)
                            {
                                anomalies++;
                                log([NSString stringWithFormat:
                                    @"AGX: UNUSUAL_KR '%s' type=%u sel=%u kr=0x%08x",
                                    gpuServices[si], ct, sel, (unsigned)skr]);
                            }
                        }

                        sym.close(conn);
                    }
                }
                sym.release(svc);
            }

            // Phase B: IORegistryEntry property dump for found GPU services
            log(@"AGX: Phase B — registry property extraction via IOSurface side-channel");

            // Use IOSurface with GPU-hint properties to probe kernel behavior
            NSDictionary *gpuHintSurface = @{
                @"IOSurfaceWidth": @256,
                @"IOSurfaceHeight": @256,
                @"IOSurfaceBytesPerElement": @4,
                @"IOSurfaceBytesPerRow": @1024,
                @"IOSurfaceAllocSize": @(1024 * 256),
                @"IOSurfacePixelFormat": @(0x42475241),
                @"IOSurfaceCacheMode": @1,        // kIOMapWriteCombineCache
                @"IOSurfaceIsGlobal": @YES,
            };
            IOSurfaceRef gpuSurf = sym.create((__bridge CFDictionaryRef)gpuHintSurface);
            if (gpuSurf) {
                IOSurfaceID gid = sym.getID(gpuSurf);
                size_t galloc = sym.getAllocSize(gpuSurf);
                log([NSString stringWithFormat:
                    @"AGX: GPU-hint surface created id=%u alloc=%zu (isGlobal requested)",
                    gid, galloc]);

                // Check if isGlobal actually took effect — try lookup
                IOSurfaceRef looked = sym.lookup(gid);
                if (looked) {
                    log(@"AGX: Global surface lookup succeeded (expected for same process)");
                    CFRelease(looked);
                }

                // Try different cache modes
                uint32_t cacheModes[] = {0, 1, 2, 3, 4, 5};
                for (int ci = 0; ci < 6 && !isr_stopped(); ci++) {
                    NSDictionary *cp = @{
                        @"IOSurfaceWidth": @64,
                        @"IOSurfaceHeight": @64,
                        @"IOSurfaceBytesPerElement": @4,
                        @"IOSurfaceBytesPerRow": @256,
                        @"IOSurfaceAllocSize": @(256 * 64),
                        @"IOSurfacePixelFormat": @(0x42475241),
                        @"IOSurfaceCacheMode": @(cacheModes[ci]),
                    };
                    IOSurfaceRef cs = sym.create((__bridge CFDictionaryRef)cp);
                    if (cs) {
                        log([NSString stringWithFormat:
                            @"AGX: cacheMode=%u ACCEPTED alloc=%zu", cacheModes[ci], sym.getAllocSize(cs)]);

                        // Write+read to check if cache mode changes memory behavior
                        sym.lock(cs, 0, NULL);
                        void *base = sym.getBase(cs);
                        if (base) {
                            volatile uint32_t *p = (volatile uint32_t *)base;
                            p[0] = 0xDEADBEEF;
                            __sync_synchronize();
                            uint32_t readback = p[0];
                            if (readback != 0xDEADBEEF) {
                                anomalies++;
                                log([NSString stringWithFormat:
                                    @"AGX: ANOMALY cacheMode=%u write/read mismatch: wrote 0xDEADBEEF read 0x%08x",
                                    cacheModes[ci], readback]);
                            }
                        }
                        sym.unlock(cs, 0, NULL);
                        CFRelease(cs);
                    } else {
                        log([NSString stringWithFormat:@"AGX: cacheMode=%u REJECTED", cacheModes[ci]]);
                    }
                }
                CFRelease(gpuSurf);
            }

            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:
                @"AGX: DONE services=%u connections=%u selectors=%u anomalies=%u elapsed=%.3fs",
                servicesFound, connectionsOpened, selectorsAccepted, anomalies, elapsed]);

            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"servicesFound": @(servicesFound),
                @"connectionsOpened": @(connectionsOpened),
                @"selectorsAccepted": @(selectorsAccepted),
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-AGX-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

#pragma mark - Probe 11: Format Corruption Render (Round 3)

void iosurface_research_format_render(ISRLogBlock log, ISRDoneBlock done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"FMTRENDER: ERROR — failed to load symbols");
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            log(@"FMTRENDER: === Format Corruption + CoreGraphics Render ===");
            log(@"FMTRENDER: Creates surfaces with invalid formats, renders via CGBitmapContext");

            uint32_t anomalies = 0;
            uint32_t renderSuccess = 0;
            uint32_t renderFail = 0;
            uint32_t dataLeaks = 0;
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();

            // dlsym CoreGraphics functions
            void *cg = dlopen("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics",
                              RTLD_LAZY | RTLD_LOCAL);
            if (!cg) {
                log(@"FMTRENDER: ERROR — failed to load CoreGraphics");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            typedef CGColorSpaceRef (*CGColorSpaceCreateFn)(void);
            typedef CGContextRef (*CGBitmapContextCreateFn)(void *, size_t, size_t, size_t, size_t,
                                                             CGColorSpaceRef, uint32_t);
            typedef void (*CGContextReleaseFn)(CGContextRef);
            typedef void (*CGColorSpaceReleaseFn)(CGColorSpaceRef);
            typedef CGImageRef (*CGBitmapContextCreateImageFn)(CGContextRef);
            typedef void (*CGImageReleaseFn)(CGImageRef);
            typedef void (*CGContextSetRGBFillColorFn)(CGContextRef, CGFloat, CGFloat, CGFloat, CGFloat);
            typedef void (*CGContextFillRectFn)(CGContextRef, CGRect);

            CGColorSpaceCreateFn cgCreateSRGB = (CGColorSpaceCreateFn)dlsym(cg, "CGColorSpaceCreateDeviceRGB");
            CGBitmapContextCreateFn cgBitmapCreate = (CGBitmapContextCreateFn)dlsym(cg, "CGBitmapContextCreate");
            CGContextReleaseFn cgCtxRelease = (CGContextReleaseFn)dlsym(cg, "CGContextRelease");
            CGColorSpaceReleaseFn cgCSRelease = (CGColorSpaceReleaseFn)dlsym(cg, "CGColorSpaceRelease");
            CGBitmapContextCreateImageFn cgCreateImage = (CGBitmapContextCreateImageFn)dlsym(cg, "CGBitmapContextCreateImage");
            CGImageReleaseFn cgImgRelease = (CGImageReleaseFn)dlsym(cg, "CGImageRelease");
            CGContextSetRGBFillColorFn cgSetFill = (CGContextSetRGBFillColorFn)dlsym(cg, "CGContextSetRGBFillColor");
            CGContextFillRectFn cgFillRect = (CGContextFillRectFn)dlsym(cg, "CGContextFillRect");

            if (!cgCreateSRGB || !cgBitmapCreate || !cgCtxRelease || !cgCSRelease) {
                log(@"FMTRENDER: ERROR — CoreGraphics symbols missing");
                dlclose(cg);
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            CGColorSpaceRef cs = cgCreateSRGB();

            // Test matrix: create IOSurface with format X, then attempt CGBitmapContext on its buffer
            struct {
                uint32_t format;
                uint32_t cgBitmapInfo;
                const char *label;
            } tests[] = {
                { 0x42475241, 1 | (2 << 12), "BGRA_premul" },           // normal
                { 0x00000000, 1 | (2 << 12), "zero_fmt_premul" },       // zero format
                { 0xFFFFFFFF, 1 | (2 << 12), "max_fmt_premul" },        // max format
                { 0x42475241, 0,              "BGRA_none" },              // no alpha
                { 0x42475241, 6 | (2 << 12), "BGRA_float" },            // float components
                { 0x00000001, 1 | (2 << 12), "tiny_fmt_premul" },       // format=1
                { 0x80000000, 1 | (2 << 12), "highbit_fmt_premul" },    // high bit
                { 0x42475241, 1 | (3 << 12), "BGRA_premul_first" },     // alphaFirst
                { 0x42475241, 2 | (2 << 12), "BGRA_last_premul" },      // alphaLast+premul
            };
            int nTests = sizeof(tests) / sizeof(tests[0]);

            size_t w = 64, h = 64, bpr = w * 4;

            for (int ti = 0; ti < nTests && !isr_stopped(); ti++) {
                isr_checkpoint(@"ISR-FmtRender-checkpoint.json", @{
                    @"test": @(tests[ti].label), @"anomalies": @(anomalies)
                });

                NSDictionary *params = @{
                    @"IOSurfaceWidth": @(w),
                    @"IOSurfaceHeight": @(h),
                    @"IOSurfaceBytesPerElement": @4,
                    @"IOSurfaceBytesPerRow": @(bpr),
                    @"IOSurfaceAllocSize": @(bpr * h),
                    @"IOSurfacePixelFormat": @(tests[ti].format),
                };
                IOSurfaceRef surf = sym.create((__bridge CFDictionaryRef)params);
                if (!surf) {
                    log([NSString stringWithFormat:@"FMTRENDER: '%s' surface creation failed", tests[ti].label]);
                    continue;
                }

                // Write sentinel pattern to IOSurface buffer
                sym.lock(surf, 0, NULL);
                void *base = sym.getBase(surf);
                if (base) {
                    memset(base, 0xCC, bpr * h);
                }
                sym.unlock(surf, 0, NULL);

                // Create CGBitmapContext on the IOSurface's buffer
                sym.lock(surf, 0, NULL);
                base = sym.getBase(surf);
                CGContextRef ctx = NULL;
                BOOL renderOK = NO;

                if (base) {
                    ctx = cgBitmapCreate(base, w, h, 8, bpr, cs, tests[ti].cgBitmapInfo);
                    if (ctx) {
                        renderSuccess++;
                        renderOK = YES;

                        // Draw something via CoreGraphics
                        if (cgSetFill && cgFillRect) {
                            cgSetFill(ctx, 1.0, 0.0, 0.0, 1.0); // red
                            cgFillRect(ctx, CGRectMake(0, 0, w, h));
                        }

                        // Create image to force render pipeline
                        if (cgCreateImage) {
                            CGImageRef img = cgCreateImage(ctx);
                            if (img) {
                                if (cgImgRelease) cgImgRelease(img);
                            }
                        }

                        // Check if the buffer was actually modified by CG
                        uint8_t *p = (uint8_t *)base;
                        int ccCount = 0;
                        for (size_t i = 0; i < MIN(bpr * h, (size_t)1024); i++) {
                            if (p[i] == 0xCC) ccCount++;
                        }
                        double sentinel_ratio = (double)ccCount / MIN(bpr * h, (size_t)1024);

                        if (sentinel_ratio > 0.9) {
                            anomalies++;
                            log([NSString stringWithFormat:
                                @"FMTRENDER: ANOMALY '%s' — CG accepted context but did NOT modify buffer (%.0f%% sentinel intact)",
                                tests[ti].label, sentinel_ratio * 100]);
                        } else {
                            log([NSString stringWithFormat:
                                @"FMTRENDER: '%s' rendered OK (%.0f%% sentinel overwritten)",
                                tests[ti].label, (1.0 - sentinel_ratio) * 100]);
                        }

                        cgCtxRelease(ctx);
                    } else {
                        renderFail++;
                        log([NSString stringWithFormat:
                            @"FMTRENDER: '%s' CGBitmapContext creation failed", tests[ti].label]);
                    }
                }
                sym.unlock(surf, 0, NULL);

                // Phase 2: Check if unreleased IOSurface with active CG render causes issues
                // Create a second surface, render to it, then lookup the first by ID
                if (renderOK) {
                    IOSurfaceID sid = sym.getID(surf);
                    IOSurfaceRef lookup = sym.lookup(sid);
                    if (lookup) {
                        sym.lock(lookup, 3, NULL); // read only
                        void *lbase = sym.getBase(lookup);
                        if (lbase && base) {
                            // Compare: lookup buffer should match original after CG render
                            if (memcmp(base, lbase, MIN((size_t)256, bpr * h)) != 0) {
                                anomalies++;
                                dataLeaks++;
                                log([NSString stringWithFormat:
                                    @"FMTRENDER: ANOMALY '%s' — lookup buffer differs from original after render!",
                                    tests[ti].label]);
                            }
                        }
                        sym.unlock(lookup, 0, NULL);
                        CFRelease(lookup);
                    }
                }

                CFRelease(surf);
            }

            if (cs) cgCSRelease(cs);
            dlclose(cg);

            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:
                @"FMTRENDER: DONE rendered=%u failed=%u dataLeaks=%u anomalies=%u elapsed=%.3fs",
                renderSuccess, renderFail, dataLeaks, anomalies, elapsed]);

            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"renderSuccess": @(renderSuccess),
                @"renderFail": @(renderFail),
                @"dataLeaks": @(dataLeaks),
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-FmtRender-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

#pragma mark - Probe 12: Cross-Reference Attack (Round 3)

void iosurface_research_xref_attack(ISRLogBlock log, ISRDoneBlock done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"XREF: ERROR — failed to load symbols");
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            log(@"XREF: === Cross-Reference Property Confusion Attack ===");
            log(@"XREF: Tests if kernel trusts cached surface metadata across connections");

            uint32_t anomalies = 0;
            uint32_t confusionHits = 0;
            uint32_t timingHits = 0;
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();

            // Phase A: Property confusion — create surface, lookup, check if properties match
            log(@"XREF: Phase A — property confusion via lookup");

            struct {
                size_t w, h;
                const char *label;
            } surfacePairs[] = {
                { 64, 64, "small" },
                { 512, 512, "medium" },
                { 1024, 1, "wide_thin" },
                { 1, 1024, "narrow_tall" },
                { 131071, 1, "max_width" },
            };
            int nPairs = sizeof(surfacePairs) / sizeof(surfacePairs[0]);

            for (int pi = 0; pi < nPairs && !isr_stopped(); pi++) {
                isr_checkpoint(@"ISR-Xref-checkpoint.json", @{
                    @"phase": @"A", @"pair": @(surfacePairs[pi].label)
                });

                size_t w = surfacePairs[pi].w, h = surfacePairs[pi].h;
                NSDictionary *params = isr_default_surface_params(w, h);
                IOSurfaceRef creator = sym.create((__bridge CFDictionaryRef)params);
                if (!creator) {
                    log([NSString stringWithFormat:@"XREF: '%s' creation failed", surfacePairs[pi].label]);
                    continue;
                }

                IOSurfaceID sid = sym.getID(creator);
                size_t cw = sym.getWidth(creator);
                size_t ch = sym.getHeight(creator);
                size_t calloc = sym.getAllocSize(creator);

                // Lookup from "another context" (same process, different reference)
                IOSurfaceRef looked = sym.lookup(sid);
                if (!looked) {
                    log([NSString stringWithFormat:@"XREF: '%s' lookup failed", surfacePairs[pi].label]);
                    CFRelease(creator);
                    continue;
                }

                size_t lw = sym.getWidth(looked);
                size_t lh = sym.getHeight(looked);
                size_t lalloc = sym.getAllocSize(looked);

                BOOL confused = (cw != lw || ch != lh || calloc != lalloc);
                if (confused) {
                    confusionHits++;
                    anomalies++;
                    log([NSString stringWithFormat:
                        @"XREF: CONFUSION '%s' creator=%zux%zu(%zu) lookup=%zux%zu(%zu)",
                        surfacePairs[pi].label, cw, ch, calloc, lw, lh, lalloc]);
                } else {
                    log([NSString stringWithFormat:
                        @"XREF: '%s' consistent %zux%zu alloc=%zu", surfacePairs[pi].label, lw, lh, lalloc]);
                }

                // Phase A.2: Write via creator, read via lookup — check coherency
                sym.lock(creator, 0, NULL);
                void *cbase = sym.getBase(creator);
                if (cbase) {
                    memset(cbase, 0x42, MIN(calloc, (size_t)4096));
                }
                sym.unlock(creator, 0, NULL);

                sym.lock(looked, 3, NULL);
                void *lbase = sym.getBase(looked);
                if (lbase && cbase) {
                    uint8_t *p = (uint8_t *)lbase;
                    int match = 0;
                    size_t check = MIN(lalloc, (size_t)4096);
                    for (size_t i = 0; i < check; i++) {
                        if (p[i] == 0x42) match++;
                    }
                    double ratio = (double)match / check;
                    if (ratio < 0.9) {
                        anomalies++;
                        log([NSString stringWithFormat:
                            @"XREF: ANOMALY '%s' — lookup reads only %.0f%% of creator's writes!",
                            surfacePairs[pi].label, ratio * 100]);
                    }
                }
                sym.unlock(looked, 0, NULL);

                CFRelease(looked);
                CFRelease(creator);
            }

            // Phase B: Race between destroy and lookup — try to catch stale metadata
            log(@"XREF: Phase B — destroy/lookup race for stale metadata");
            uint32_t raceTrials = 500;
            uint32_t staleMetadata = 0;

            for (uint32_t t = 0; t < raceTrials && !isr_stopped(); t++) {
                NSDictionary *params = isr_default_surface_params(128, 128);
                IOSurfaceRef s = sym.create((__bridge CFDictionaryRef)params);
                if (!s) continue;

                IOSurfaceID sid = sym.getID(s);
                size_t origW = sym.getWidth(s);

                // Release creator
                CFRelease(s);

                // Immediately create a DIFFERENT sized surface hoping to reuse the ID
                NSDictionary *params2 = isr_default_surface_params(256, 32);
                IOSurfaceRef s2 = sym.create((__bridge CFDictionaryRef)params2);
                if (!s2) continue;

                IOSurfaceID sid2 = sym.getID(s2);

                if (sid2 == sid) {
                    // Same ID reused — check if lookup returns new or stale dimensions
                    IOSurfaceRef looked2 = sym.lookup(sid);
                    if (looked2) {
                        size_t lookW = sym.getWidth(looked2);
                        size_t s2W = sym.getWidth(s2);

                        if (lookW != s2W) {
                            staleMetadata++;
                            anomalies++;
                            log([NSString stringWithFormat:
                                @"XREF: STALE trial=%u id=%u lookup_w=%zu expected=%zu orig=%zu",
                                t, sid, lookW, s2W, origW]);
                        }
                        CFRelease(looked2);
                    }
                    timingHits++;
                }
                CFRelease(s2);
            }

            log([NSString stringWithFormat:
                @"XREF: Phase B — %u/%u ID reuses, %u stale metadata hits",
                timingHits, raceTrials, staleMetadata]);

            // Phase C: Concurrent lookup + property read race
            log(@"XREF: Phase C — concurrent lookup/property-read race");
            __block uint32_t propRaceAnomalies = 0;
            NSDictionary *raceParams = isr_default_surface_params(64, 64);
            IOSurfaceRef raceSurf = sym.create((__bridge CFDictionaryRef)raceParams);

            if (raceSurf) {
                IOSurfaceID raceID = sym.getID(raceSurf);
                dispatch_group_t group = dispatch_group_create();
                dispatch_queue_t q = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0);

                for (int thread = 0; thread < 4; thread++) {
                    dispatch_group_async(group, q, ^{
                        for (int i = 0; i < 1000 && !isr_stopped(); i++) {
                            IOSurfaceRef l = sym.lookup(raceID);
                            if (l) {
                                size_t rw = sym.getWidth(l);
                                size_t rh = sym.getHeight(l);
                                if (rw != 64 || rh != 64) {
                                    OSAtomicIncrement32((volatile int32_t *)&propRaceAnomalies);
                                }
                                CFRelease(l);
                            }
                        }
                    });
                }

                dispatch_group_wait(group, DISPATCH_TIME_FOREVER);
                CFRelease(raceSurf);

                if (propRaceAnomalies > 0) {
                    anomalies += propRaceAnomalies;
                    log([NSString stringWithFormat:
                        @"XREF: ANOMALY Phase C — %u property inconsistencies during concurrent lookup",
                        propRaceAnomalies]);
                } else {
                    log(@"XREF: Phase C — 4000 concurrent lookups, properties consistent");
                }
            }

            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:
                @"XREF: DONE confusion=%u staleMetadata=%u propRace=%u anomalies=%u elapsed=%.3fs",
                confusionHits, staleMetadata, propRaceAnomalies, anomalies, elapsed]);

            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"confusionHits": @(confusionHits),
                @"staleMetadata": @(staleMetadata),
                @"propRaceAnomalies": @(propRaceAnomalies),
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-Xref-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

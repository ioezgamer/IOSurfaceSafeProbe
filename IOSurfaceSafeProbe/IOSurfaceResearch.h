//
//  IOSurfaceResearch.h
//  IOSurfaceSafeProbe
//
//  IOSurface vulnerability research module for iOS 27.
//  Educational security research on user's own device.
//  GPL-3.0-or-later.
//

#import <Foundation/Foundation.h>

typedef void (^ISRLogBlock)(NSString * _Nonnull message);
typedef void (^ISRDoneBlock)(NSDictionary * _Nonnull results);

/// Probe 1: Race condition detector — concurrent create/destroy with ID reuse monitoring.
void iosurface_research_race(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 2: Property corruption scanner — integer overflow, edge-case dimensions, lock/unlock consistency.
void iosurface_research_properties(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 3: Reference count probe — multi-connection lookup and ordered close for refcount imbalances.
void iosurface_research_refcount(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 4: Cross-process sharing probe — creator-destroy while lookup references exist.
void iosurface_research_sharing(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 5: Mach port / IOKit selector scanner — boundary selectors 0–32 on IOSurfaceRoot.
void iosurface_research_mach(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// --- Round 2: Advanced probes ---

/// Probe 6: Timed race — mach_absolute_time precision UAF window between ID recycle.
void iosurface_research_timed_race(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 7: Pixel buffer leak — write patterns, destroy, check if content persists in recycled surface.
void iosurface_research_buffer_leak(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 8: IOKit connection types — try different owningTask / connection type variants on IOSurfaceRoot.
void iosurface_research_conn_types(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 9: Alloc boundary — dimensions at exact rejection thresholds from Round 1 data.
void iosurface_research_alloc_boundary(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// --- Round 3: Targeted exploitation vectors ---

/// Probe 10: AGX deep scan — enumerate GPU services, connection types, selector fuzzing on AGX.
void iosurface_research_agx_scan(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 11: Format corruption — create surfaces with invalid formats, render via CoreGraphics.
void iosurface_research_format_render(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 12: Cross-reference attack — share surfaces between connections with conflicting properties.
void iosurface_research_xref_attack(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// --- Round 4: Deep exploitation vectors ---

/// Probe 13: IOMobileFramebuffer deep scan — selector fuzzing on all 8 connection types.
void iosurface_research_framebuffer(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 14: Format mismatch attack — pass IOSurface buffers to CG with conflicting bitmap info.
void iosurface_research_format_mismatch(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 15: Kernel info leak — extract metadata, seed values, plane info for kernel pointer disclosure.
void iosurface_research_info_leak(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// --- Round 5: Exploitation primitives ---

/// Probe 16: Heap spray — measure address distribution and grooming success for IOSurface buffers.
void iosurface_research_heap_spray(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 17: UAF window — nanosecond-precision timing of ID reuse and residual data detection.
void iosurface_research_uaf_window(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 18: Kernel timing oracle — side-channel timing analysis of IOSurface kernel operations.
void iosurface_research_timing_oracle(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// --- Round 6: Combined attack chains ---

/// Probe 19: Heap Feng Shui — precise object placement with spray, grooming and cross-boundary probing.
void iosurface_research_feng_shui(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 20: Cache covert channel — build reliable timing oracle from lock/unlock, measure bandwidth.
void iosurface_research_cache_channel(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 21: Confused deputy — pass IOSurface handles through IOKit services, test unvalidated access.
void iosurface_research_confused_deputy(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Stop any running probe.
void iosurface_research_stop(void);

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

/// Stop any running probe.
void iosurface_research_stop(void);

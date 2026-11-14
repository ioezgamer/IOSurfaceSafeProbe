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

// --- Round 7: Deep kernel attack surface ---

/// Probe 22: Property injection — stress kernel property dictionary with oversized/reserved keys.
void iosurface_research_property_inject(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 23: Plane overlap — multi-plane surfaces with overlapping offsets for cross-plane reads.
void iosurface_research_plane_overlap(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 24: Mach port race — port lifecycle attacks, reuse, and 50-thread race condition.
void iosurface_research_port_race(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// --- Round 8: Exploit confirmed vulnerabilities ---

/// Probe 25: Phantom plane — write to phantom planes in format-mismatched surfaces.
void iosurface_research_phantom_plane(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 26: Global spy — espionage via IOSurfaceIsGlobal cross-lookup and tampering.
void iosurface_research_global_spy(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 27: ID oracle — predictable ID exploitation and stale reference persistence.
void iosurface_research_id_oracle(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// --- Round 9: CG Overflow exploitation chain ---

/// Probe 28: CG overflow amplifier — maximum overflow, cross-surface read, 16bpc confusion.
void iosurface_research_cg_overflow(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 29: Spray+CG chain — heap spray with CG overflow for cross-surface data harvest.
void iosurface_research_spray_cg_chain(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 30: Global+overflow combo — global surface as overflow target with entropy analysis.
void iosurface_research_global_overflow(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// --- Round 10: Real exploitation probes ---

/// Probe 31: CG cross-plane read — actual OOB read of plane1 data via CG h=128 within allocSize.
void iosurface_research_cg_crossplane_read(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 32: Mach port surface hijack — transfer surface via mach port, tamper from second ref.
void iosurface_research_mach_hijack(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 33: Global surface TOCTOU — race between lookup and write for time-of-check/time-of-use.
void iosurface_research_global_toctou(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// --- Round 11: System service TOCTOU attacks ---

/// Probe 34: Compositor TOCTOU — race against backboardd render server via CALayer-backed IOSurface.
void iosurface_research_compositor_race(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 35: System surface sniff — detect system daemon access via use-count and bootstrap enumeration.
void iosurface_research_system_sniff(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 36: Render server corruption — dual-plane surface as compositor input for cross-plane leak.
void iosurface_research_render_corrupt(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// --- Round 12: Aggressive exploitation chains ---

/// Probe 37: UAF compositor — free surface while compositor still renders it, detect stale access.
void iosurface_research_compositor_uaf(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 38: Kernel metadata harvest — extract all IOSurface properties to find kernel pointer leaks.
void iosurface_research_kernel_harvest(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 39: Full chain — combine mach port hijack + compositor TOCTOU + CG OOB for multi-primitive attack.
void iosurface_research_full_chain(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// --- Round 13: Real exploit primitives ---

/// Probe 40: UAF realloc — release+reclaim backing memory, write via dangling ref to corrupt new surface.
void iosurface_research_uaf_realloc(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 41: ASLR defeat — collect base addresses from multiple surfaces to compute kernel ASLR slide.
void iosurface_research_aslr_defeat(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 42: Read-write primitive — dangling write + CG OOB read for controlled cross-surface data flow.
void iosurface_research_rw_primitive(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// --- Round 14: Kernel boundary attacks ---

/// Probe 43: Kalloc zone overlap — free IOSurface backing, spray kernel objects to reclaim, detect overlap.
void iosurface_research_kalloc_overlap(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 44: Property kernel corruption — stress IOSurface property dictionary to corrupt kernel OSDictionary.
void iosurface_research_property_corrupt(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 45: Mach port kernel spray — spray ipc_port objects to reclaim freed IOSurface memory, detect kernel data.
void iosurface_research_port_kernel_spray(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// --- Round 15: Kernel R/W hunt ---

/// Probe 46: Property size confusion — override AllocSize in kernel dict, attempt OOB read beyond real backing.
void iosurface_research_size_confusion(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 47: BytesPerRow overflow — override BytesPerRow in kernel dict, use CG to read with corrupted stride.
void iosurface_research_bpr_overflow(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 48: Mach port property chain — property override + mach port transfer + CG OOB for kernel-adjacent read.
void iosurface_research_port_prop_chain(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// --- Round 16: Kernel R/W weaponization ---

/// Probe 49: Stride kernel probe — use stride confusion to read kernel-adjacent memory via vm_read at kalloc-zone offsets.
void iosurface_research_stride_kernel(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 50: Cross-surface corruption — stride write to corrupt adjacent surface's OSDictionary properties.
void iosurface_research_xsurf_corrupt(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 51: Fake object forge — stride overflow write to inject fake kernel object patterns in adjacent surface memory.
void iosurface_research_fake_object(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// --- Round 17: Mach port structure exploitation ---

/// Probe 52: Port structure map — fine-grained OOB dump to map ipc_port layout and identify kernel fields.
void iosurface_research_port_map(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 53: Port field corruption — write to ipc_port fields via stride OOB, verify via mach_port_get_refs.
void iosurface_research_port_corrupt(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 54: Kernel R/W chain — full chain: spray + port locate + kobject read + redirect + arbitrary R/W.
void iosurface_research_krw_chain(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// --- Round 18: Stable heap grooming ---

/// Probe 55: Mega spray groom — massive heap grooming for reliable port adjacency.
void iosurface_research_mega_spray(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 56: Iterative port hunt — repeat spray+scan cycles until port found, then map completely.
void iosurface_research_port_hunt(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 57: Kobject redirect — full kernel R/W via iterative port locate + kobject redirect.
void iosurface_research_kobject_redirect(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// --- Round 19: Property Dictionary Hijack ---

/// Probe 58: Dict hijack — stride OOB write to corrupt adjacent surface properties via IOSurfaceCopyValue.
void iosurface_research_dict_hijack(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 59: Prop fake — write crafted patterns via stride OOB, check if target surface getters return corrupted values.
void iosurface_research_prop_fake(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 60: Kernel read — find target surface metadata in OOB, corrupt size fields, scan expanded memory for kernel pointers.
void iosurface_research_kernel_read(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Stop any running probe.
void iosurface_research_stop(void);

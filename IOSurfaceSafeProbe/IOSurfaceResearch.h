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

// --- Round 20: Kalloc Zone Reclaim ---

/// Probe 61: Zone spray — spray IOSurface properties into kalloc zones, free/reclaim, detect cross-contamination.
void iosurface_research_zone_spray(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 62: Zone reclaim — destroy surface, spray mach OOL data into freed zone, read stale reference.
void iosurface_research_zone_reclaim(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 63: Ptr leak — full chain: zone spray + reclaim + scan for kernel pointer patterns.
void iosurface_research_ptr_leak(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// --- Round 21: Kalloc Bucket Precision ---

/// Probe 64: Kalloc size sweep — try multiple OOL sizes to find the exact kalloc bucket that overlaps with IOSurface property storage.
void iosurface_research_size_sweep(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 65: Property cross-spray — use IOSurface properties as both victim and spray for guaranteed same-bucket reclaim.
void iosurface_research_prop_spray(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 66: ID reuse confusion — destroy surface and create many until same ID is assigned, check for property confusion.
void iosurface_research_id_reuse(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// --- Round 22: Internal Key Exploitation ---

/// Probe 67: Key enum — enumerate all internal IOSurface keys via IOSurfaceCopyValue.
void iosurface_research_key_enum(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 68: Key override — write controlled values to internal keys, check if surface behavior changes.
void iosurface_research_key_override(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 69: Address redirect — attempt to redirect surface mapping via internal key manipulation.
void iosurface_research_addr_redirect(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// --- Round 23: IOKit Brute Force ---

/// Probe 70: IOKit brute — massive selector fuzzing on IOSurfaceRootUserClient with crafted inputs.
void iosurface_research_iokit_brute(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 71: Struct overflow — oversized struct inputs to accepting selectors, trigger kernel OOB.
void iosurface_research_struct_overflow(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 72: Race exploit — multi-threaded IOConnectCallMethod + create/destroy TOCTOU race.
void iosurface_research_race_exploit(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// --- Round 24: GPU/Metal Exploitation ---

/// Probe 73: Metal corrupt — pass IOSurface to Metal as texture, modify stride mid-render for GPU OOB.
void iosurface_research_metal_corrupt(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 74: AGX driver — fuzz selectors on AGXAccelerator/AGXG15P GPU driver, much larger attack surface.
void iosurface_research_agx_driver(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 75: GPU DMA race — race between CPU modifying IOSurface and GPU rendering, exploit DMA window.
void iosurface_research_gpu_dma_race(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// --- Round 25: Deep Service Exploitation ---

/// Probe 76: IOMobileFramebuffer deep — intensive selector fuzzing on type 4 with crafted structs, output capture, memory mapping.
void iosurface_research_fb_deep(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 77: AppleJPEGDriver exploit — fuzz selectors on all 5 connection types with JPEG markers and IOSurface IDs.
void iosurface_research_jpeg_exploit(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 78: Service chain — pass IOSurface through IOMobileFramebuffer and AppleJPEGDriver, detect cross-service memory corruption.
void iosurface_research_service_chain(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// --- Round 26: Maximum Aggression ---

/// Probe 79: VM remap attack — mach_vm_remap IOSurface pages, destroy surface, read freed kernel memory.
void iosurface_research_vm_remap(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 80: IOSurfaceAccelerator — find and fuzz hardware blit services for OOB via stride mismatch.
void iosurface_research_surf_accel(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 81: Syscall storm — task_info, mach_make_memory_entry, vm_remap, mach_vm_region for kernel leaks.
void iosurface_research_syscall_storm(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// Round 27: Kernel Primitives Exploitation
/// Probe 82: OOB heap scanner — systematic OOB reads mapping heap layout around IOSurface.
void iosurface_research_oob_scanner(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 83: Remap spray oracle — vm_remap + destroy + spray to read freed IOSurface metadata.
void iosurface_research_remap_spray(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 84: Kernel slide calculator — compute KASLR slide from leaked pointers + probe kernel memory.
void iosurface_research_kslide(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// Round 28: Kernel R/W Construction
/// Probe 85: Pointer classifier — categorize 154 leaked kernel ptrs, find IOSurface objects in heap.
void iosurface_research_ptr_classifier(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 86: Stride corruption engine — exploit stride confusion for cross-surface OOB write.
void iosurface_research_stride_corrupt(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 87: Arbitrary read probe — combine all primitives to attempt kernel memory read.
void iosurface_research_arb_read(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// Round 29: Kernel Takeover
/// Probe 88: Vtable spray + confusion — spray IOSurfaces, locate vtables via OOB, attempt overwrite.
void iosurface_research_vtbl_spray(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 89: Refcount corruption — find IOSurface header via sentinel, corrupt refcount for controlled UAF.
void iosurface_research_refcount_corrupt(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 90: Pipe kernel R/W — use pipe buffers as kernel heap oracles for read/write primitive.
void iosurface_research_pipe_krw(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// Round 30: Strategy Pivot
/// Probe 91: Mach OOL message spray — controlled kernel heap allocations via OOL descriptors + IOSurface reclaim.
void iosurface_research_ool_spray(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 92: IOKit external method fuzzing — call IOSurface user client selectors 0-33 with crafted inputs.
void iosurface_research_ioconn_call(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 93: Task port self-inspection — harvest kernel info via task_info, vm_region, host_info, commpage.
void iosurface_research_task_intro(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// --- Round 31: Exploit Chain ---

/// Probe 94: Race condition UAF — 4 threads hammering SetValue/GetValue/RemoveValue for kernel UAF.
void iosurface_research_race_uaf(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 95: Physical memory mapping — 100 single-page surfaces, sentinel cross-scan, vm_remap overlap.
void iosurface_research_phys_map(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 96: Full exploit chain — spray+OOB+AllocSize override+kernel scan+vm_remap R/W.
void iosurface_research_exploit_chain(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

// --- Round 32: Bug Hunting ---

/// Probe 97: Property type confusion — set CFData, read as different types, check kernel type coercion bugs.
void iosurface_research_type_confuse(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 98: IOConnectCallStructMethod — struct-based IOKit methods with crafted struct inputs.
void iosurface_research_struct_method(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe 99: Surface lifecycle TOCTOU — race destroy vs lookup to trigger use-after-free on IOSurface object.
void iosurface_research_lifecycle_race(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB3: Stale-page physical alias — memory entry survives CFRelease, R/W recycled pages.
void iosurface_stale_page_alias(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB4: IOSurface notify UAF race (CVE-2026-112477) — SetSurfaceNotify + Create/Release race.
void iosurface_notify_uaf_race(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB5: Kernel object spray via stale-page alias — read kernel data through recycled pages.
void iosurface_kernel_spray_alias(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB6: Controlled corruption via stale-page write — corrupt IOSurface properties for OOB.
void iosurface_controlled_corruption(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB7: Mach OOL message spray into stale alias — kernel kalloc pages via OOL descriptors.
void iosurface_ool_spray_alias(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB8: Notify UAF + stale alias combo — read freed kernel notification object via alias.
void iosurface_notify_uaf_alias(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB9: Pipe buffer spray into stale alias — kernel pipe buffers in recycled pages.
void iosurface_pipe_spray_alias(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB10: Normal surface stale alias — vm_allocate pages may share allocator with kernel objects.
void iosurface_normal_alias_spray(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB11: IOSurface property kalloc oracle — spray/free/reclaim kernel heap via SetValue.
void iosurface_property_kalloc_oracle(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB12: Exhaustive kernel info harvest — commpage, task_info, host_info, vm_region.
void iosurface_kernel_info_harvest(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB13: Exception port kernel pointer leak — controlled crash + inspect Mach exception message.
void iosurface_exc_port_leak(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB14: Kernel zone info + voucher spray — direct kernel heap layout via host_zone_info.
void iosurface_zone_voucher_spray(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB15: Thread state residue + port space enumeration — kernel pointer residue in registers.
void iosurface_thread_port_leak(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB16: PAC pointer harvest — mass thread scan + diverse syscalls + kernel address map.
void iosurface_pac_harvest(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB17: Kalloc overflow oracle — IOSurface property sizes at kalloc zone boundaries.
void iosurface_kalloc_overflow(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB18: Heap feng shui + type confusion via IOSurface/voucher cross-zone spray.
void iosurface_heap_fengshui(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB19: Kernel pointer oracle — use leaked PAC ptr + IOSurface ID correlation.
void iosurface_kptr_oracle(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB20: IOSurfaceRoot UAF calibration — test async selector 17/18 call shapes.
void iosurface_sysctl_leak(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB21: IOSurfaceRoot UAF trigger — register/deregister/re-register dangling pointer.
void iosurface_pixelbuf_scan(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB22: IOSurfaceRoot UAF exploit — heap spray + dangling pointer dereference.
void iosurface_pipe_primitive(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB23: IOKit driver enumerator — full sandbox attack surface mapping.
void iosurface_iokit_enumerator(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB24: AppleM2ScalerCSCDriver deep fuzz — CVE-2026-43655 UAF variant hunt.
void iosurface_m2scaler_fuzz(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB25: CVE-2026-112611 — CoreGraphics PDF ShadingType 5 OOB write primitive.
void iosurface_cg_oob_write(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB26: CVE-2026-112611 exploit — heap spray + zero-write ISA corruption.
void iosurface_cg_exploit(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB27: Security bypass — zero-write to sandbox/AMFI pointers.
void iosurface_sec_bypass(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB28: Direct strike — zero-write to sandbox profile strings + AMFI entitlements + csops.
void iosurface_direct_strike(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB29: ObjC ISA swizzle — fake class + corrupted ISA -> code exec via objc_msgSend.
void iosurface_isa_swizzle(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB30: GOT redirect — CVE-2026-112611 zero-write GOT entry -> redirect to controlled page.
void iosurface_got_redirect(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB31: Shellcode exec — mmap RW -> write arm64 shellcode -> mprotect RX -> execute.
void iosurface_shellcode_exec(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB32: ROP chain infrastructure — gadgets + PAC + thread_create + fake stack.
void iosurface_jit_exec(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB33: ROP execution via thread_create_running — call signed functions.
void iosurface_rop_exec(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB34: IOSurface kernel memory map + ObjC swizzle exec.
void iosurface_kernel_map(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB35: Syscall redirect via ObjC swizzle + IOSurface kernel probe.
void iosurface_syscall_redirect(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB36: IOSurface kernel R/W primitives — MapMemory64, struct input, property leaks.
void iosurface_kernel_rw(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB37: IOSurfaceRef deep object scan + kernel pointer harvest.
void iosurface_obj_scan(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB38: Kernel info leak vectors + OSSerialize format.
void iosurface_kleak(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB39: Exception ports + task_info + mach kobject leak.
void iosurface_exc_leak(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB40: KASLR side-channel + commpage + zone info + memory entry.
void iosurface_kaslr_sidechan(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Probe JB40 test (renamed to rule out cache issues).
void iosurface_jb40_test(ISRLogBlock _Nonnull log, ISRDoneBlock _Nonnull done);

/// Stop any running probe.
void iosurface_research_stop(void);

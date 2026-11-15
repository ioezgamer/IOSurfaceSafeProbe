import SwiftUI

struct ResearchView: View {
    @State private var log = ""
    @State private var running = false
    @State private var activeProbe: String? = nil
    @State private var results: [String: Any] = [:]
    @State private var showResults = false

    private let probes: [(id: String, name: String, icon: String, desc: String, action: (@escaping (String) -> Void, @escaping ([String: Any]) -> Void) -> Void)] = [
        ("race", "Race Condition", "bolt.trianglebadge.exclamationmark.fill",
         "Crea/destruye IOSurfaces concurrentemente para detectar reutilizacion de IDs",
         { log, done in iosurface_research_race({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("props", "Propiedades", "slider.horizontal.3",
         "Escanea dimensiones extremas y overflow de enteros en IOSurface",
         { log, done in iosurface_research_properties({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("refcount", "Refcount", "arrow.triangle.2.circlepath",
         "Prueba desbalances de conteo de referencias con multiples conexiones",
         { log, done in iosurface_research_refcount({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("sharing", "Compartir", "person.2.fill",
         "Destruye creador mientras referencias lookup siguen activas",
         { log, done in iosurface_research_sharing({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("mach", "Mach/IOKit", "cpu.fill",
         "Escanea selectores 0-32 en IOSurfaceRoot con patrones de entrada",
         { log, done in iosurface_research_mach({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 2
        ("timed_race", "Race Precisa", "timer",
         "UAF con timing nanosegundos — detecta datos residuales en IDs reciclados",
         { log, done in iosurface_research_timed_race({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("bufleak", "Buffer Leak", "memorychip.fill",
         "Escribe patrones en buffer, destruye, verifica si persisten en nuevas surfaces",
         { log, done in iosurface_research_buffer_leak({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("conn", "Conexiones IOKit", "link.circle.fill",
         "Prueba tipos de conexion 0-15, task ports alternativos, servicios relacionados",
         { log, done in iosurface_research_conn_types({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("boundary", "Limites Alloc", "ruler.fill",
         "Busqueda binaria de umbrales, mismatches bytesPerRow/allocSize, formatos",
         { log, done in iosurface_research_alloc_boundary({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 3
        ("agx", "AGX Deep Scan", "bolt.horizontal.fill",
         "Enumera servicios GPU, tipos de conexion y fuzzing de selectores en AGX",
         { log, done in iosurface_research_agx_scan({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("fmtrender", "Format Render", "paintbrush.fill",
         "Crea surfaces con formatos invalidos y renderiza via CoreGraphics",
         { log, done in iosurface_research_format_render({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("xref", "Cross-Reference", "arrow.triangle.swap",
         "Comparte surfaces entre conexiones con propiedades conflictivas",
         { log, done in iosurface_research_xref_attack({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 4
        ("fb", "Framebuffer", "rectangle.on.rectangle.angled",
         "Fuzzing de selectores en IOMobileFramebuffer — 8 tipos de conexion abiertos",
         { log, done in iosurface_research_framebuffer({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("mismatch", "Format Mismatch", "exclamationmark.triangle.fill",
         "Ataque de mismatch: bpe/formato IOSurface vs bitmap info de CoreGraphics",
         { log, done in iosurface_research_format_mismatch({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("infoleak", "Info Leak", "eye.trianglebadge.exclamationmark.fill",
         "Busca disclosure de punteros kernel, seeds, planos y entropia de direcciones",
         { log, done in iosurface_research_info_leak({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 5
        ("heapspray", "Heap Spray", "square.grid.3x3.fill",
         "Mide distribucion de direcciones y grooming de heap con IOSurfaces",
         { log, done in iosurface_research_heap_spray({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("uafwindow", "UAF Window", "clock.badge.exclamationmark.fill",
         "Detecta ventana UAF con timing nanosegundos y datos residuales",
         { log, done in iosurface_research_uaf_window({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("timingoracle", "Timing Oracle", "stopwatch.fill",
         "Side-channel de timing en operaciones kernel de IOSurface",
         { log, done in iosurface_research_timing_oracle({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 6
        ("fengshui", "Heap Feng Shui", "square.grid.3x3.topleft.filled",
         "Colocacion precisa de objetos con spray, grooming y sondeo cross-boundary",
         { log, done in iosurface_research_feng_shui({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("cachechannel", "Cache Channel", "antenna.radiowaves.left.and.right",
         "Canal encubierto via cache: señalizacion por eviccion y ratio hot/cold",
         { log, done in iosurface_research_cache_channel({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("deputy", "Confused Deputy", "person.badge.key.fill",
         "Inyeccion de IDs IOSurface en servicios IOKit — test de acceso sin validar",
         { log, done in iosurface_research_confused_deputy({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 7
        ("propinject", "Property Injection", "text.badge.plus",
         "Inyeccion de propiedades en diccionario kernel de IOSurface",
         { log, done in iosurface_research_property_inject({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("planeovlap", "Plane Overlap", "square.stack.3d.up.fill",
         "Planos solapados para lectura cross-plane y OOB read",
         { log, done in iosurface_research_plane_overlap({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("portrace", "Mach Port Race", "bolt.shield.fill",
         "Ataque de puertos Mach: lifecycle, reuso y race masivo 50 hilos",
         { log, done in iosurface_research_port_race({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 8
        ("phantom", "Phantom Plane", "rectangle.stack.badge.play.fill",
         "Escritura en planos fantasma de surfaces con format mismatch",
         { log, done in iosurface_research_phantom_plane({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("globalspy", "Global Spy", "eye.circle.fill",
         "Espionaje via IOSurfaceIsGlobal — acceso cross-lookup y tampering",
         { log, done in iosurface_research_global_spy({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("idoracle", "ID Oracle", "number.circle.fill",
         "Prediccion de IDs y ataque de referencia stale post-destroy",
         { log, done in iosurface_research_id_oracle({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 9
        ("cgoverflow", "CG Overflow", "rectangle.expand.vertical",
         "Amplificador de overflow CG: lectura maxima cross-plane y cross-surface",
         { log, done in iosurface_research_cg_overflow({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("spraycg", "Spray+CG Chain", "link.badge.plus",
         "Cadena heap spray + CG overflow para harvest de datos cross-surface",
         { log, done in iosurface_research_spray_cg_chain({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("globalovf", "Global+Overflow", "globe.badge.chevron.backward",
         "Combo global surface + CG overflow con analisis de entropia Shannon",
         { log, done in iosurface_research_global_overflow({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 10
        ("cgread", "CG Cross-Plane Read", "doc.text.magnifyingglass",
         "OOB read REAL: lee datos de plane1 via contexto CG en plane0",
         { log, done in iosurface_research_cg_crossplane_read({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("machijack", "Mach Port Hijack", "lock.open.rotation",
         "Secuestra surface via mach port: lectura y tamper desde segunda referencia",
         { log, done in iosurface_research_mach_hijack({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("toctou", "Global TOCTOU", "arrow.triangle.2.circlepath.circle.fill",
         "Race condition TOCTOU: spy modifica datos entre check y use del owner",
         { log, done in iosurface_research_global_toctou({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 11
        ("comprace", "Compositor TOCTOU", "display",
         "Race contra backboardd/render server via CALayer-backed IOSurface",
         { log, done in iosurface_research_compositor_race({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("syssniff", "System Sniff", "antenna.radiowaves.left.and.right",
         "Detecta acceso de daemons del sistema via use-count y bootstrap lookup",
         { log, done in iosurface_research_system_sniff({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("rendcorr", "Render Corrupt", "paintbrush.pointed.fill",
         "Surface dual-plane como input del compositor — busca leak cross-plane",
         { log, done in iosurface_research_render_corrupt({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 12
        ("compuaf", "UAF Compositor", "xmark.octagon.fill",
         "Libera surface mientras el compositor la usa — detecta acceso stale",
         { log, done in iosurface_research_compositor_uaf({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),

        ("harvest", "Kernel Harvest", "server.rack",
         "Extrae toda la metadata IOSurface buscando leaks de punteros kernel",
         { log, done in iosurface_research_kernel_harvest({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("chain", "Full Chain", "link.badge.plus",
         "Cadena completa: mach hijack + CG OOB + compositor TOCTOU combinados",
         { log, done in iosurface_research_full_chain({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 13
        ("uafrealloc", "UAF Realloc", "arrow.triangle.swap",
         "Release + reclaim memoria — escribe via ref dangling para corromper nueva surface",
         { log, done in iosurface_research_uaf_realloc({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("aslrdefeat", "ASLR Defeat", "eye.trianglebadge.exclamationmark.fill",
         "Recolecta direcciones base de multiples surfaces para calcular ASLR slide",
         { log, done in iosurface_research_aslr_defeat({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("rwprim", "R/W Primitive", "arrow.left.arrow.right.circle.fill",
         "Escritura dangling + lectura CG OOB para flujo de datos controlado cross-surface",
         { log, done in iosurface_research_rw_primitive({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 14
        ("kalloc", "Kalloc Overlap", "square.stack.3d.up.fill",
         "Libera IOSurface + spray objetos kernel para reclamar memoria — detecta overlap",
         { log, done in iosurface_research_kalloc_overlap({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("propcorrupt", "Property Corrupt", "doc.badge.gearshape.fill",
         "Estresa el diccionario de propiedades IOSurface en kernel — busca corrupcion OSDictionary",
         { log, done in iosurface_research_property_corrupt({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("portkspray", "Port Kernel Spray", "network.badge.shield.half.filled",
         "Spray ipc_port kernel objects para reclamar memoria IOSurface liberada",
         { log, done in iosurface_research_port_kernel_spray({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 15
        ("sizeconfuse", "Size Confusion", "arrow.up.left.and.arrow.down.right.circle.fill",
         "Override AllocSize en kernel dict — intenta lectura OOB mas alla del backing real",
         { log, done in iosurface_research_size_confusion({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("bproverflow", "BPR Overflow", "rectangle.expand.vertical",
         "Override BytesPerRow en kernel dict — usa CG para leer con stride corrupto",
         { log, done in iosurface_research_bpr_overflow({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("portpropchain", "Port+Prop Chain", "link.badge.plus",
         "Property override + mach port transfer + CG OOB — lectura kernel-adyacente",
         { log, done in iosurface_research_port_prop_chain({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 16
        ("stridekern", "Stride Kernel", "cpu.fill",
         "Stride confusion para leer memoria kernel-adyacente — escanea patrones de datos kernel",
         { log, done in iosurface_research_stride_kernel({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("xsurfcorrupt", "XSurf Corrupt", "arrow.triangle.swap",
         "Stride OOB write para corromper propiedades OSDictionary de surfaces adyacentes",
         { log, done in iosurface_research_xsurf_corrupt({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("fakeobject", "Fake Object", "hammer.fill",
         "Inyecta patrones de objetos kernel falsos via stride overflow en memoria adyacente",
         { log, done in iosurface_research_fake_object({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 17
        ("portmap", "Port Map", "map.fill",
         "Mapeo fino de estructura ipc_port en OOB — identifica campos kernel",
         { log, done in iosurface_research_port_map({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("portcorrupt", "Port Corrupt", "bolt.trianglebadge.exclamationmark.fill",
         "Corrupción de campos ipc_port via stride OOB — verifica via mach_port_get_refs",
         { log, done in iosurface_research_port_corrupt({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("krwchain", "K-R/W Chain", "link.circle.fill",
         "Cadena completa: spray + port locate + kobject read + redirect + R/W arbitrario",
         { log, done in iosurface_research_krw_chain({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 18
        ("megaspray", "Mega Spray", "drop.deferred.fill",
         "Grooming masivo del heap — 5 ciclos con 100 surfaces + 200 ports para adjacencia fiable",
         { log, done in iosurface_research_mega_spray({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("porthunt", "Port Hunt", "binoculars.fill",
         "Búsqueda iterativa de port — hasta 10 intentos spray+scan, mapeo completo de 256 bytes",
         { log, done in iosurface_research_port_hunt({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("kobjredir", "Kobject Redir", "arrow.triangle.turn.up.right.diamond.fill",
         "Kernel R/W completo — port locate iterativo + kobject redirect + verificación R/W",
         { log, done in iosurface_research_kobject_redirect({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 19
        ("dicthijack", "Dict Hijack", "book.closed.fill",
         "Stride OOB write para corromper propiedades de surfaces adyacentes — hijack diccionario kernel",
         { log, done in iosurface_research_dict_hijack({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("propfake", "Prop Fake", "wand.and.stars",
         "Escribe patrones AAAA via stride OOB — verifica si getters del target devuelven datos corruptos",
         { log, done in iosurface_research_prop_fake({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("kernread", "Kernel Read", "eye.trianglebadge.exclamationmark.fill",
         "Localiza metadata de surface en OOB — corrompe campos de tamaño — escanea punteros kernel",
         { log, done in iosurface_research_kernel_read({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 20
        ("zonespray", "Zone Spray", "circle.grid.cross.fill",
         "Spray propiedades en kalloc zones — free/reclaim — detecta contaminación cruzada entre zones",
         { log, done in iosurface_research_zone_spray({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("zonereclaim", "Zone Reclaim", "arrow.triangle.2.circlepath",
         "Destruye surface — spray OOL mach msgs en zona liberada — lee referencia stale para datos kernel",
         { log, done in iosurface_research_zone_reclaim({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("ptrleak", "Ptr Leak", "lock.open.trianglebadge.exclamationmark.fill",
         "Cadena completa: zone spray + reclaim + escaneo de punteros kernel 0xFFFFxxxxxxxx",
         { log, done in iosurface_research_ptr_leak({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 21
        ("sizesweep", "Size Sweep", "ruler.fill",
         "Barrido de 14 tamaños OOL (16B–2KB) para encontrar el bucket kalloc exacto que solapa con IOSurface",
         { log, done in iosurface_research_size_sweep({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("propspray", "Prop Spray", "arrow.triangle.swap",
         "Cross-spray con propiedades IOSurface como víctima y spray — mismo allocator, mismo bucket garantizado",
         { log, done in iosurface_research_prop_spray({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("idreuse", "ID Reuse", "arrow.2.squarepath",
         "Confusión por reutilización de ID — destruir y recrear hasta obtener mismo ID, verificar confusión de propiedades",
         { log, done in iosurface_research_id_reuse({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 22
        ("keyenum", "Key Enum", "list.bullet.rectangle.portrait.fill",
         "Enumera TODAS las claves internas de IOSurface — detecta valores tipo address expuestos via API",
         { log, done in iosurface_research_key_enum({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("keyoverride", "Key Override", "pencil.and.list.clipboard",
         "Sobrescribe claves internas — verifica si cambian base address, tamaño o mapeo de la superficie",
         { log, done in iosurface_research_key_override({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("addredir", "Addr Redirect", "arrow.uturn.right.circle.fill",
         "Intenta redirigir el mapeo de memoria via claves internas — busca kernel R/W primitiva",
         { log, done in iosurface_research_addr_redirect({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 23
        ("iokbrute", "IOKit Brute", "hammer.fill",
         "Fuerza bruta masiva — fuzzing de selectores 0-199 en IOSurfaceRootUserClient con inputs crafteados",
         { log, done in iosurface_research_iokit_brute({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("structovf", "Struct Overflow", "arrow.up.doc.fill",
         "Overflow de structs — envía inputs progresivamente más grandes a selectores del kernel, busca OOB",
         { log, done in iosurface_research_struct_overflow({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("raceexpl", "Race Exploit", "bolt.horizontal.fill",
         "Exploit de carrera — 8 hilos simultáneos: IOConnectCallMethod + create/destroy TOCTOU",
         { log, done in iosurface_research_race_exploit({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 24
        ("metalcrpt", "Metal Corrupt", "cpu.fill",
         "Corrupción Metal — pasa IOSurface como textura GPU, modifica stride durante render para OOB",
         { log, done in iosurface_research_metal_corrupt({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("agxdrv", "AGX Driver", "gamecontroller.fill",
         "Fuzzing GPU — selectores 0-99 en AGXAccelerator, IOGPU, IOMobileFramebuffer y más drivers",
         { log, done in iosurface_research_agx_driver({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("gpudma", "GPU DMA Race", "bolt.trianglebadge.exclamationmark.fill",
         "Carrera DMA — CPU escribe vs GPU lee simultáneamente en IOSurface compartido, busca torn reads",
         { log, done in iosurface_research_gpu_dma_race({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 25
        ("fbdeep", "FB Deep Fuzz", "display",
         "IOMobileFramebuffer tipo 4 — fuzzing intensivo sel 70-99, structs crafteados, MapMemory, captura outputs",
         { log, done in iosurface_research_fb_deep({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("jpegexp", "JPEG Exploit", "photo.fill",
         "AppleJPEGDriver — fuzzing en 5 tipos de conexión con markers JPEG + IOSurface IDs, MapMemory",
         { log, done in iosurface_research_jpeg_exploit({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("svcchain", "Service Chain", "link.circle.fill",
         "Cadena multi-servicio — pasa IOSurface por FB+JPEG, detecta corrupción cruzada y kernel leaks",
         { log, done in iosurface_research_service_chain({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 26
        ("vmremap", "VM Remap", "arrow.triangle.swap",
         "mach_vm_remap IOSurface pages, destroy surface, read freed memory, OOL spray, cross-write check",
         { log, done in iosurface_research_vm_remap({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("surfaccel", "Surf Accelerator", "bolt.horizontal.fill",
         "IOSurfaceAccelerator/Blitter — fuzzing hardware blit services, stride mismatch OOB",
         { log, done in iosurface_research_surf_accel({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("syscallstorm", "Syscall Storm", "tornado",
         "task_info ASLR leak, mach_make_memory_entry, vm_remap post-destroy, vm_region enum, OOB reads",
         { log, done in iosurface_research_syscall_storm({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 27
        ("oobscan", "OOB Heap Scanner", "magnifyingglass.circle.fill",
         "Lectura OOB sistemática 0-16MB mapeando heap layout, kernel ptrs, vtables adyacentes",
         { log, done in iosurface_research_oob_scanner({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("remapspray", "Remap Spray Oracle", "arrow.triangle.2.circlepath.circle.fill",
         "vm_remap + destroy + spray 500 surfaces — lee metadata de superficie nueva via UAF read",
         { log, done in iosurface_research_remap_spray({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("kslide", "Kernel Slide Calc", "function",
         "Calcula KASLR slide desde punteros filtrados + prueba mapear memoria de kernel",
         { log, done in iosurface_research_kslide({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 28
        ("ptrclass", "Pointer Classifier", "cpu.fill",
         "Clasifica 154 kernel ptrs filtrados, encuentra objetos IOSurface en heap, busca vtables",
         { log, done in iosurface_research_ptr_classifier({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("stridecorr", "Stride Corruption", "arrow.up.and.down.text.horizontal",
         "Explota confusión de stride para escritura OOB cross-surface + manipulación de geometría",
         { log, done in iosurface_research_stride_corrupt({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("arbread", "Arbitrary Read", "eye.trianglebadge.exclamationmark.fill",
         "Combina todas las primitivas para intentar lectura arbitraria de memoria kernel",
         { log, done in iosurface_research_arb_read({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 29
        ("vtblspray", "Vtable Spray", "cpu.fill",
         "Spray 200 surfaces, localiza vtables via OOB, intenta overwrite para confusión",
         { log, done in iosurface_research_vtbl_spray({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("refcorr", "Refcount Corrupt", "bolt.trianglebadge.exclamationmark.fill",
         "Busca header IOSurface via OOB, corrompe refcount para UAF controlado + reclaim",
         { log, done in iosurface_research_refcount_corrupt({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("pipekrw", "Pipe Kernel R/W", "arrow.left.arrow.right.circle.fill",
         "256 pipes como oráculos de heap kernel — localiza buffers via OOB para R/W primitiva",
         { log, done in iosurface_research_pipe_krw({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 30
        ("oolspray", "OOL Msg Spray", "envelope.fill",
         "Spray 1024 mach OOL messages, libera mitad, reclama con IOSurface para cross-contamination",
         { log, done in iosurface_research_ool_spray({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("ioconncall", "IOKit Method Fuzz", "hammer.fill",
         "Fuzzing de selectores 0-99 en IOSurface user client con inputs crafteados",
         { log, done in iosurface_research_ioconn_call({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("taskintro", "Task Introspection", "brain.filled.head.profile",
         "Harvest kernel info via task_info, vm_region, commpage, host_info, thread state",
         { log, done in iosurface_research_task_intro({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        // Round 31
        ("raceuaf", "Race Condition UAF", "bolt.trianglebadge.exclamationmark.fill",
         "4 threads racing SetValue/GetValue/RemoveValue — CVE-2023-32434 style UAF/type confusion",
         { log, done in iosurface_research_race_uaf({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("physmap", "Physical Memory Map", "cpu.fill",
         "100 single-page surfaces, sentinel cross-scan, vm_remap overlap para R/W físico",
         { log, done in iosurface_research_phys_map({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
        ("exploitchain", "Full Exploit Chain", "lock.open.laptopcomputer",
         "Spray+OOB+AllocSize override+kernel scan+vm_remap — cadena completa de explotación",
         { log, done in iosurface_research_exploit_chain({ msg in log(msg as String) }, { res in done(res as! [String: Any]) }) }),
    ]

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    headerSection
                    probeCards
                }
                .padding(.horizontal)
                .padding(.bottom, 30)
            }
            .background(Color(.systemGroupedBackground))
            .navigationTitle("IOSurface Research")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                if running {
                    ToolbarItem(placement: .topBarTrailing) {
                        Button {
                            iosurface_research_stop()
                            running = false
                            activeProbe = nil
                            appendLog("[!] Detenido por usuario")
                        } label: {
                            Label("Detener", systemImage: "stop.circle.fill")
                                .foregroundStyle(.red)
                        }
                    }
                }
            }
        }
    }

    private var headerSection: some View {
        VStack(spacing: 12) {
            Image(systemName: "shield.lefthalf.filled.badge.checkmark")
                .font(.system(size: 44))
                .foregroundStyle(.purple)
            Text("Investigacion IOSurface")
                .font(.title2.weight(.bold))
            Text("Sondas de seguridad educativas para iOS 27.\nSe ejecutan en tu dispositivo, sin red.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 20)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 20))
        .padding(.top, 8)
    }

    private var probeCards: some View {
        VStack(spacing: 10) {
            Text("Ronda 1 — Reconocimiento")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)

            ForEach(probes.prefix(5), id: \.id) { probe in
                probeCard(probe)
            }

            Text("Ronda 2 — Sondas Avanzadas")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.purple)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[5..<9], id: \.id) { probe in
                probeCard(probe)
            }

            Text("Ronda 3 — Vectores de Explotacion")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.red)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[9..<12], id: \.id) { probe in
                probeCard(probe)
            }

            Text("Ronda 4 — Explotacion Profunda")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.orange)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[12..<15], id: \.id) { probe in
                probeCard(probe)
            }

            Text("Ronda 5 — Primitivas de Explotacion")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.cyan)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[15..<18], id: \.id) { probe in
                probeCard(probe)
            }

            Text("Ronda 6 — Cadenas de Ataque")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.green)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[18..<21], id: \.id) { probe in
                probeCard(probe)
            }

            Text("Ronda 7 — Superficie de Ataque Kernel")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.red)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[21..<24], id: \.id) { probe in
                probeCard(probe)
            }

            Text("Ronda 8 — Explotacion de Vulnerabilidades")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.yellow)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[24..<27], id: \.id) { probe in
                probeCard(probe)
            }

            Text("Ronda 9 — Cadena CG Overflow")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.pink)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[27..<30], id: \.id) { probe in
                probeCard(probe)
            }

            Text("Ronda 10 — Explotacion Real")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.red)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[30..<33], id: \.id) { probe in
                probeCard(probe)
            }

            // --- ROUND 11 ---
            Text("Round 11 — System Service TOCTOU")
                .font(.caption.bold())
                .foregroundStyle(.indigo)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[33..<36], id: \.id) { probe in
                probeCard(probe)
            }

            // --- ROUND 12 ---
            Text("Round 12 — Aggressive Exploitation")
                .font(.caption.bold())
                .foregroundStyle(.orange)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[36..<39], id: \.id) { probe in
                probeCard(probe)
            }

            // --- ROUND 13 ---
            Text("Round 13 — Real Exploit Primitives")
                .font(.caption.bold())
                .foregroundStyle(.red)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[39..<42], id: \.id) { probe in
                probeCard(probe)
            }

            // --- ROUND 14 ---
            Text("Round 14 — Kernel Boundary Attacks")
                .font(.caption.bold())
                .foregroundStyle(.pink)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[42..<45], id: \.id) { probe in
                probeCard(probe)
            }

            // --- ROUND 15 ---
            Text("Round 15 — Kernel R/W Hunt")
                .font(.caption.bold())
                .foregroundStyle(.purple)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[45..<48], id: \.id) { probe in
                probeCard(probe)
            }

            // --- ROUND 16 ---
            Text("Round 16 — Kernel R/W Weaponization")
                .font(.caption.bold())
                .foregroundStyle(.red)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[48..<51], id: \.id) { probe in
                probeCard(probe)
            }

            // --- ROUND 17 ---
            Text("Round 17 — Mach Port Structure Exploitation")
                .font(.caption.bold())
                .foregroundStyle(.orange)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[51..<54], id: \.id) { probe in
                probeCard(probe)
            }

            // --- ROUND 18 ---
            Text("Round 18 — Stable Heap Grooming")
                .font(.caption.bold())
                .foregroundStyle(.red)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[54..<57], id: \.id) { probe in
                probeCard(probe)
            }

            // --- ROUND 19 ---
            Text("Round 19 — Property Dictionary Hijack")
                .font(.caption.bold())
                .foregroundStyle(.cyan)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[57..<60], id: \.id) { probe in
                probeCard(probe)
            }

            // --- ROUND 20 ---
            Text("Round 20 — Kalloc Zone Reclaim")
                .font(.caption.bold())
                .foregroundStyle(.mint)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[60..<63], id: \.id) { probe in
                probeCard(probe)
            }

            // --- ROUND 21 ---
            Text("Round 21 — Kalloc Bucket Precision")
                .font(.caption.bold())
                .foregroundStyle(.orange)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[63..<66], id: \.id) { probe in
                probeCard(probe)
            }

            // --- ROUND 22 ---
            Text("Round 22 — Internal Key Exploitation")
                .font(.caption.bold())
                .foregroundStyle(.red)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[66..<69], id: \.id) { probe in
                probeCard(probe)
            }

            // --- ROUND 23 ---
            Text("Round 23 — IOKit Brute Force")
                .font(.caption.bold())
                .foregroundStyle(.purple)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[69..<72], id: \.id) { probe in
                probeCard(probe)
            }

            // --- ROUND 24 ---
            Text("Round 24 — GPU/Metal Exploitation")
                .font(.caption.bold())
                .foregroundStyle(.cyan)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[72..<75], id: \.id) { probe in
                probeCard(probe)
            }

            // --- ROUND 25 ---
            Text("Round 25 — Deep Service Exploitation")
                .font(.caption.bold())
                .foregroundStyle(.red)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[75..<78], id: \.id) { probe in
                probeCard(probe)
            }

            // --- ROUND 26 ---
            Text("Round 26 — Maximum Aggression")
                .font(.caption.bold())
                .foregroundStyle(.red)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[78..<81], id: \.id) { probe in
                probeCard(probe)
            }

            // --- ROUND 27 ---
            Text("Round 27 — Kernel Primitives")
                .font(.caption.bold())
                .foregroundStyle(.red)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[81..<84], id: \.id) { probe in
                probeCard(probe)
            }

            Text("Round 28 — Kernel R/W Construction")
                .font(.caption.bold())
                .foregroundStyle(.red)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[84..<87], id: \.id) { probe in
                probeCard(probe)
            }

            // --- ROUND 29 ---
            Text("Round 29 — Kernel Takeover")
                .font(.caption.bold())
                .foregroundStyle(.red)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[87..<90], id: \.id) { probe in
                probeCard(probe)
            }

            // --- ROUND 30 ---
            Text("Round 30 — Strategy Pivot")
                .font(.caption.bold())
                .foregroundStyle(.red)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes[90..<93], id: \.id) { probe in
                probeCard(probe)
            }

            // --- ROUND 31 ---
            Text("Round 31 — Exploit Chain")
                .font(.caption.bold())
                .foregroundStyle(.red)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 4)
                .padding(.top, 8)

            ForEach(probes.suffix(from: 93), id: \.id) { probe in
                probeCard(probe)
            }

            if !log.isEmpty { logSection }
        }
    }

    private func probeCard(_ probe: (id: String, name: String, icon: String, desc: String, action: (@escaping (String) -> Void, @escaping ([String: Any]) -> Void) -> Void)) -> some View {
        Button {
            runProbe(probe)
        } label: {
            HStack(spacing: 14) {
                Image(systemName: probe.icon)
                    .font(.title2)
                    .foregroundStyle(.purple)
                    .frame(width: 36)
                VStack(alignment: .leading, spacing: 3) {
                    Text(probe.name)
                        .font(.headline)
                        .foregroundStyle(.primary)
                    Text(probe.desc)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
                Spacer()
                if activeProbe == probe.id {
                    ProgressView()
                } else {
                    Image(systemName: "play.circle.fill")
                        .font(.title2)
                        .foregroundStyle(.purple.opacity(0.7))
                }
            }
            .padding(14)
            .background(
                RoundedRectangle(cornerRadius: 14)
                    .fill(activeProbe == probe.id
                          ? Color.purple.opacity(0.08)
                          : Color(.secondarySystemGroupedBackground))
            )
        }
        .disabled(running)
        .buttonStyle(.plain)
    }

    private var logSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label("Log", systemImage: "terminal.fill")
                    .font(.subheadline.weight(.semibold))
                Spacer()
                Button {
                    log = ""
                } label: {
                    Text("Limpiar")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            ScrollViewReader { proxy in
                ScrollView {
                    Text(log)
                        .font(.system(.caption2, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .id("logBottom")
                }
                .frame(height: 240)
                .onChange(of: log) { _ in
                    proxy.scrollTo("logBottom", anchor: .bottom)
                }
            }
        }
        .padding()
        .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 16))
    }

    private func appendLog(_ msg: String) {
        DispatchQueue.main.async {
            log += msg + "\n"
        }
    }

    private func runProbe(_ probe: (id: String, name: String, icon: String, desc: String, action: (@escaping (String) -> Void, @escaping ([String: Any]) -> Void) -> Void)) {
        running = true
        activeProbe = probe.id
        appendLog("=== \(probe.name) ===")
        probe.action(
            { msg in appendLog(msg) },
            { res in
                DispatchQueue.main.async {
                    running = false
                    activeProbe = nil
                    results = res
                    appendLog("[OK] Completado. Anomalias: \(res["anomalies"] ?? res["accepted_selectors"] ?? "N/A")")
                }
            }
        )
    }
}

#Preview {
    ResearchView()
}

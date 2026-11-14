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

            ForEach(probes.suffix(from: 18), id: \.id) { probe in
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

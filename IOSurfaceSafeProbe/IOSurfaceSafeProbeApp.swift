import SwiftUI
import IOSurface
import CoreFoundation

@main
struct IOSurfaceSafeProbeApp: App {
    var body: some Scene {
        WindowGroup {
            ProbeView()
        }
    }
}

struct ProbeView: View {
    @State private var report = "Prueba sin ejecutar. No modifica el kernel ni prueba argumentos invalidos."

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 18) {
                Text("Prueba de API publica")
                    .font(.title2.bold())
                Text("Crea una IOSurface pequena y valida operaciones normales. No intenta provocar panics, hacer jailbreak ni inspeccionar registros del kernel.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)

                Button {
                    report = runSafeProbe()
                } label: {
                    Label("Ejecutar prueba segura", systemImage: "checkmark.shield")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)

                ScrollView {
                    Text(report)
                        .font(.system(.footnote, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                        .padding(14)
                }
                .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))

                ShareLink(item: report) {
                    Label("Compartir registro", systemImage: "square.and.arrow.up")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .disabled(report.hasPrefix("Prueba sin ejecutar"))
            }
            .padding()
            .navigationTitle("IOSurface Probe")
        }
    }

    private func runSafeProbe() -> String {
        var log: [String] = []
        log.append("IOSurface Safe Probe 1.0")
        log.append("Fecha: \(ISO8601DateFormatter().string(from: Date()))")
        log.append("iOS: \(UIDevice.current.systemVersion)")
        log.append("Modelo informado: \(UIDevice.current.model)")
        log.append("Modo: API publica, valores validos, una sola superficie")

        let properties: [String: Any] = [
            kIOSurfaceWidth as String: 64,
            kIOSurfaceHeight as String: 64,
            kIOSurfaceBytesPerElement as String: 4,
            kIOSurfaceBytesPerRow as String: 256,
            kIOSurfacePixelFormat as String: UInt32(0x42475241) // BGRA
        ]

        guard let surface = IOSurfaceCreate(properties as CFDictionary) else {
            log.append("IOSurfaceCreate: fallo (nil)")
            log.append("Conclusión: esta solicitud publica no creo una superficie; no prueba el despacho virtual.")
            return log.joined(separator: "\n")
        }

        let surfaceID = IOSurfaceGetID(surface)
        log.append("IOSurfaceCreate: OK")
        log.append("IOSurfaceID: \(surfaceID)")
        log.append("Tamano: \(IOSurfaceGetWidth(surface))x\(IOSurfaceGetHeight(surface))")
        log.append("Bytes asignados: \(IOSurfaceGetAllocSize(surface))")

        var seed: UInt32 = 0
        let lockResult = IOSurfaceLock(surface, [], &seed)
        log.append("IOSurfaceLock: \(lockResult)")
        if lockResult == 0 {
            let unlockResult = IOSurfaceUnlock(surface, [], &seed)
            log.append("IOSurfaceUnlock: \(unlockResult)")
        } else {
            log.append("IOSurfaceUnlock: omitido porque Lock fallo")
        }

        let lookedUp = IOSurfaceLookup(surfaceID)
        log.append("IOSurfaceLookup(ID propio): \(lookedUp == nil ? "nil" : "OK")")
        log.append("Fin: sin solicitudes malformadas")
        log.append("Limite: no demuestra invocacion de IOSurfaceClient::metodo_virtual ni valor de x2.")
        return log.joined(separator: "\n")
    }
}

import Foundation
import UIKit

struct KernelEvidenceReport: Codable {
    let schema: String
    let capturedAt: Date
    let iosVersion: String
    let systemUptimeSeconds: Double
    let estimatedBootEpoch: Double
    let previousBootEpoch: Double?
    let bootChanged: Bool
    let reportName: String?
    let classification: String
    let panicMarkers: [String]
    let notes: String
}
enum KernelEvidenceLab {
    private static let key = "kernelEvidence.previousBootEpoch"

    static func record() -> KernelEvidenceReport {
        let now = Date()
        let uptime = ProcessInfo.processInfo.systemUptime
        let bootEpoch = now.timeIntervalSince1970 - uptime
        let defaults = UserDefaults.standard
        let previous: Double? = defaults.object(forKey: key) == nil ? nil : defaults.double(forKey: key)
        // Comparing monotonic uptime-derived boot epochs across launches
        // is only a heuristic: clock adjustments can produce false positives.
        let changed = previous.map { abs(bootEpoch - $0) > 120 } ?? false
        defaults.set(bootEpoch, forKey: key)
        return KernelEvidenceReport(schema: "iosurface-evidence-lab/kernel-evidence-v8",
            capturedAt: now, iosVersion: UIDevice.current.systemVersion,
            systemUptimeSeconds: uptime, estimatedBootEpoch: bootEpoch,
            previousBootEpoch: previous, bootChanged: changed,
            reportName: nil, classification: changed ? "BOOT_EPOCH_CHANGED" : "NO_REBOOT_EVIDENCE",
            panicMarkers: [],
            notes: changed
              ? "La época estimada de arranque cambió. No atribuir el reinicio a un kernel panic sin un informe independiente."
              : "Sin evidencia de reinicio entre capturas. Esto no prueba ausencia de errores del kernel.")
    }

    static func analyze(_ body: String, fileName: String) -> KernelEvidenceReport {
        let baseline = record()
        let lower = body.lowercased()
        let markers = ["panicstring", "panic(cpu", "kernel panic", "bug_type", "kernelcache", "iokit", "iosurface", "iogpu"]
            .filter { lower.contains($0) }
        let isPanic = lower.contains("panicstring") || lower.contains("panic(cpu") || lower.contains("kernel panic")
        let isApp = lower.contains("exc_bad_access") || lower.contains("exception type")
        let classification = isPanic ? "PANIC_REPORT_CANDIDATE" :
            (isApp ? "APPLICATION_CRASH_REPORT" : "UNCLASSIFIED_REPORT")
        let explanation = isPanic
          ? "Contiene indicadores textuales de panic. Se requiere confirmar cabecera, dispositivo, fecha y stack del kernel; no demuestra por sí mismo corrupción explotable."
          : (isApp
             ? "El informe contiene indicadores de excepción de proceso. No atribuirlo al kernel."
             : "No hay indicadores suficientes para clasificarlo como panic.")
        return KernelEvidenceReport(schema: baseline.schema, capturedAt: baseline.capturedAt,
            iosVersion: baseline.iosVersion, systemUptimeSeconds: baseline.systemUptimeSeconds,
            estimatedBootEpoch: baseline.estimatedBootEpoch,
            previousBootEpoch: baseline.previousBootEpoch, bootChanged: baseline.bootChanged,
            reportName: fileName, classification: classification,
            panicMarkers: markers, notes: explanation)
    }
}

import Foundation
import Darwin
import UIKit

struct ProtectionReport: Codable {
    let schema: String
    let timestamp: Date
    let iosVersion: String
    let pageSize: Int
    let protectionApplied: Bool
    let accessRestored: Bool
    let integrityVerified: Bool
    let detail: String
}

/// Proof of userspace VM protection enforcement; does not access kernel memory.
enum ProcessProtectionLab {
    private static let markerKey = "protectedPageFaultWasRequested"

    static func pendingCrashMarker() -> Bool {
        UserDefaults.standard.bool(forKey: markerKey)
    }
    static func clearCrashMarker() {
        UserDefaults.standard.removeObject(forKey: markerKey)
    }
    static func run() -> ProtectionReport {
        let size = Int(getpagesize())
        let p = mmap(nil, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0)
        guard p != MAP_FAILED, let memory = p else {
            return ProtectionReport(schema: "iosurface-evidence-lab/protection-v7",
                timestamp: Date(), iosVersion: UIDevice.current.systemVersion,
                pageSize: size, protectionApplied: false, accessRestored: false,
                integrityVerified: false, detail: "mmap failed (errno=\(errno))")
        }
        defer { _ = munmap(memory, size) }
        memory.storeBytes(of: UInt32(0x13579BDF), as: UInt32.self)
        let protected = mprotect(memory, size, PROT_NONE) == 0
        // Never dereference protected memory here: the separate, confirmed button
        // demonstrates actual VM enforcement by terminating this app.
        let restored = protected && mprotect(memory, size, PROT_READ | PROT_WRITE) == 0
        let valid = restored && memory.load(as: UInt32.self) == 0x13579BDF
        return ProtectionReport(schema: "iosurface-evidence-lab/protection-v7",
            timestamp: Date(), iosVersion: UIDevice.current.systemVersion,
            pageSize: size, protectionApplied: protected,
            accessRestored: restored, integrityVerified: valid,
            detail: valid ? "Una página RW pasó a PROT_NONE y regresó a RW conservando el token."
                          : "No se verificó todo el ciclo de protección. Revisar permisos y errno.")
    }

    static func triggerProtectedPageFault() {
        let size = Int(getpagesize())
        let p = mmap(nil, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0)
        guard p != MAP_FAILED, let memory = p else { return }
        memory.storeBytes(of: UInt32(0x13579BDF), as: UInt32.self)
        guard mprotect(memory, size, PROT_NONE) == 0 else {
            _ = munmap(memory, size)
            return
        }
        UserDefaults.standard.set(true, forKey: markerKey)
        // Persist marker before triggering the deliberate *userspace* fault.
        CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication)
        memory.storeBytes(of: UInt32(0xDEADBEEF), as: UInt32.self)
        // Expected: EXC_BAD_ACCESS for the app process. If it is not terminated,
        // do not leave a protected mapping behind.
        _ = munmap(memory, size)
    }
}

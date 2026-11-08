import Foundation
import CoreFoundation
import IOSurface
import UIKit

struct StressReport: Codable {
    let schema: String
    let timestamp: Date
    let iosVersion: String
    let workers: Int
    let operations: Int
    let created: Int
    let verified: Int
    let elapsedNanoseconds: UInt64
    let errors: [String]
    let interpretation: String
}

/// Bounded concurrency stress through public IOSurface APIs only.
/// No use-after-free, invalid pointer, kernel-memory access, or SPTM interaction.
enum SurfaceStressTest {
    static func run() -> StressReport {
        let workers = 4
        let perWorker = 50
        let lock = NSLock()
        var created = 0
        var verified = 0
        var errors: [String] = []
        let start = DispatchTime.now().uptimeNanoseconds

        DispatchQueue.concurrentPerform(iterations: workers) { worker in
            for i in 0..<perWorker {
                autoreleasepool {
                    let dimension: Int32 = [64, 128, 256][(worker + i) % 3]
                    var keys = kCFTypeDictionaryKeyCallBacks
                    var values = kCFTypeDictionaryValueCallBacks
                    guard let props = CFDictionaryCreateMutable(kCFAllocatorDefault, 4, &keys, &values) else {
                        lock.lock(); errors.append("worker \(worker): properties allocation failed"); lock.unlock()
                        return
                    }
                    let pairs: [(CFString, Int32)] = [
                        (kIOSurfaceWidth, dimension),
                        (kIOSurfaceHeight, dimension),
                        (kIOSurfaceBytesPerElement, 4),
                        (kIOSurfacePixelFormat, 0x42475241)
                    ]
                    for (key, value) in pairs {
                        var v = value
                        if let number = CFNumberCreate(kCFAllocatorDefault, .sInt32Type, &v) {
                            CFDictionarySetValue(props,
                                Unmanaged.passUnretained(key).toOpaque(),
                                Unmanaged.passUnretained(number).toOpaque())
                        }
                    }
                    guard let owner = IOSurfaceCreate(props) else {
                        lock.lock(); errors.append("worker \(worker), op \(i): IOSurfaceCreate returned nil"); lock.unlock()
                        return
                    }
                    lock.lock(); created += 1; lock.unlock()
                    let id = IOSurfaceGetID(owner)
                    let token = UInt64(truncatingIfNeeded: worker * 100_000 + i + 1) ^ 0xE5A37B281D0CF649
                    guard IOSurfaceGetAllocSize(owner) >= 8, IOSurfaceLock(owner, [], nil) == 0 else {
                        lock.lock(); errors.append("worker \(worker), op \(i): owner lock/capacity failed"); lock.unlock()
                        return
                    }
                    IOSurfaceGetBaseAddress(owner).storeBytes(of: token, as: UInt64.self)
                    let unlockResult = IOSurfaceUnlock(owner, [], nil)
                    if unlockResult != 0 {
                        lock.lock(); errors.append("worker \(worker), op \(i): owner unlock failed"); lock.unlock()
                        return
                    }
                    guard let second = IOSurfaceLookup(id), IOSurfaceGetAllocSize(second) >= 8,
                          IOSurfaceLock(second, [], nil) == 0 else {
                        lock.lock(); errors.append("worker \(worker), op \(i): live lookup or lock failed for \(id)"); lock.unlock()
                        return
                    }
                    let observed = IOSurfaceGetBaseAddress(second).load(as: UInt64.self)
                    let unlocked = IOSurfaceUnlock(second, [], nil)
                    if observed == token && unlocked == 0 {
                        lock.lock(); verified += 1; lock.unlock()
                    } else {
                        lock.lock(); errors.append("worker \(worker), op \(i): token mismatch or unlock error for \(id)"); lock.unlock()
                    }
                }
            }
        }
        let elapsed = DispatchTime.now().uptimeNanoseconds &- start
        return StressReport(
            schema: "iosurface-evidence-lab/stress-v5",
            timestamp: Date(), iosVersion: UIDevice.current.systemVersion,
            workers: workers, operations: workers * perWorker,
            created: created, verified: verified,
            elapsedNanoseconds: elapsed,
            errors: errors,
            interpretation: "Concurrent public-API IO on app-owned IOSurfaces; no kernel memory corruption, SPTM bypass or exploit asserted."
        )
    }
}

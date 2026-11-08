import Foundation
import IOSurface
import UIKit

struct InvariantCampaignReport: Codable {
    let schema: String
    let date: Date
    let iosVersion: String
    let seed: UInt64
    let sentinels: Int
    let workers: Int
    let attemptedChurn: Int
    let churnCompleted: Int
    let sentinelChecks: Int
    let elapsedNanoseconds: UInt64
    let verdict: String
    let firstAnomaly: String?
    let notes: String
}

enum PersistentInvariantLab {
    private static func surface(_ width: Int32, _ height: Int32) -> IOSurfaceRef? {
        var keys = kCFTypeDictionaryKeyCallBacks
        var vals = kCFTypeDictionaryValueCallBacks
        guard let dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 4, &keys, &vals) else { return nil }
        let props: [(CFString, Int32)] = [
            (kIOSurfaceWidth, width), (kIOSurfaceHeight, height),
            (kIOSurfaceBytesPerElement, 4), (kIOSurfacePixelFormat, 0x42475241)
        ]
        for (key, value) in props {
            var val = value
            guard let num = CFNumberCreate(kCFAllocatorDefault, .sInt32Type, &val) else { return nil }
            CFDictionarySetValue(dict, Unmanaged.passUnretained(key).toOpaque(),
                                 Unmanaged.passUnretained(num).toOpaque())
        }
        return IOSurfaceCreate(dict)
    }

    static func run() -> InvariantCampaignReport {
        let start = DispatchTime.now().uptimeNanoseconds
        let seed: UInt64 = 0xD931A30F
        let target = 400
        let workers = 4
        let sentinelCount = 8
        var sentinels: [IOSurfaceRef] = []
        var ids: [UInt32] = []
        var firstAnomaly: String?
        let sync = NSLock()
        var completed = 0
        var checks = 0

        func fail(_ message: String) {
            sync.lock()
            if firstAnomaly == nil { firstAnomaly = message }
            sync.unlock()
        }
        func isFailed() -> Bool {
            sync.lock(); defer { sync.unlock() }
            return firstAnomaly != nil
        }
        func marker(_ index: Int) -> UInt32 {
            UInt32(truncatingIfNeeded: seed) ^ (UInt32(index) &* 0x9E3779B9)
        }
        func verify(_ i: Int) -> Bool {
            let owner = sentinels[i]
            let width = IOSurfaceGetWidth(owner)
            let height = IOSurfaceGetHeight(owner)
            let row = IOSurfaceGetBytesPerRow(owner)
            let size = IOSurfaceGetAllocSize(owner)
            guard width == 64, height == 64, row >= 256,
                  size >= (height - 1) * row + 256 else {
                fail("Sentinel \(i) metadata changed unexpectedly")
                return false
            }
            guard IOSurfaceGetID(owner) == ids[i] else {
                fail("Sentinel \(i) ID changed while retained")
                return false
            }
            guard let alias = IOSurfaceLookup(ids[i]) else {
                fail("Sentinel \(i) no longer resolvable while retained")
                return false
            }
            guard IOSurfaceLock(alias, [], nil) == 0 else {
                fail("Sentinel \(i) could not lock second live reference")
                return false
            }
            let base = IOSurfaceGetBaseAddress(alias)
            let offset = (height - 1) * row + (width - 1) * 4
            let first = base.load(as: UInt32.self)
            let last = base.advanced(by: offset).load(as: UInt32.self)
            let unlocked = IOSurfaceUnlock(alias, [], nil) == 0
            if first != marker(i) || last != ~marker(i) || !unlocked {
                fail("Sentinel \(i) integrity mismatch: first=\(first) last=\(last) unlock=\(unlocked)")
                return false
            }
            return true
        }
        for i in 0..<sentinelCount {
            guard let s = surface(64,64) else {
                fail("Unable to create sentinel \(i)")
                break
            }
            let row = IOSurfaceGetBytesPerRow(s)
            let size = IOSurfaceGetAllocSize(s)
            guard row >= 256, size >= 63 * row + 256,
                  IOSurfaceLock(s, [], nil) == 0 else {
                fail("Unable to initialize sentinel \(i)")
                break
            }
            let p = IOSurfaceGetBaseAddress(s)
            p.storeBytes(of: marker(i), as: UInt32.self)
            p.advanced(by: 63 * row + 63 * 4).storeBytes(of: ~marker(i), as: UInt32.self)
            guard IOSurfaceUnlock(s, [], nil) == 0 else {
                fail("Unable to unlock initialized sentinel \(i)")
                break
            }
            sentinels.append(s)
            ids.append(IOSurfaceGetID(s))
        }
        if !isFailed() && Set(ids).count != ids.count {
            fail("Collision between simultaneously retained sentinel IDs")
        }
        if !isFailed() {
            DispatchQueue.concurrentPerform(iterations: workers) { worker in
                for step in 0..<(target / workers) {
                    if isFailed() { break }
                    autoreleasepool {
                        let width: Int32 = [Int32(1), 7, 64, 127, 256][(step + worker) % 5]
                        let height: Int32 = [Int32(1), 9, 64, 129, 256][(step * 3 + worker) % 5]
                        guard let churn = surface(width, height) else {
                            fail("Churn \(worker):\(step) create failed")
                            return
                        }
                        let row = IOSurfaceGetBytesPerRow(churn)
                        let alloc = IOSurfaceGetAllocSize(churn)
                        if row < Int(width) * 4 || alloc < Int(height) * row {
                            fail("Churn \(worker):\(step) allocation/stride contract mismatch")
                            return
                        }
                        if IOSurfaceLock(churn, [], nil) != 0 {
                            fail("Churn \(worker):\(step) lock failed")
                            return
                        }
                        let tag = UInt32(worker * 10000 + step)
                        IOSurfaceGetBaseAddress(churn).storeBytes(of: tag, as: UInt32.self)
                        if IOSurfaceUnlock(churn, [], nil) != 0 {
                            fail("Churn \(worker):\(step) unlock failed")
                            return
                        }
                        let id = IOSurfaceGetID(churn)
                        guard let alias = IOSurfaceLookup(id) else {
                            fail("Churn \(worker):\(step) valid lookup failed")
                            return
                        }
                        if IOSurfaceLock(alias, [], nil) != 0 {
                            fail("Churn \(worker):\(step) alias lock failed")
                            return
                        }
                        let readBack = IOSurfaceGetBaseAddress(alias).load(as: UInt32.self)
                        let unlockOK = IOSurfaceUnlock(alias, [], nil) == 0
                        if readBack != tag || !unlockOK {
                            fail("Churn \(worker):\(step) self-integrity mismatch")
                            return
                        }
                        sync.lock()
                        completed += 1
                        sync.unlock()
                    }
                }
            }
        }
        // Read sentinels only after concurrent workers finish, so no shared
        // writes or data races are introduced by the test itself.
        for i in 0..<sentinels.count {
            if verify(i) { checks += 1 }
        }
        return InvariantCampaignReport(
            schema: "iosurface-evidence-lab/persistent-invariants-v9",
            date: Date(), iosVersion: UIDevice.current.systemVersion,
            seed: seed, sentinels: sentinels.count, workers: workers,
            attemptedChurn: target, churnCompleted: completed,
            sentinelChecks: checks,
            elapsedNanoseconds: DispatchTime.now().uptimeNanoseconds &- start,
            verdict: firstAnomaly == nil ? "NO_ANOMALY_OBSERVED" : "INVARIANT_MISMATCH",
            firstAnomaly: firstAnomaly,
            notes: "Public IOSurface APIs with valid, retained references. A mismatch must be reproduced independently and is not itself evidence of kernel exploitation.")
    }
}

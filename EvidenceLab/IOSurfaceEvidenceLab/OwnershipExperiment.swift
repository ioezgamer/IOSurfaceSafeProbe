import Foundation
import CoreFoundation
import IOSurface
import UIKit

struct OwnershipEvent: Codable {
    let phase: String
    let elapsedNanoseconds: UInt64
    let surfaceID: UInt32?
    let result: String
    let detail: String
}
struct OwnershipReport: Codable {
    let schema: String
    let generatedAt: Date
    let iosVersion: String
    let totalCreated: Int
    let activeIDCollisions: Int
    let reusedReleasedIDs: Int
    let verifiedReads: Int
    let errors: [String]
    let events: [OwnershipEvent]
    let conclusion: String
}

// Owns every IOSurface reference while calling its public APIs.
// No dangling pointers, unsafe lookup of released memory, kernel addresses or private APIs.
enum OwnershipExperiment {
    static func execute() -> OwnershipReport {
        let start = DispatchTime.now().uptimeNanoseconds
        var events: [OwnershipEvent] = []
        var errors: [String] = []
        var live: [UInt32: IOSurfaceRef] = [:]
        var tokens: [UInt32: UInt64] = [:]
        var releasedIDs: Set<UInt32> = []
        var created = 0
        var collisions = 0
        var recycled = 0
        var verified = 0

        func event(_ phase: String, _ id: UInt32?, _ result: String, _ detail: String) {
            let elapsed = DispatchTime.now().uptimeNanoseconds &- start
            events.append(OwnershipEvent(phase: phase, elapsedNanoseconds: elapsed,
                                         surfaceID: id, result: result, detail: detail))
            if result == "FAIL" { errors.append(phase + ": " + detail) }
        }

        func createSurface() -> IOSurfaceRef? {
            var keys = kCFTypeDictionaryKeyCallBacks
            var values = kCFTypeDictionaryValueCallBacks
            guard let properties = CFDictionaryCreateMutable(kCFAllocatorDefault, 4, &keys, &values) else { return nil }
            let pairs: [(CFString, Int32)] = [
                (kIOSurfaceWidth, 64),
                (kIOSurfaceHeight, 64),
                (kIOSurfaceBytesPerElement, 4),
                (kIOSurfacePixelFormat, 0x42475241)
            ]
            for (key, value) in pairs {
                var v = value
                guard let number = CFNumberCreate(kCFAllocatorDefault, .sInt32Type, &v) else { return nil }
                CFDictionarySetValue(properties,
                    Unmanaged.passUnretained(key).toOpaque(),
                    Unmanaged.passUnretained(number).toOpaque())
            }
            return IOSurfaceCreate(properties)
        }

        func add(_ phase: String) {
            guard let surface = createSurface() else {
                event(phase, nil, "FAIL", "IOSurfaceCreate failed")
                return
            }
            let id = IOSurfaceGetID(surface)
            created += 1
            if live[id] != nil {
                // Do not replace live[id]; preserve references and report collision.
                collisions += 1
                event(phase, id, "FAIL", "ID already belongs to another live reference")
                return
            }
            if releasedIDs.contains(id) {
                recycled += 1
                event(phase, id, "OBSERVED", "Released ID issued again; not an address match or UAF")
            }
            let token = UInt64.random(in: 1...UInt64.max)
            guard IOSurfaceGetAllocSize(surface) >= MemoryLayout<UInt64>.size else {
                event(phase, id, "FAIL", "Surface capacity too small")
                return
            }
            guard IOSurfaceLock(surface, [], nil) == 0 else {
                event(phase, id, "FAIL", "Could not lock own IOSurface")
                return
            }
            IOSurfaceGetBaseAddress(surface).storeBytes(of: token, as: UInt64.self)
            let unlock = IOSurfaceUnlock(surface, [], nil)
            if unlock != 0 { event(phase, id, "FAIL", "Unlock failed") }
            live[id] = surface
            tokens[id] = token
            event(phase, id, "PASS", "Live owner retained; unique token stored")
        }

        func verify(_ phase: String) {
            for id in live.keys.sorted() {
                guard let expected = tokens[id], let retained = IOSurfaceLookup(id) else {
                    event(phase, id, "FAIL", "Live object not found by IOSurfaceLookup")
                    continue
                }
                guard IOSurfaceGetAllocSize(retained) >= 8, IOSurfaceLock(retained, [], nil) == 0 else {
                    event(phase, id, "FAIL", "Live object unavailable for read")
                    continue
                }
                let actual = IOSurfaceGetBaseAddress(retained).load(as: UInt64.self)
                let unlock = IOSurfaceUnlock(retained, [], nil)
                if actual == expected && unlock == 0 {
                    verified += 1
                    event(phase, id, "PASS", "Token verified through valid second reference")
                } else {
                    event(phase, id, "FAIL", "Token mismatch or unlock failed")
                }
            }
        }

        for _ in 0..<8 { add("initial_parallel") }
        verify("verify_all_live")

        let toRelease = Array(live.keys.sorted().prefix(4))
        for id in toRelease {
            live.removeValue(forKey: id)
            tokens.removeValue(forKey: id)
            releasedIDs.insert(id)
            let stillResolves = IOSurfaceLookup(id) != nil
            event("release_half", id, "OBSERVED",
                  stillResolves ? "ID still resolves; other system references may remain" :
                    "ID no longer resolves; does not imply kernel UAF")
        }
        verify("verify_survivors")

        for _ in 0..<4 { add("replace_released") }
        verify("verify_combined")
        let remaining = live.keys.sorted()
        for id in remaining {
            live.removeValue(forKey: id)
            tokens.removeValue(forKey: id)
            let found = IOSurfaceLookup(id) != nil
            event("final_release", id, "OBSERVED",
                  found ? "ID still resolves" : "ID no longer resolves")
        }

        return OwnershipReport(schema: "iosurface-evidence-lab/ownership-v3",
                               generatedAt: Date(), iosVersion: UIDevice.current.systemVersion,
                               totalCreated: created, activeIDCollisions: collisions,
                               reusedReleasedIDs: recycled, verifiedReads: verified,
                               errors: errors, events: events,
                               conclusion: "Public-API ownership test only. ID reuse is not kernel-address reuse. No kernel UAF, kread, kwrite or SPTM bypass was tested.")
    }
}

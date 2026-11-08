import Foundation
import CoreFoundation
import IOSurface
import UIKit

struct MatrixCase: Codable {
    let caseID: String
    let width: Int
    let height: Int
    let expectedMinimumBytes: Int
    let actualAllocationBytes: Int?
    let surfaceID: UInt32?
    let elapsedNanoseconds: UInt64
    let status: String
    let detail: String
}
struct MatrixReport: Codable {
    let schema: String
    let timestamp: Date
    let iosVersion: String
    let cases: [MatrixCase]
    let passed: Int
    let failed: Int
    let unavailable: Int
    let elapsedNanoseconds: UInt64
    let limitations: [String]
}

/// Real, bounded checks of PUBLIC IOSurface contracts.
/// No invalid pointer, races over a shared mutable buffer, or kernel exploit behavior.
enum SurfaceMatrixLab {
    static func run() -> MatrixReport {
        let start = DispatchTime.now().uptimeNanoseconds
        let configurations: [(Int32, Int32)] = [
            (1, 1), (2, 3), (7, 9), (64, 64),
            (127, 129), (256, 256), (512, 512), (32, 512)
        ]
        let countPerConfig = 8
        let total = configurations.count * countPerConfig
        let lock = NSLock()
        var collected: [MatrixCase] = []

        DispatchQueue.concurrentPerform(iterations: 4) { worker in
            for sequence in stride(from: worker, to: total, by: 4) {
                autoreleasepool {
                    let config = configurations[sequence % configurations.count]
                    let w = config.0
                    let h = config.1
                    let name = "case-\(sequence)-\(w)x\(h)"
                    let started = DispatchTime.now().uptimeNanoseconds
                    func finish(_ status: String, _ detail: String,
                                _ allocation: Int? = nil, _ id: UInt32? = nil) {
                        let elapsed = DispatchTime.now().uptimeNanoseconds &- started
                        let test = MatrixCase(caseID: name, width: Int(w), height: Int(h),
                            expectedMinimumBytes: Int(w) * Int(h) * 4,
                            actualAllocationBytes: allocation, surfaceID: id,
                            elapsedNanoseconds: elapsed, status: status, detail: detail)
                        lock.lock()
                        collected.append(test)
                        lock.unlock()
                    }
                    var keyCallbacks = kCFTypeDictionaryKeyCallBacks
                    var valueCallbacks = kCFTypeDictionaryValueCallBacks
                    guard let props = CFDictionaryCreateMutable(kCFAllocatorDefault, 4,
                                             &keyCallbacks, &valueCallbacks) else {
                        finish("UNAVAILABLE", "Could not construct properties")
                        return
                    }
                    let pairs: [(CFString, Int32)] = [
                        (kIOSurfaceWidth, w),
                        (kIOSurfaceHeight, h),
                        (kIOSurfaceBytesPerElement, 4),
                        (kIOSurfacePixelFormat, 0x42475241)
                    ]
                    for (key, value) in pairs {
                        var valueCopy = value
                        guard let number = CFNumberCreate(kCFAllocatorDefault, .sInt32Type, &valueCopy) else {
                            finish("UNAVAILABLE", "Could not construct CFNumber")
                            return
                        }
                        CFDictionarySetValue(props, Unmanaged.passUnretained(key).toOpaque(),
                                             Unmanaged.passUnretained(number).toOpaque())
                    }
                    guard let owner = IOSurfaceCreate(props) else {
                        finish("UNAVAILABLE", "IOSurfaceCreate rejected this configuration")
                        return
                    }
                    let id = IOSurfaceGetID(owner)
                    let actualSize = IOSurfaceGetAllocSize(owner)
                    let bytesPerRow = IOSurfaceGetBytesPerRow(owner)
                    let actualWidth = IOSurfaceGetWidth(owner)
                    let actualHeight = IOSurfaceGetHeight(owner)
                    let minimum = Int(w) * Int(h) * 4
                    guard actualWidth == Int(w), actualHeight == Int(h),
                          bytesPerRow >= Int(w) * 4,
                          actualSize >= minimum else {
                        finish("FAIL", "Dimension/stride/allocation invariant failed; stride \(bytesPerRow)", actualSize, id)
                        return
                    }
                    guard IOSurfaceLock(owner, [], nil) == 0 else {
                        finish("FAIL", "Could not lock owned pixels", actualSize, id)
                        return
                    }
                    let marker = UInt64(sequence + 1) ^ 0x9473D812C56FA209
                    let buffer = IOSurfaceGetBaseAddress(owner)
                    buffer.storeBytes(of: marker, as: UInt64.self)
                    let endOffset = actualSize - MemoryLayout<UInt64>.size
                    buffer.advanced(by: endOffset).storeBytes(of: marker ^ 0xA55A55A5, as: UInt64.self)
                    if IOSurfaceUnlock(owner, [], nil) != 0 {
                        finish("FAIL", "Unlock of owner failed", actualSize, id)
                        return
                    }
                    guard let second = IOSurfaceLookup(id) else {
                        finish("FAIL", "Could not look up live ID", actualSize, id)
                        return
                    }
                    guard IOSurfaceLock(second, [], nil) == 0 else {
                        finish("FAIL", "Could not lock second valid reference", actualSize, id)
                        return
                    }
                    let base = IOSurfaceGetBaseAddress(second)
                    let first = base.load(as: UInt64.self)
                    let last = base.advanced(by: endOffset).load(as: UInt64.self)
                    let secondUnlock = IOSurfaceUnlock(second, [], nil)
                    if first == marker && last == marker ^ 0xA55A55A5 && secondUnlock == 0 {
                        finish("PASS", "Dimensions, stride, first/last token and valid lookup verified; stride \(bytesPerRow)", actualSize, id)
                    } else {
                        finish("FAIL", "Owned buffer tokens or unlock diverged", actualSize, id)
                    }
                }
            }
        }
        let cases = collected.sorted { $0.caseID < $1.caseID }
        return MatrixReport(schema: "iosurface-evidence-lab/matrix-v6",
            timestamp: Date(), iosVersion: UIDevice.current.systemVersion,
            cases: cases, passed: cases.filter { $0.status == "PASS" }.count,
            failed: cases.filter { $0.status == "FAIL" }.count,
            unavailable: cases.filter { $0.status == "UNAVAILABLE" }.count,
            elapsedNanoseconds: DispatchTime.now().uptimeNanoseconds &- start,
            limitations: [
                "Expected min allocation is logical pixel count; stride may require additional padding.",
                "The test writes first and last 8 bytes of a valid IOSurface pixel buffer.",
                "No kernel memory instrumentation, UAF, kernel write or SPTM bypass is attempted.",
                "Unexpected results need repeat tests and independent system logs."
            ])
    }
}

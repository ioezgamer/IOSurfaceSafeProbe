import Foundation

enum MemoryASanDemo {
    @inline(never)
    static func trigger() {
        // Only enabled in the dedicated AddressSanitizer build.
        // Userland allocation; no kernel or IOSurface access.
        #if ASAN_LAB
        let storage = UnsafeMutablePointer<UInt8>.allocate(capacity: 8)
        for i in 0..<8 {
            storage.advanced(by: i).pointee = UInt8(i)
        }
        // Deliberately write one byte beyond the allocated region.
        // Expected: ASan heap-buffer-overflow, followed by app termination.
        storage.advanced(by: 8).pointee = 0xA5
        storage.deallocate()
        #endif
    }
}

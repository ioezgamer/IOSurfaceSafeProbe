import Foundation

struct AppCacheInfo: Identifiable, Hashable {
    let id = UUID()
    let bundleID: String
    let path: String
    let cacheSize: UInt64
    var selected: Bool = true
    var formattedSize: String {
        ByteCountFormatter.string(fromByteCount: Int64(cacheSize), countStyle: .file)
    }
}

class CacheManager: ObservableObject {
    @Published var apps: [AppCacheInfo] = []
    @Published var isScanning = false
    @Published var isCleaning = false
    @Published var totalCacheSize: UInt64 = 0
    @Published var freedSpace: UInt64 = 0
    @Published var statusMessage = ""
    @Published var detectedGroup: String = "detecting..."
    @Published var signatureGroups: [String] = []
    @Published var workingGroup: String = "none yet"
    @Published var needsTrollStore = false

    private let cachePaths = ["/var/mobile/Containers/Data/Application"]

    func detectGroup() {
        KMWorseQueryResetGroupCache()
        let group = KMWorseQueryAppGroup()
        let allGroups = KMWorseQuerySignatureGroups() as? [String] ?? []
        let sideloaderDetected = KMWorseQueryUsingSideloaderGroups()
        detectedGroup = group ?? "none"
        signatureGroups = allGroups
        needsTrollStore = sideloaderDetected
        if sideloaderDetected {
            print("[AppGroup] WARNING: Sideloader groups detected - install via TrollStore!")
        }
        if let g = group {
            print("[AppGroup] Primary: \(g)")
            print("[AppGroup] All: \(allGroups.joined(separator: ", "))")
        } else {
            print("[AppGroup] ERROR: No usable App Group found")
        }
    }

    private func consumeExtensionTryingAllGroups(_ path: String) -> (Int64, String?) {
        let allGroups = KMWorseQuerySignatureGroups() as? [String] ?? []
        let ver = ProcessInfo.processInfo.operatingSystemVersion
        print("[Exploit] iOS \(ver.majorVersion).\(ver.minorVersion).\(ver.patchVersion)")
        print("[Exploit] Target: \(path)")
        print("[Exploit] Groups (\(allGroups.count)): \(allGroups)")

        var lastErr: Int64 = 0
        for altFlags in [false, true] {
            let flagLabel = altFlags ? "alt(0x800000000)" : "primary(0x8000000000)"
            for group in allGroups {
                let handle = worse_query(path, group, altFlags, true)
                if handle > 0 {
                    print("[Exploit] SUCCESS group=\(group) flags=\(flagLabel) handle=\(handle)")
                    return (handle, group)
                }
                lastErr = handle
                print("[Exploit] FAIL group=\(group) flags=\(flagLabel) err=\(handle)")
            }
        }

        DispatchQueue.main.async {
            self.statusMessage = "Exploit failed (err=\(lastErr), \(allGroups.count) groups)"
        }
        return (lastErr, nil)
    }

    func scanCaches() {
        let allGroups = KMWorseQuerySignatureGroups() as? [String] ?? []
        guard !allGroups.isEmpty else {
            statusMessage = "No App Groups found"
            return
        }

        isScanning = true; apps = []; totalCacheSize = 0
        statusMessage = "Scanning (\(allGroups.count) groups)..."
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            var found: [AppCacheInfo] = []
            for basePath in self.cachePaths {
                let (handle, usedGroup) = self.consumeExtensionTryingAllGroups(basePath)
                if handle > 0 {
                    DispatchQueue.main.async { self.workingGroup = usedGroup ?? "unknown" }
                    found += self.scanContainers(basePath: basePath)
                    worse_query_release(handle)
                } else {
                    print("[Scan] All methods failed for: \(basePath)")
                }
            }
            self.finishScan(found)
        }
    }

    private func scanContainers(basePath: String) -> [AppCacheInfo] {
        var found: [AppCacheInfo] = []
        let fm = FileManager.default
        let baseURL = URL(filePath: basePath)
        do {
            let containers = try fm.contentsOfDirectory(at: baseURL, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles])
            for containerURL in containers {
                let resources = try? containerURL.resourceValues(forKeys: [.isDirectoryKey])
                guard resources?.isDirectory == true else { continue }
                let containerPath = containerURL.path
                let bundleID = getBundleID(at: containerPath)
                var size: UInt64 = 0
                for sub in ["Library/Caches", "tmp"] {
                    size += directorySize(at: containerURL.appending(path: sub))
                }
                if size > 0 {
                    found.append(AppCacheInfo(bundleID: bundleID ?? containerURL.lastPathComponent, path: containerPath, cacheSize: size))
                }
            }
        } catch { print("[Scan] Error: \(error)") }
        return found
    }

    private func finishScan(_ found: [AppCacheInfo]) {
        let sorted = found.sorted { $0.cacheSize > $1.cacheSize }
        let total = sorted.reduce(0) { $0 + $1.cacheSize }
        DispatchQueue.main.async {
            self.apps = sorted; self.totalCacheSize = total; self.isScanning = false
            self.statusMessage = "Found \(sorted.count) apps with caches"
        }
    }

    func cleanSelected() {
        let toClean = apps.filter { $0.selected }
        guard !toClean.isEmpty else { return }
        isCleaning = true; freedSpace = 0; statusMessage = "Cleaning..."
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            let fm = FileManager.default; var freed: UInt64 = 0
            for app in toClean {
                let (handle, _) = self.consumeExtensionTryingAllGroups(app.path)
                if handle <= 0 { continue }
                let activeHandle = handle
                let containerURL = URL(filePath: app.path)
                for sub in ["Library/Caches", "tmp"] {
                    let cacheDir = containerURL.appending(path: sub)
                    let before = self.directorySize(at: cacheDir)
                    if let items = try? fm.contentsOfDirectory(at: cacheDir, includingPropertiesForKeys: nil) {
                        for item in items { try? fm.removeItem(at: item) }
                    }
                    let after = self.directorySize(at: cacheDir)
                    if before > after { freed += (before - after) }
                }
                worse_query_release(activeHandle)
            }
            DispatchQueue.main.async {
                self.freedSpace = freed; self.isCleaning = false
                self.statusMessage = "Freed \(ByteCountFormatter.string(fromByteCount: Int64(freed), countStyle: .file))"
                self.scanCaches()
            }
        }
    }

    private func getBundleID(at path: String) -> String? {
        var buf = [CChar](repeating: 0, count: 512)
        let len = getxattr(path, "com.apple.containermanager.identifier", &buf, 511, 0, 0)
        return len > 0 ? String(cString: buf) : nil
    }

    private func directorySize(at url: URL) -> UInt64 {
        guard let enumerator = FileManager.default.enumerator(at: url, includingPropertiesForKeys: [.fileSizeKey, .isRegularFileKey], options: [.skipsHiddenFiles]) else { return 0 }
        var total: UInt64 = 0
        for case let fileURL as URL in enumerator {
            guard let v = try? fileURL.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey]), v.isRegularFile == true, let s = v.fileSize else { continue }
            total += UInt64(s)
        }
        return total
    }
}

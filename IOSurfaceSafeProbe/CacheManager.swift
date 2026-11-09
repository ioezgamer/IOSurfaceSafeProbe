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

    private let cachePaths = ["/var/mobile/Containers/Data/Application"]

    func detectGroup() {
        KMWorseQueryResetGroupCache()
        let group = KMWorseQueryAppGroup()
        let allGroups = KMWorseQuerySignatureGroups() as? [String] ?? []
        detectedGroup = group ?? "none"
        signatureGroups = allGroups
        if let g = group {
            print("[AppGroup] Primary: \(g)")
            print("[AppGroup] All signed: \(allGroups.joined(separator: ", "))")
        } else {
            print("[AppGroup] ERROR: No usable App Group found")
        }
    }

    private func consumeExtensionTryingAllGroups(_ path: String) -> (Int64, String?) {
        let allGroups = KMWorseQuerySignatureGroups() as? [String] ?? []
        let isAppGroup = path.contains("/var/mobile/Containers/Shared/AppGroup")
        let isIOS26 = ProcessInfo.processInfo.operatingSystemVersion.majorVersion == 26
        let altFlags = isAppGroup && isIOS26
        for group in allGroups {
            let handle = worse_query(path, group, altFlags, false)
            if handle > 0 {
                print("[Exploit] SUCCESS with group: \(group) (handle: \(handle))")
                return (handle, group)
            }
            print("[Exploit] Group \(group) failed (error \(handle))")
        }
        return (-6, nil)
    }

    func scanCaches() {
        let allGroups = KMWorseQuerySignatureGroups() as? [String] ?? []
        guard !allGroups.isEmpty else { statusMessage = "No App Groups in signature"; return }
        isScanning = true; apps = []; totalCacheSize = 0
        statusMessage = "Scanning (\(allGroups.count) groups)..."
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            var found: [AppCacheInfo] = []
            for basePath in self.cachePaths {
                let (handle, usedGroup) = self.consumeExtensionTryingAllGroups(basePath)
                if handle < 0 { print("[Scan] All groups failed for: \(basePath)"); continue }
                DispatchQueue.main.async { self.workingGroup = usedGroup ?? "unknown" }
                let fm = FileManager.default
                let baseURL = URL(filePath: basePath)
                do {
                    let containers = try fm.contentsOfDirectory(at: baseURL, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles])
                    for containerURL in containers {
                        let resources = try? containerURL.resourceValues(forKeys: [.isDirectoryKey])
                        guard resources?.isDirectory == true else { continue }
                        let containerPath = containerURL.path
                        let bundleID = self.getBundleID(at: containerPath)
                        var size: UInt64 = 0
                        for sub in ["Library/Caches", "tmp"] {
                            size += self.directorySize(at: containerURL.appending(path: sub))
                        }
                        if size > 0 {
                            found.append(AppCacheInfo(bundleID: bundleID ?? containerURL.lastPathComponent, path: containerPath, cacheSize: size))
                        }
                    }
                } catch { print("[Scan] Error: \(error)") }
                worse_query_release(handle)
            }
            found.sort { $0.cacheSize > $1.cacheSize }
            let total = found.reduce(0) { $0 + $1.cacheSize }
            DispatchQueue.main.async {
                self.apps = found; self.totalCacheSize = total; self.isScanning = false
                self.statusMessage = "Found \(found.count) apps with caches"
            }
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
                if handle < 0 { continue }
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
                worse_query_release(handle)
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

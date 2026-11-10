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
    @Published var logText: String = ""

    private let cachePaths = ["/var/mobile/Containers/Data/Application"]

    func detectGroup() {
        let group = wq_app_group()
        detectedGroup = group ?? "none"
        logText = wq_log_text()
        if let g = group {
            print("[CacheWipe] Group: \(g)")
        } else {
            print("[CacheWipe] ERROR: No usable App Group found")
        }
    }

    func scanCaches() {
        guard wq_app_group() != nil else {
            statusMessage = "No App Group found"
            return
        }
        isScanning = true; apps = []; totalCacheSize = 0
        statusMessage = "Scanning..."
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            var found: [AppCacheInfo] = []
            for basePath in self.cachePaths {
                if wq_grant(basePath) {
                    found += self.scanContainers(basePath: basePath)
                } else {
                    print("[Scan] Grant failed for: \(basePath)")
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
                    let subPath = containerURL.appending(path: sub).path
                    if wq_grant(subPath) {
                        size += directorySize(at: containerURL.appending(path: sub))
                    }
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
            self.logText = wq_log_text()
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
                let containerURL = URL(filePath: app.path)
                for sub in ["Library/Caches", "tmp"] {
                    let cacheDir = containerURL.appending(path: sub)
                    guard wq_grant(cacheDir.path) else { continue }
                    let before = self.directorySize(at: cacheDir)
                    if let items = try? fm.contentsOfDirectory(at: cacheDir, includingPropertiesForKeys: nil) {
                        for item in items { try? fm.removeItem(at: item) }
                    }
                    let after = self.directorySize(at: cacheDir)
                    if before > after { freed += (before - after) }
                }
            }
            DispatchQueue.main.async {
                self.freedSpace = freed; self.isCleaning = false
                self.statusMessage = "Freed \(ByteCountFormatter.string(fromByteCount: Int64(freed), countStyle: .file))"
                self.logText = wq_log_text()
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

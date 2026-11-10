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
    @Published var scanProgress: String = ""

    private let containerParent = "/var/mobile/Containers/Data/Application"

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
        statusMessage = "Discovering containers..."
        scanProgress = ""
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }

            let containers = wq_enumerate(self.containerParent) { done, total, found in
                let pct = total > 0 ? Int(done * 100 / total) : 0
                DispatchQueue.main.async {
                    self.scanProgress = "\(pct)% scanned, \(found) found"
                    self.statusMessage = "Scanning: \(pct)% (\(found) apps)"
                }
            }

            guard let paths = containers as? [String], !paths.isEmpty else {
                DispatchQueue.main.async {
                    self.statusMessage = "No containers found"
                    self.isScanning = false
                    self.logText = wq_log_text()
                }
                return
            }

            DispatchQueue.main.async {
                self.statusMessage = "Measuring caches for \(paths.count) apps..."
            }

            var found: [AppCacheInfo] = []
            for containerPath in paths {
                let bundleID = self.getBundleID(at: containerPath)
                var size: UInt64 = 0
                for sub in ["Library/Caches", "tmp"] {
                    let subPath = (containerPath as NSString).appendingPathComponent(sub)
                    if wq_grant(subPath) {
                        size += self.directorySize(at: URL(filePath: subPath))
                    }
                }
                if size > 0 {
                    let name = bundleID ?? (containerPath as NSString).lastPathComponent
                    found.append(AppCacheInfo(bundleID: name, path: containerPath, cacheSize: size))
                }
            }
            self.finishScan(found)
        }
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
                for sub in ["Library/Caches", "tmp"] {
                    let cachePath = (app.path as NSString).appendingPathComponent(sub)
                    let cacheURL = URL(filePath: cachePath)
                    guard wq_grant(cachePath) else { continue }
                    let before = self.directorySize(at: cacheURL)
                    if let items = try? fm.contentsOfDirectory(at: cacheURL, includingPropertiesForKeys: nil) {
                        for item in items { try? fm.removeItem(at: item) }
                    }
                    let after = self.directorySize(at: cacheURL)
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

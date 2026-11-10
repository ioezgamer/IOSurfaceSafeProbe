import Foundation

struct AppCacheInfo: Identifiable, Hashable {
    let id = UUID()
    let bundleID: String
    let displayName: String
    let path: String
    let cacheSize: UInt64
    let tmpSize: UInt64
    var selected: Bool = true

    var totalSize: UInt64 { cacheSize + tmpSize }

    var formattedSize: String {
        ByteCountFormatter.string(fromByteCount: Int64(totalSize), countStyle: .file)
    }

    var formattedCacheSize: String {
        ByteCountFormatter.string(fromByteCount: Int64(cacheSize), countStyle: .file)
    }

    var formattedTmpSize: String {
        ByteCountFormatter.string(fromByteCount: Int64(tmpSize), countStyle: .file)
    }

    var sizeCategory: SizeCategory {
        if totalSize >= 100_000_000 { return .large }
        if totalSize >= 10_000_000 { return .medium }
        return .small
    }

    enum SizeCategory: String, CaseIterable {
        case large = "Large (>100 MB)"
        case medium = "Medium (10–100 MB)"
        case small = "Small (<10 MB)"
    }
}

enum SortOption: String, CaseIterable {
    case sizeDesc = "Size ↓"
    case sizeAsc = "Size ↑"
    case nameAsc = "Name A–Z"
    case nameDesc = "Name Z–A"
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
    @Published var scanProgressValue: Double = 0
    @Published var cleaningApp: String = ""
    @Published var lastScanDate: Date? = nil

    private let containerParent = "/var/mobile/Containers/Data/Application"

    var selectedCount: Int { apps.filter(\.selected).count }
    var selectedSize: UInt64 { apps.filter(\.selected).reduce(0) { $0 + $1.totalSize } }

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
        isScanning = true; apps = []; totalCacheSize = 0; freedSpace = 0
        statusMessage = "Discovering containers..."
        scanProgress = ""; scanProgressValue = 0
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }

            let containers = wq_enumerate(self.containerParent) { done, total, found in
                let pct = total > 0 ? Double(done) / Double(total) : 0
                DispatchQueue.main.async {
                    self.scanProgressValue = pct
                    self.scanProgress = "\(Int(pct * 100))% scanned, \(found) found"
                    self.statusMessage = "Scanning inodes: \(Int(pct * 100))%"
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
                self.statusMessage = "Measuring caches (0/\(paths.count))..."
            }

            var found: [AppCacheInfo] = []
            for (idx, containerPath) in paths.enumerated() {
                let resolved = self.resolveAppIdentity(at: containerPath)
                var cacheSz: UInt64 = 0
                var tmpSz: UInt64 = 0

                let cachePath = (containerPath as NSString).appendingPathComponent("Library/Caches")
                if wq_grant(cachePath) {
                    cacheSz = self.directorySize(at: URL(filePath: cachePath))
                }
                let tmpPath = (containerPath as NSString).appendingPathComponent("tmp")
                if wq_grant(tmpPath) {
                    tmpSz = self.directorySize(at: URL(filePath: tmpPath))
                }

                if cacheSz > 0 || tmpSz > 0 {
                    found.append(AppCacheInfo(
                        bundleID: resolved.bundleID,
                        displayName: resolved.displayName,
                        path: containerPath,
                        cacheSize: cacheSz,
                        tmpSize: tmpSz
                    ))
                }

                if idx % 5 == 0 {
                    DispatchQueue.main.async {
                        self.statusMessage = "Measuring caches (\(idx + 1)/\(paths.count))..."
                    }
                }
            }
            self.finishScan(found)
        }
    }

    private func finishScan(_ found: [AppCacheInfo]) {
        let sorted = found.sorted { $0.totalSize > $1.totalSize }
        let total = sorted.reduce(0 as UInt64) { $0 + $1.totalSize }
        DispatchQueue.main.async {
            self.apps = sorted; self.totalCacheSize = total; self.isScanning = false
            self.statusMessage = "Found \(sorted.count) apps with caches"
            self.logText = wq_log_text()
            self.lastScanDate = Date()
        }
    }

    func cleanSelected() {
        let toClean = apps.filter(\.selected)
        guard !toClean.isEmpty else { return }
        isCleaning = true; freedSpace = 0; statusMessage = "Cleaning..."
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            let fm = FileManager.default; var freed: UInt64 = 0
            for (idx, app) in toClean.enumerated() {
                DispatchQueue.main.async {
                    self.cleaningApp = app.displayName
                    self.statusMessage = "Cleaning \(idx + 1)/\(toClean.count)..."
                }
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
                self.freedSpace = freed; self.isCleaning = false; self.cleaningApp = ""
                self.statusMessage = "Freed \(ByteCountFormatter.string(fromByteCount: Int64(freed), countStyle: .file))"
                self.logText = wq_log_text()
                self.scanCaches()
            }
        }
    }

    func selectAll() { for i in apps.indices { apps[i].selected = true } }
    func deselectAll() { for i in apps.indices { apps[i].selected = false } }

    func selectByCategory(_ cat: AppCacheInfo.SizeCategory) {
        for i in apps.indices {
            apps[i].selected = apps[i].sizeCategory == cat
        }
    }

    func sortedApps(by option: SortOption, search: String) -> [AppCacheInfo] {
        var list = apps
        if !search.isEmpty {
            let q = search.lowercased()
            list = list.filter {
                $0.displayName.lowercased().contains(q) ||
                $0.bundleID.lowercased().contains(q)
            }
        }
        switch option {
        case .sizeDesc: list.sort { $0.totalSize > $1.totalSize }
        case .sizeAsc: list.sort { $0.totalSize < $1.totalSize }
        case .nameAsc: list.sort { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending }
        case .nameDesc: list.sort { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedDescending }
        }
        return list
    }

    private func resolveAppIdentity(at path: String) -> (bundleID: String, displayName: String) {
        let uuid = (path as NSString).lastPathComponent

        if let xattrID = getXattrBundleID(at: path) {
            return (xattrID, Self.prettyName(from: xattrID))
        }

        let metaPlist = (path as NSString).appendingPathComponent(
            ".com.apple.mobile_container_manager.metadata.plist")
        if let dict = NSDictionary(contentsOfFile: metaPlist),
           let mcmID = dict["MCMMetadataIdentifier"] as? String {
            return (mcmID, Self.prettyName(from: mcmID))
        }

        let libMetaPlist = (path as NSString).appendingPathComponent(
            "Library/.com.apple.mobile_container_manager.metadata.plist")
        if let dict = NSDictionary(contentsOfFile: libMetaPlist),
           let mcmID = dict["MCMMetadataIdentifier"] as? String {
            return (mcmID, Self.prettyName(from: mcmID))
        }

        let itunesPlist = (path as NSString).appendingPathComponent(
            "iTunesMetadata.plist")
        if let dict = NSDictionary(contentsOfFile: itunesPlist),
           let name = dict["itemName"] as? String {
            let bid = (dict["softwareVersionBundleId"] as? String) ?? uuid
            return (bid, name)
        }

        return (uuid, uuid)
    }

    private func getXattrBundleID(at path: String) -> String? {
        var buf = [CChar](repeating: 0, count: 512)
        let len = getxattr(path, "com.apple.containermanager.identifier", &buf, 511, 0, 0)
        return len > 0 ? String(cString: buf) : nil
    }

    static func prettyName(from bundleID: String) -> String {
        let parts = bundleID.split(separator: ".")
        if parts.count >= 2 {
            let last = String(parts.last!)
            if last.count > 2 {
                return last.prefix(1).uppercased() + last.dropFirst()
            }
        }
        return bundleID
    }

    private func directorySize(at url: URL) -> UInt64 {
        guard let enumerator = FileManager.default.enumerator(
            at: url,
            includingPropertiesForKeys: [.fileSizeKey, .isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else { return 0 }
        var total: UInt64 = 0
        for case let fileURL as URL in enumerator {
            guard let v = try? fileURL.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey]),
                  v.isRegularFile == true, let s = v.fileSize else { continue }
            total += UInt64(s)
        }
        return total
    }
}

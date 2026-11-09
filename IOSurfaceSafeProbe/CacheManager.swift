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

    private func canAccessDirectly(_ path: String) -> Bool {
        do {
            let contents = try FileManager.default.contentsOfDirectory(atPath: path)
            if !contents.isEmpty {
                print("[Access] Direct access to \(path) OK (\(contents.count) items)")
                return true
            }
        } catch {
            print("[Access] No direct access to \(path): \(error.localizedDescription)")
        }
        return false
    }

    private func obtainAccess(_ path: String) -> (Int64, String) {
        // Method 1: Direct access (TrollStore / unsandboxed / jailbroken)
        if canAccessDirectly(path) {
            return (0, "direct")
        }

        // Method 2: Container manager exploit with all group/flag/part combos
        let allGroups = KMWorseQuerySignatureGroups() as? [String] ?? []
        for altFlags in [false, true] {
            for group in allGroups {
                let handle = worse_query(path, group, altFlags, false)
                if handle > 0 {
                    print("[Exploit] SUCCESS group=\(group) altFlags=\(altFlags) handle=\(handle)")
                    return (handle, "exploit:\(group)")
                }
                print("[Exploit] group=\(group) altFlags=\(altFlags) err=\(handle)")
            }
        }

        // Method 3: sandbox_extension_issue_file_to_self
        let selfHandle = worse_query_issue_self(path)
        if selfHandle > 0 {
            print("[Fallback] issue_file_to_self succeeded handle=\(selfHandle)")
            return (selfHandle, "issue_self")
        }

        return (-1, "none")
    }

    func scanCaches() {
        isScanning = true; apps = []; totalCacheSize = 0
        statusMessage = "Scanning..."
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            var found: [AppCacheInfo] = []
            for basePath in self.cachePaths {
                let (handle, method) = self.obtainAccess(basePath)
                if handle < 0 {
                    print("[Scan] All methods failed for: \(basePath)")
                    DispatchQueue.main.async { self.statusMessage = "Access denied: \(basePath)" }
                    continue
                }

                DispatchQueue.main.async {
                    self.workingGroup = method
                    self.statusMessage = "Scanning via \(method)..."
                }

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
                } catch {
                    print("[Scan] Error listing \(basePath): \(error)")
                }

                if handle > 0 { worse_query_release(handle) }
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
                let (handle, _) = self.obtainAccess(app.path)
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
                if handle > 0 { worse_query_release(handle) }
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

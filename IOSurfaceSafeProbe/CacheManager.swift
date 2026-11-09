//
//  CacheManager.swift
//  IOSurfaceSafeProbe
//
//  Handles scanning and cleaning of app caches via worse_query.
//  App Group is detected automatically from the signed entitlements.
//

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
    
    private var appGroup: String? {
        return KMWorseQueryAppGroup()
    }
    
    private let cachePaths = [
        "/var/mobile/Containers/Data/Application"
    ]
    
    func detectGroup() {
        KMWorseQueryResetGroupCache()
        let group = KMWorseQueryAppGroup()
        let allGroups = KMWorseQuerySignatureGroups() as? [String] ?? []
        
        detectedGroup = group ?? "none"
        signatureGroups = allGroups
        
        if let g = group {
            print("[AppGroup] Active: \(g)")
        } else if allGroups.isEmpty {
            print("[AppGroup] ERROR: No App Groups in signature. Re-sign with App Groups enabled.")
        } else {
            print("[AppGroup] ERROR: \(allGroups.count) groups in signature but none have a container.")
        }
    }
    
    // MARK: - Scan
    
    func scanCaches() {
        guard let group = appGroup else {
            statusMessage = "No usable App Group"
            print("[Scan] Cannot scan: no App Group available")
            return
        }
        
        isScanning = true
        apps = []
        totalCacheSize = 0
        statusMessage = "Scanning..."
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            var found: [AppCacheInfo] = []
            
            for basePath in self.cachePaths {
                let handle = self.consumeExtension(basePath, group: group)
                if handle < 0 {
                    print("[Scan] Failed to access: \(basePath) (error \(handle))")
                    continue
                }
                
                let fm = FileManager.default
                let baseURL = URL(filePath: basePath)
                
                do {
                    let containers = try fm.contentsOfDirectory(
                        at: baseURL,
                        includingPropertiesForKeys: [.isDirectoryKey],
                        options: [.skipsHiddenFiles]
                    )
                    
                    for containerURL in containers {
                        let resources = try? containerURL.resourceValues(forKeys: [.isDirectoryKey])
                        guard resources?.isDirectory == true else { continue }
                        
                        let containerPath = containerURL.path
                        let bundleID = self.getBundleID(at: containerPath)
                        
                        let cacheDirs = [
                            containerURL.appending(path: "Library/Caches"),
                            containerURL.appending(path: "tmp")
                        ]
                        
                        var size: UInt64 = 0
                        for cacheDir in cacheDirs {
                            size += self.directorySize(at: cacheDir)
                        }
                        
                        if size > 0 {
                            let info = AppCacheInfo(
                                bundleID: bundleID ?? containerURL.lastPathComponent,
                                path: containerPath,
                                cacheSize: size
                            )
                            found.append(info)
                        }
                    }
                } catch {
                    print("[Scan] Error enumerating \(basePath): \(error)")
                }
                
                worse_query_release(handle)
            }
            
            found.sort { $0.cacheSize > $1.cacheSize }
            let total = found.reduce(0) { $0 + $1.cacheSize }
            
            DispatchQueue.main.async {
                self.apps = found
                self.totalCacheSize = total
                self.isScanning = false
                self.statusMessage = "Found \(found.count) apps with caches"
                print("[Scan] Done: \(found.count) apps, \(ByteCountFormatter.string(fromByteCount: Int64(total), countStyle: .file))")
            }
        }
    }
    
    // MARK: - Clean
    
    func cleanSelected() {
        guard let group = appGroup else { return }
        let toClean = apps.filter { $0.selected }
        guard !toClean.isEmpty else { return }
        
        isCleaning = true
        freedSpace = 0
        statusMessage = "Cleaning..."
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            let fm = FileManager.default
            var freed: UInt64 = 0
            
            for app in toClean {
                let handle = self.consumeExtension(app.path, group: group)
                if handle < 0 {
                    print("[Clean] Failed to access: \(app.bundleID)")
                    continue
                }
                
                let containerURL = URL(filePath: app.path)
                let cacheDirs = [
                    containerURL.appending(path: "Library/Caches"),
                    containerURL.appending(path: "tmp")
                ]
                
                for cacheDir in cacheDirs {
                    let sizeBefore = self.directorySize(at: cacheDir)
                    if let items = try? fm.contentsOfDirectory(at: cacheDir, includingPropertiesForKeys: nil) {
                        for item in items {
                            try? fm.removeItem(at: item)
                        }
                    }
                    let sizeAfter = self.directorySize(at: cacheDir)
                    if sizeBefore > sizeAfter {
                        freed += (sizeBefore - sizeAfter)
                    }
                }
                
                worse_query_release(handle)
                print("[Clean] \(app.bundleID): freed \(ByteCountFormatter.string(fromByteCount: Int64(freed), countStyle: .file))")
            }
            
            DispatchQueue.main.async {
                self.freedSpace = freed
                self.isCleaning = false
                self.statusMessage = "Freed \(ByteCountFormatter.string(fromByteCount: Int64(freed), countStyle: .file))"
                self.scanCaches()
            }
        }
    }
    
    // MARK: - Helpers
    
    private func consumeExtension(_ path: String, group: String) -> Int64 {
        let isAppGroup = path.contains("/var/mobile/Containers/Shared/AppGroup")
        let isIOS26 = ProcessInfo.processInfo.operatingSystemVersion.majorVersion == 26
        let altFlags = isAppGroup && isIOS26
        
        return worse_query(path, group, altFlags, false)
    }
    
    private func getBundleID(at path: String) -> String? {
        var buf = [CChar](repeating: 0, count: 512)
        let len = getxattr(path, "com.apple.containermanager.identifier", &buf, 511, 0, 0)
        if len > 0 {
            return String(cString: buf)
        }
        return nil
    }
    
    private func directorySize(at url: URL) -> UInt64 {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(
            at: url,
            includingPropertiesForKeys: [.fileSizeKey, .isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else { return 0 }
        
        var total: UInt64 = 0
        for case let fileURL as URL in enumerator {
            guard let values = try? fileURL.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey]),
                  values.isRegularFile == true,
                  let size = values.fileSize else { continue }
            total += UInt64(size)
        }
        return total
    }
}

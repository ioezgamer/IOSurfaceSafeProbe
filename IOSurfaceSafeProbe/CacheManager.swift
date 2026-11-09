//
//  CacheManager.swift
//  IOSurfaceSafeProbe
//
//  Handles scanning and cleaning of app caches via worse_query
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
    
    private let appGroup = "group.com.ioezgamer.iosurfacesafeprobe" // Register this identifier in Apple Developer before signing
    
    private let cachePaths = [
        "/var/mobile/Containers/Data/Application"
    ]
    
    // MARK: - Scan
    
    func scanCaches() {
        isScanning = true
        apps = []
        totalCacheSize = 0
        statusMessage = "Scanning..."
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            var found: [AppCacheInfo] = []
            
            for basePath in self.cachePaths {
                let handle = self.consumeExtension(basePath)
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
                        
                        // Get bundle ID from xattr
                        let bundleID = self.getBundleID(at: containerPath, parentHandle: handle)
                        
                        // Calculate cache size
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
                let handle = self.consumeExtension(app.path)
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
                print("[Clean] Total freed: \(ByteCountFormatter.string(fromByteCount: Int64(freed), countStyle: .file))")
                
                // Rescan
                self.scanCaches()
            }
        }
    }
    
    // MARK: - Helpers
    
    private func consumeExtension(_ path: String) -> Int64 {
        let isAppGroup = path.contains("/var/mobile/Containers/Shared/AppGroup")
        let isIOS26 = ProcessInfo.processInfo.operatingSystemVersion.majorVersion == 26
        let altFlags = isAppGroup && isIOS26
        
        return worse_query(path, appGroup, altFlags, false)
    }
    
    private func getBundleID(at path: String, parentHandle: Int64) -> String? {
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

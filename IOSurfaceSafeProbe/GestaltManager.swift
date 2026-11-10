import Foundation

// MARK: - Tweak Definitions

struct GestaltTweak: Identifiable, Hashable {
    let id: String
    let key: String
    let name: String
    let description: String
    let category: TweakCategory
    let type: TweakType
    let defaultValue: Any?
    let enabledValue: Any?

    enum TweakType {
        case bool
        case int
        case pick([PickOption])
    }

    struct PickOption: Hashable {
        let label: String
        let value: Int
        let detail: String
    }

    static func == (lhs: GestaltTweak, rhs: GestaltTweak) -> Bool { lhs.id == rhs.id }
    func hash(into hasher: inout Hasher) { hasher.combine(id) }
}

enum TweakCategory: String, CaseIterable {
    case display = "Display & UI"
    case hardware = "Buttons & Hardware"
    case features = "Features"
    case connectivity = "Connectivity"
    case advanced = "Advanced"

    var icon: String {
        switch self {
        case .display: return "sparkles.rectangle.stack"
        case .hardware: return "button.horizontal.top.press"
        case .features: return "star.circle"
        case .connectivity: return "wifi"
        case .advanced: return "gearshape.2"
        }
    }
}

// MARK: - Tweak State

struct TweakState: Identifiable {
    let id: String
    var currentValue: Any?
    var originalValue: Any?
    var isModified: Bool
    var tweak: GestaltTweak
}

// MARK: - Manager

class GestaltManager: ObservableObject {
    @Published var tweakStates: [TweakState] = []
    @Published var isLoading = false
    @Published var statusMessage = ""
    @Published var gestaltAccessible = false
    @Published var hasBackup = false
    @Published var modifiedCount = 0
    @Published var deviceModel = ""
    @Published var deviceSubtype = 0
    @Published var grantStatus = ""
    @Published var plistKeyCount = 0
    @Published var lastError = ""

    private let knownPaths = [
        "/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist",
        "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist"
    ]
    private let backupSuffix = ".cachewipe-backup"
    private(set) var plistPath: String?
    private var originalPlistData: Data?

    static let shared = GestaltManager()

    static let allTweaks: [GestaltTweak] = {
        var t = [GestaltTweak]()

        // Display & UI
        t.append(GestaltTweak(
            id: "dynamic_island", key: "ArtworkDeviceSubType",
            name: "Device Subtype (Dynamic Island)",
            description: "Changes device appearance. Pick a model to get its UI features like Dynamic Island.",
            category: .display, type: .pick([
                .init(label: "Default", value: 0, detail: "Keep original"),
                .init(label: "iPhone 14 Pro", value: 2556, detail: "Dynamic Island"),
                .init(label: "iPhone 14 Pro Max", value: 2796, detail: "Dynamic Island"),
                .init(label: "iPhone 15 Pro", value: 2622, detail: "Dynamic Island + Action Button UI"),
                .init(label: "iPhone 15 Pro Max", value: 2868, detail: "Dynamic Island + Action Button UI"),
                .init(label: "iPhone 16 Pro", value: 2766, detail: "All latest features"),
                .init(label: "iPhone 16 Pro Max", value: 2976, detail: "All latest features"),
            ]),
            defaultValue: nil, enabledValue: nil
        ))
        t.append(GestaltTweak(
            id: "aod", key: "oPeik/9e8lQWMszEjbPJng",
            name: "Always On Display",
            description: "Enables the Always On Display feature.",
            category: .display, type: .bool,
            defaultValue: false, enabledValue: true
        ))
        t.append(GestaltTweak(
            id: "promotion", key: "nMFHFySlwVIRkgRPRgJMUA",
            name: "ProMotion 120Hz",
            description: "Enables adaptive 120Hz refresh rate.",
            category: .display, type: .bool,
            defaultValue: false, enabledValue: true
        ))

        // Buttons & Hardware
        t.append(GestaltTweak(
            id: "action_button", key: "j8/Omm6s1lsmTDFsXjsBfA",
            name: "Action Button",
            description: "Enables the customizable Action Button in Settings.",
            category: .hardware, type: .bool,
            defaultValue: false, enabledValue: true
        ))
        t.append(GestaltTweak(
            id: "camera_control", key: "8olRm6C1xqr7APlGPLQaBQ",
            name: "Camera Control",
            description: "Enables the Camera Control button feature.",
            category: .hardware, type: .bool,
            defaultValue: false, enabledValue: true
        ))
        t.append(GestaltTweak(
            id: "boot_chime", key: "qeaj75wk3HF4DwQ8qbIi7g",
            name: "Boot Chime",
            description: "Plays a sound when the device starts up.",
            category: .hardware, type: .bool,
            defaultValue: false, enabledValue: true
        ))
        t.append(GestaltTweak(
            id: "tap_to_wake", key: "IMLaTlxS7ITtwfbRfPYWuA",
            name: "Tap to Wake",
            description: "Wake device by tapping the screen.",
            category: .hardware, type: .bool,
            defaultValue: false, enabledValue: true
        ))
        t.append(GestaltTweak(
            id: "pencil", key: "yhHcB0iH0d1XzPO/CFd3ow",
            name: "Apple Pencil Support",
            description: "Enables Apple Pencil hover and drawing.",
            category: .hardware, type: .bool,
            defaultValue: false, enabledValue: true
        ))

        // Features
        t.append(GestaltTweak(
            id: "apple_intelligence", key: "h9jDsbgj7xIVeIQ8S3/X3Q",
            name: "Apple Intelligence",
            description: "Enables Apple Intelligence AI features.",
            category: .features, type: .bool,
            defaultValue: false, enabledValue: true
        ))
        t.append(GestaltTweak(
            id: "stage_manager", key: "A62OafQ85EJAiiqKn4agtg",
            name: "Stage Manager",
            description: "Enables Stage Manager multitasking.",
            category: .features, type: .bool,
            defaultValue: false, enabledValue: true
        ))
        t.append(GestaltTweak(
            id: "charge_limit", key: "HCzWusHQwZDea6nNhaKndw",
            name: "Charge Limit (80%)",
            description: "Shows the battery charging limit option in Settings.",
            category: .features, type: .bool,
            defaultValue: false, enabledValue: true
        ))
        t.append(GestaltTweak(
            id: "crash_detect", key: "HpRFTVJEOFyB7bYerFAglw",
            name: "Crash Detection",
            description: "Enables automatic crash detection and emergency SOS.",
            category: .features, type: .bool,
            defaultValue: false, enabledValue: true
        ))
        t.append(GestaltTweak(
            id: "internal_storage", key: "cT44WE1EohiwRzhsZ8xEsw",
            name: "Show Internal Storage",
            description: "Shows detailed internal storage info in Settings.",
            category: .features, type: .bool,
            defaultValue: false, enabledValue: true
        ))
        t.append(GestaltTweak(
            id: "parallax", key: "zHeENZu+wbg7PUprwNwBWg",
            name: "Parallax Wallpaper",
            description: "Enables the 3D parallax effect on wallpapers.",
            category: .features, type: .bool,
            defaultValue: false, enabledValue: true
        ))
        t.append(GestaltTweak(
            id: "medusa", key: "qcL5umGIGGq3+HKXC0rkjg",
            name: "Multitasking (Medusa)",
            description: "Enables iPad-style split-view multitasking.",
            category: .features, type: .bool,
            defaultValue: false, enabledValue: true
        ))

        // Connectivity
        t.append(GestaltTweak(
            id: "wifi6e", key: "k4QJ57yYERsHpRuA/y2VYg",
            name: "WiFi 6E",
            description: "Enables WiFi 6E (6 GHz band) support.",
            category: .connectivity, type: .bool,
            defaultValue: false, enabledValue: true
        ))
        t.append(GestaltTweak(
            id: "5g_mmwave", key: "nLbwFJiCMqorlA5s8RVYBQ",
            name: "5G mmWave",
            description: "Enables 5G millimeter wave connectivity.",
            category: .connectivity, type: .bool,
            defaultValue: false, enabledValue: true
        ))
        t.append(GestaltTweak(
            id: "uwb", key: "UmPLhbSig0kGA/8lpSxaCA",
            name: "Ultra Wideband (U1/U2)",
            description: "Enables UWB chip features for Precision Finding.",
            category: .connectivity, type: .bool,
            defaultValue: false, enabledValue: true
        ))
        t.append(GestaltTweak(
            id: "thunderbolt", key: "EqrsVvjcYDdxHBiQmGhAWw",
            name: "USB-C / Thunderbolt",
            description: "Enables Thunderbolt/USB4 data transfer speeds.",
            category: .connectivity, type: .bool,
            defaultValue: false, enabledValue: true
        ))

        // Advanced
        t.append(GestaltTweak(
            id: "metal_hdr", key: "CXB7BWIrE4oHuHIYCwWEJQ",
            name: "Metal HFR (High Frame Rate)",
            description: "Enables Metal high frame rate compositing.",
            category: .advanced, type: .bool,
            defaultValue: false, enabledValue: true
        ))
        t.append(GestaltTweak(
            id: "ringtone_store", key: "nHEEjkuaP0qa7JeDVno+Dg",
            name: "Ringtone Store",
            description: "Enables the Ringtone Store in Settings.",
            category: .advanced, type: .bool,
            defaultValue: false, enabledValue: true
        ))

        return t
    }()

    // MARK: - Load

    func loadGestalt() {
        guard wq_app_group() != nil else {
            statusMessage = "No App Group — install via FlareStore"
            return
        }
        isLoading = true
        statusMessage = "Granting access to MobileGestalt..."
        lastError = ""
        grantStatus = ""

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }

            print("[Gestalt] Starting gestalt load...")

            // Try known paths
            var foundPath: String?
            for path in self.knownPaths {
                let dir = (path as NSString).deletingLastPathComponent
                print("[Gestalt] Trying grant for: \(dir)")
                if wq_grant(dir) {
                    print("[Gestalt] Grant OK for: \(dir)")
                    if FileManager.default.fileExists(atPath: path) {
                        foundPath = path
                        print("[Gestalt] Plist found at: \(path)")
                        break
                    } else {
                        print("[Gestalt] Grant OK but plist not found at: \(path)")
                    }
                } else {
                    print("[Gestalt] Grant FAILED for: \(dir)")
                }
            }

            // Try discovering via Shared SystemGroup containers
            if foundPath == nil {
                print("[Gestalt] Known paths failed, trying discovery...")
                foundPath = self.discoverGestaltPath()
            }

            guard let path = foundPath else {
                let msg = "Cannot access MobileGestalt — grant failed for all paths"
                print("[Gestalt] \(msg)")
                DispatchQueue.main.async {
                    self.statusMessage = msg
                    self.grantStatus = "FAILED"
                    self.lastError = "wq_grant returned false for all MobileGestalt paths. The exploit may not reach SystemGroup containers on this iOS version."
                    self.isLoading = false
                    self.gestaltAccessible = false
                }
                return
            }

            self.plistPath = path
            print("[Gestalt] Using plist: \(path)")

            DispatchQueue.main.async {
                self.grantStatus = "OK"
            }

            // Check backup
            let backupPath = path + self.backupSuffix
            let hasBackup = FileManager.default.fileExists(atPath: backupPath)

            // Read plist as data first (to preserve binary format)
            guard let plistData = FileManager.default.contents(atPath: path) else {
                print("[Gestalt] Cannot read plist data")
                DispatchQueue.main.async {
                    self.statusMessage = "Cannot read MobileGestalt plist"
                    self.lastError = "FileManager.contents returned nil"
                    self.isLoading = false
                }
                return
            }
            self.originalPlistData = plistData
            print("[Gestalt] Plist data: \(plistData.count) bytes")

            // Parse plist
            guard let plist = try? PropertyListSerialization.propertyList(
                from: plistData, options: .mutableContainersAndLeaves, format: nil
            ) as? NSMutableDictionary else {
                print("[Gestalt] Cannot parse plist")
                DispatchQueue.main.async {
                    self.statusMessage = "Cannot parse MobileGestalt plist"
                    self.lastError = "PropertyListSerialization failed"
                    self.isLoading = false
                }
                return
            }

            guard let extra = plist["CacheExtra"] as? NSDictionary else {
                print("[Gestalt] No CacheExtra key")
                DispatchQueue.main.async {
                    self.statusMessage = "MobileGestalt plist has no CacheExtra"
                    self.lastError = "CacheExtra key missing"
                    self.isLoading = false
                }
                return
            }

            let keyCount = extra.count
            print("[Gestalt] CacheExtra has \(keyCount) keys")

            let subtype = extra["ArtworkDeviceSubType"] as? Int ?? 0
            let model = extra["h63QSdBCiT/z0WU6rdQr6Q"] as? String ?? "Unknown"
            print("[Gestalt] Device model: \(model), subtype: \(subtype)")

            var states = [TweakState]()
            for tweak in Self.allTweaks {
                let current = extra[tweak.key]
                let isModified: Bool
                switch tweak.type {
                case .bool:
                    let cur = current as? Bool ?? false
                    let def = tweak.defaultValue as? Bool ?? false
                    isModified = cur != def
                case .int:
                    let cur = current as? Int ?? 0
                    let def = tweak.defaultValue as? Int ?? 0
                    isModified = cur != def
                case .pick:
                    isModified = false
                }
                states.append(TweakState(
                    id: tweak.id,
                    currentValue: current,
                    originalValue: current,
                    isModified: isModified,
                    tweak: tweak
                ))
            }

            DispatchQueue.main.async {
                self.tweakStates = states
                self.gestaltAccessible = true
                self.hasBackup = hasBackup
                self.deviceSubtype = subtype
                self.deviceModel = model
                self.plistKeyCount = keyCount
                self.modifiedCount = states.filter(\.isModified).count
                self.statusMessage = "Loaded \(keyCount) keys from MobileGestalt"
                self.isLoading = false
            }
        }
    }

    // MARK: - Discover path via scanning /var/containers/Shared/SystemGroup

    private func discoverGestaltPath() -> String? {
        let bases = [
            "/var/containers/Shared/SystemGroup",
            "/private/var/containers/Shared/SystemGroup"
        ]
        for base in bases {
            print("[Gestalt] Trying to grant base: \(base)")
            if wq_grant(base) {
                print("[Gestalt] Base grant OK, listing...")
                if let items = try? FileManager.default.contentsOfDirectory(atPath: base) {
                    for item in items {
                        if item.contains("mobilegestalt") {
                            let candidate = "\(base)/\(item)/Library/Caches/com.apple.MobileGestalt.plist"
                            let dir = (candidate as NSString).deletingLastPathComponent
                            print("[Gestalt] Found gestalt dir: \(item), granting \(dir)")
                            if wq_grant(dir) && FileManager.default.fileExists(atPath: candidate) {
                                print("[Gestalt] Discovery found plist: \(candidate)")
                                return candidate
                            }
                        }
                    }
                }
            } else {
                print("[Gestalt] Base grant FAILED for: \(base)")
            }

            // Try granting the specific systemgroup path directly
            let directPath = "\(base)/systemgroup.com.apple.mobilegestaltcache"
            print("[Gestalt] Trying direct: \(directPath)")
            if wq_grant(directPath) {
                let cachesDir = "\(directPath)/Library/Caches"
                if wq_grant(cachesDir) {
                    let plist = "\(cachesDir)/com.apple.MobileGestalt.plist"
                    if FileManager.default.fileExists(atPath: plist) {
                        return plist
                    }
                }
            }
        }
        return nil
    }

    // MARK: - Modify

    func toggleBool(id: String) {
        guard let idx = tweakStates.firstIndex(where: { $0.id == id }) else { return }
        let current = tweakStates[idx].currentValue as? Bool ?? false
        tweakStates[idx].currentValue = !current
        tweakStates[idx].isModified = true
    }

    func setPickValue(id: String, value: Int) {
        guard let idx = tweakStates.firstIndex(where: { $0.id == id }) else { return }
        tweakStates[idx].currentValue = value
        tweakStates[idx].isModified = true
    }

    // MARK: - Apply (binary plist)

    func applyChanges() {
        guard let path = plistPath else {
            statusMessage = "No plist loaded"
            return
        }

        let changed = tweakStates.filter(\.isModified)
        guard !changed.isEmpty else {
            statusMessage = "No changes to apply"
            return
        }

        isLoading = true
        statusMessage = "Applying \(changed.count) changes..."
        lastError = ""

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }

            // Re-grant
            let dir = (path as NSString).deletingLastPathComponent
            guard wq_grant(dir) else {
                print("[Gestalt] Apply: grant failed for \(dir)")
                DispatchQueue.main.async {
                    self.statusMessage = "Grant failed — cannot write"
                    self.lastError = "wq_grant failed during apply"
                    self.isLoading = false
                }
                return
            }

            // Create backup if needed
            let backupPath = path + self.backupSuffix
            if !FileManager.default.fileExists(atPath: backupPath) {
                do {
                    try FileManager.default.copyItem(atPath: path, toPath: backupPath)
                    print("[Gestalt] Backup created: \(backupPath)")
                } catch {
                    print("[Gestalt] Backup failed: \(error)")
                }
            }

            // Read current plist
            guard let plistData = FileManager.default.contents(atPath: path) else {
                print("[Gestalt] Apply: cannot read plist")
                DispatchQueue.main.async {
                    self.statusMessage = "Cannot read plist for modification"
                    self.isLoading = false
                }
                return
            }

            var format = PropertyListSerialization.PropertyListFormat.binary
            guard let plist = try? PropertyListSerialization.propertyList(
                from: plistData, options: .mutableContainersAndLeaves, format: &format
            ) as? NSMutableDictionary else {
                print("[Gestalt] Apply: cannot parse plist")
                DispatchQueue.main.async {
                    self.statusMessage = "Cannot parse plist"
                    self.isLoading = false
                }
                return
            }

            print("[Gestalt] Original format: \(format == .binary ? "binary" : format == .xml ? "XML" : "openStep")")

            guard let extra = plist["CacheExtra"] as? NSMutableDictionary else {
                print("[Gestalt] Apply: no CacheExtra")
                DispatchQueue.main.async {
                    self.statusMessage = "No CacheExtra in plist"
                    self.isLoading = false
                }
                return
            }

            // Apply changes
            for state in changed {
                if let val = state.currentValue {
                    extra[state.tweak.key] = val
                    print("[Gestalt] Set \(state.tweak.key) = \(val)")
                }
            }

            plist["CacheExtra"] = extra

            // Write back as BINARY plist (critical!)
            do {
                let outputData = try PropertyListSerialization.data(
                    fromPropertyList: plist,
                    format: .binary,
                    options: 0
                )
                print("[Gestalt] Serialized \(outputData.count) bytes as binary plist")

                let success = FileManager.default.createFile(atPath: path, contents: outputData, attributes: nil)
                if !success {
                    // Try writing via NSData
                    try (outputData as NSData).write(toFile: path, options: .atomic)
                }
                print("[Gestalt] Write completed")

                // Verify: re-read and check
                if let verifyData = FileManager.default.contents(atPath: path),
                   let verifyDict = try? PropertyListSerialization.propertyList(
                    from: verifyData, options: [], format: nil
                   ) as? [String: Any],
                   let verifyExtra = verifyDict["CacheExtra"] as? [String: Any] {
                    var verified = 0
                    for state in changed {
                        if let written = verifyExtra[state.tweak.key] {
                            print("[Gestalt] Verify \(state.tweak.name): \(written)")
                            verified += 1
                        }
                    }
                    print("[Gestalt] Verified \(verified)/\(changed.count) changes")

                    DispatchQueue.main.async {
                        self.modifiedCount = changed.count
                        self.hasBackup = true
                        self.statusMessage = "Applied \(changed.count) tweaks (\(verified) verified) — REBOOT to take effect"
                        self.isLoading = false
                    }
                } else {
                    DispatchQueue.main.async {
                        self.statusMessage = "Written but verify failed — reboot to check"
                        self.isLoading = false
                    }
                }
            } catch {
                print("[Gestalt] Write error: \(error)")
                DispatchQueue.main.async {
                    self.statusMessage = "Write failed: \(error.localizedDescription)"
                    self.lastError = error.localizedDescription
                    self.isLoading = false
                }
            }
        }
    }

    // MARK: - Restore

    func restoreBackup() {
        guard let path = plistPath else {
            statusMessage = "No plist loaded"
            return
        }

        isLoading = true
        statusMessage = "Restoring backup..."

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }

            let dir = (path as NSString).deletingLastPathComponent
            guard wq_grant(dir) else {
                DispatchQueue.main.async {
                    self.statusMessage = "Grant failed"
                    self.isLoading = false
                }
                return
            }

            let backupPath = path + self.backupSuffix
            guard FileManager.default.fileExists(atPath: backupPath) else {
                DispatchQueue.main.async {
                    self.statusMessage = "No backup found"
                    self.isLoading = false
                }
                return
            }

            do {
                try FileManager.default.removeItem(atPath: path)
                try FileManager.default.copyItem(atPath: backupPath, toPath: path)
                print("[Gestalt] Backup restored")
                DispatchQueue.main.async {
                    self.statusMessage = "Backup restored — REBOOT to take effect"
                    self.isLoading = false
                    self.loadGestalt()
                }
            } catch {
                print("[Gestalt] Restore error: \(error)")
                DispatchQueue.main.async {
                    self.statusMessage = "Restore failed: \(error.localizedDescription)"
                    self.isLoading = false
                }
            }
        }
    }

    // MARK: - Bulk

    func enableAll(in category: TweakCategory) {
        for i in tweakStates.indices {
            guard tweakStates[i].tweak.category == category else { continue }
            switch tweakStates[i].tweak.type {
            case .bool:
                tweakStates[i].currentValue = true
                tweakStates[i].isModified = true
            default: break
            }
        }
    }

    func disableAll(in category: TweakCategory) {
        for i in tweakStates.indices {
            guard tweakStates[i].tweak.category == category else { continue }
            switch tweakStates[i].tweak.type {
            case .bool:
                tweakStates[i].currentValue = false
                tweakStates[i].isModified = true
            default: break
            }
        }
    }
}

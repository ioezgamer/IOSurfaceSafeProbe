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

    private let gestaltPaths = [
        "/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist",
        "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist"
    ]
    private let backupSuffix = ".cachewipe-backup"
    private var plistPath: String?
    private var cacheExtra: NSMutableDictionary?

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
        t.append(GestaltTweak(
            id: "dev_mode", key: "EqrsVvjcYDdxHBiQmGhAWw",
            name: "Developer Mode Extras",
            description: "Shows additional developer options.",
            category: .advanced, type: .bool,
            defaultValue: false, enabledValue: true
        ))

        return t
    }()

    func loadGestalt() {
        guard wq_app_group() != nil else {
            statusMessage = "No App Group — install via FlareStore"
            return
        }
        isLoading = true
        statusMessage = "Granting access to MobileGestalt..."

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }

            var foundPath: String?
            for path in self.gestaltPaths {
                let dir = (path as NSString).deletingLastPathComponent
                if wq_grant(dir) {
                    foundPath = path
                    break
                }
            }

            guard let path = foundPath else {
                DispatchQueue.main.async {
                    self.statusMessage = "Cannot access MobileGestalt cache"
                    self.isLoading = false
                    self.gestaltAccessible = false
                }
                return
            }

            self.plistPath = path

            let backupPath = path + self.backupSuffix
            let hasBackup = FileManager.default.fileExists(atPath: backupPath)

            guard let dict = NSDictionary(contentsOfFile: path) as? [String: Any],
                  let extra = dict["CacheExtra"] as? [String: Any] else {
                DispatchQueue.main.async {
                    self.statusMessage = "Cannot read MobileGestalt plist"
                    self.isLoading = false
                }
                return
            }

            let mutableExtra = NSMutableDictionary(dictionary: extra)
            self.cacheExtra = mutableExtra

            let subtype = extra["ArtworkDeviceSubType"] as? Int ?? 0
            let model = extra["h63QSdBCiT/z0WU6rdQr6Q"] as? String ?? "Unknown"

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
                    isModified = current != nil && (current as? Int ?? 0) != 0
                }
                states.append(TweakState(
                    id: tweak.id,
                    currentValue: current,
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
                self.modifiedCount = states.filter(\.isModified).count
                self.statusMessage = "Loaded \(extra.count) keys"
                self.isLoading = false
            }
        }
    }

    func toggleBool(id: String) {
        guard let idx = tweakStates.firstIndex(where: { $0.id == id }) else { return }
        let state = tweakStates[idx]
        let current = state.currentValue as? Bool ?? false
        tweakStates[idx].currentValue = !current
        tweakStates[idx].isModified = true
    }

    func setPickValue(id: String, value: Int) {
        guard let idx = tweakStates.firstIndex(where: { $0.id == id }) else { return }
        tweakStates[idx].currentValue = value
        tweakStates[idx].isModified = true
    }

    func applyChanges() {
        guard let path = plistPath, let extra = cacheExtra else {
            statusMessage = "No plist loaded"
            return
        }

        isLoading = true
        statusMessage = "Applying changes..."

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }

            let dir = (path as NSString).deletingLastPathComponent
            guard wq_grant(dir) else {
                DispatchQueue.main.async {
                    self.statusMessage = "Grant failed — cannot write"
                    self.isLoading = false
                }
                return
            }

            let backupPath = path + self.backupSuffix
            if !FileManager.default.fileExists(atPath: backupPath) {
                try? FileManager.default.copyItem(atPath: path, toPath: backupPath)
            }

            for state in self.tweakStates where state.isModified {
                if let val = state.currentValue {
                    extra[state.tweak.key] = val
                }
            }

            guard let fullDict = NSDictionary(contentsOfFile: path) as? [String: Any] else {
                DispatchQueue.main.async {
                    self.statusMessage = "Re-read failed"
                    self.isLoading = false
                }
                return
            }

            let mutable = NSMutableDictionary(dictionary: fullDict)
            mutable["CacheExtra"] = extra

            let success = mutable.write(toFile: path, atomically: true)

            DispatchQueue.main.async {
                if success {
                    let count = self.tweakStates.filter(\.isModified).count
                    self.modifiedCount = count
                    self.hasBackup = true
                    self.statusMessage = "Applied \(count) tweaks — reboot to take effect"
                } else {
                    self.statusMessage = "Write failed — check permissions"
                }
                self.isLoading = false
            }
        }
    }

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
                DispatchQueue.main.async {
                    self.statusMessage = "Backup restored — reboot to take effect"
                    self.isLoading = false
                    self.loadGestalt()
                }
            } catch {
                DispatchQueue.main.async {
                    self.statusMessage = "Restore failed: \(error.localizedDescription)"
                    self.isLoading = false
                }
            }
        }
    }

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

import Foundation
import Darwin

// MARK: - GreenTea / NotGreenTea master flags (CacheData gate keys)

private let kGreenTeaKey  = "iyfxmLogGVIaH7aEgqwcIA"   // must be FALSE (0) to enable overrides
private let kNotGreenTeaKey = "4snMZS8LJkSctKypt2m+xA"  // must be TRUE  (1) to enable overrides

// MARK: - Tweak Definitions

struct GestaltTweak: Identifiable, Hashable {
    let id: String
    let key: String          // MobileGestalt key hash (used for both CacheExtra and CacheData)
    let name: String
    let description: String
    let category: TweakCategory
    let type: TweakType
    let defaultValue: Any?
    let enabledValue: Any?
    var extraKey: String?    // Alternate CacheExtra key (e.g. "ArtworkDeviceSubType")

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
    @Published var hasCacheData = false
    @Published var eligibilityStatus = ""
    @Published var isImmutable = false
    @Published var cacheDataPatchInfo = ""

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
            id: "dynamic_island", key: "oPeik/9e8lQWMszEjbPzng",
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
            defaultValue: nil, enabledValue: nil,
            extraKey: "ArtworkDeviceSubType"
        ))
        t.append(GestaltTweak(
            id: "aod", key: "2OOJf1VhaM7NxfRok3HbWQ",
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
            id: "action_button", key: "cT44WE1EohiwRzhsZ8xEsw",
            name: "Action Button",
            description: "Enables the customizable Action Button in Settings.",
            category: .hardware, type: .bool,
            defaultValue: false, enabledValue: true
        ))
        t.append(GestaltTweak(
            id: "camera_control", key: "CwvKxM2cEogD3p+HYgaW0Q",
            name: "Camera Control",
            description: "Enables the Camera Control button feature.",
            category: .hardware, type: .bool,
            defaultValue: false, enabledValue: true
        ))
        t.append(GestaltTweak(
            id: "boot_chime", key: "QHxt+hGLaBPbQJbXiUJX3w",
            name: "Boot Chime",
            description: "Plays a sound when the device starts up.",
            category: .hardware, type: .bool,
            defaultValue: false, enabledValue: true
        ))
        t.append(GestaltTweak(
            id: "tap_to_wake", key: "yZf3GTRMGTuwSV/lD7Cagw",
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
            id: "apple_intelligence", key: "A62OafQ85EJAiiqKn4agtg",
            name: "Apple Intelligence",
            description: "Enables Apple Intelligence AI features.",
            category: .features, type: .bool,
            defaultValue: false, enabledValue: true
        ))
        t.append(GestaltTweak(
            id: "stage_manager", key: "qeaj75wk3HF4DwQ8qbIi7g",
            name: "Stage Manager",
            description: "Enables Stage Manager multitasking.",
            category: .features, type: .bool,
            defaultValue: false, enabledValue: true
        ))
        t.append(GestaltTweak(
            id: "charge_limit", key: "37NVydb//GP/GrhuTN+exg",
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
            id: "internal_storage", key: "LBJfwOEzExRxzlAnSuI7eg",
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
            statusMessage = "No App Group container — install via FlareStore (needs group.1669a1048b00156e.X)"
            return
        }
        isLoading = true
        statusMessage = "Granting access to MobileGestalt..."
        lastError = ""
        grantStatus = ""

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }

            print("[Gestalt] Starting gestalt load...")

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
                    }
                }
            }

            if foundPath == nil {
                print("[Gestalt] Known paths failed, trying discovery...")
                foundPath = self.discoverGestaltPath()
            }

            guard let path = foundPath else {
                DispatchQueue.main.async {
                    self.statusMessage = "Cannot access MobileGestalt"
                    self.grantStatus = "FAILED"
                    self.lastError = "wq_grant failed for all paths"
                    self.isLoading = false
                    self.gestaltAccessible = false
                }
                return
            }

            self.plistPath = path
            DispatchQueue.main.async { self.grantStatus = "OK" }

            let backupPath = path + self.backupSuffix
            let hasBackup = FileManager.default.fileExists(atPath: backupPath)

            guard let plistData = FileManager.default.contents(atPath: path) else {
                DispatchQueue.main.async {
                    self.statusMessage = "Cannot read plist"
                    self.isLoading = false
                }
                return
            }
            self.originalPlistData = plistData
            print("[Gestalt] Plist data: \(plistData.count) bytes")

            guard let plist = try? PropertyListSerialization.propertyList(
                from: plistData, options: .mutableContainersAndLeaves, format: nil
            ) as? NSMutableDictionary else {
                DispatchQueue.main.async {
                    self.statusMessage = "Cannot parse plist"
                    self.isLoading = false
                }
                return
            }

            guard let extra = plist["CacheExtra"] as? NSDictionary else {
                DispatchQueue.main.async {
                    self.statusMessage = "No CacheExtra in plist"
                    self.isLoading = false
                }
                return
            }

            let cacheDataPresent = plist["CacheData"] != nil

            let keyCount = extra.count
            let subtype = (extra["ArtworkDeviceSubType"] ?? extra["oPeik/9e8lQWMszEjbPzng"]) as? Int ?? 0
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
                    isModified = false
                }
                states.append(TweakState(
                    id: tweak.id, currentValue: current,
                    originalValue: current, isModified: isModified, tweak: tweak
                ))
            }

            var fileStat = stat()
            let immutable = stat(path, &fileStat) == 0 && (fileStat.st_flags & UInt32(UF_IMMUTABLE)) != 0

            DispatchQueue.main.async {
                self.tweakStates = states
                self.gestaltAccessible = true
                self.hasBackup = hasBackup
                self.hasCacheData = cacheDataPresent
                self.isImmutable = immutable
                self.deviceSubtype = subtype
                self.deviceModel = model
                self.plistKeyCount = keyCount
                self.modifiedCount = states.filter(\.isModified).count
                self.statusMessage = "Loaded \(keyCount) keys"
                self.isLoading = false
            }
        }
    }

    // MARK: - Discover path

    private func discoverGestaltPath() -> String? {
        let bases = [
            "/var/containers/Shared/SystemGroup",
            "/private/var/containers/Shared/SystemGroup"
        ]
        for base in bases {
            if wq_grant(base) {
                if let items = try? FileManager.default.contentsOfDirectory(atPath: base) {
                    for item in items where item.contains("mobilegestalt") {
                        let candidate = "\(base)/\(item)/Library/Caches/com.apple.MobileGestalt.plist"
                        let dir = (candidate as NSString).deletingLastPathComponent
                        if wq_grant(dir) && FileManager.default.fileExists(atPath: candidate) {
                            return candidate
                        }
                    }
                }
            }

            let directPath = "\(base)/systemgroup.com.apple.mobilegestaltcache"
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

    // MARK: - Apply

    func applyChanges() { writeGestalt(forceAll: false) }
    func forceRewrite() { writeGestalt(forceAll: true) }

    private func writeGestalt(forceAll: Bool) {
        guard let path = plistPath else {
            statusMessage = "No plist loaded"
            return
        }

        let toWrite: [TweakState]
        if forceAll {
            toWrite = tweakStates.filter { state in
                switch state.tweak.type {
                case .bool: return (state.currentValue as? Bool) == true
                case .pick: return (state.currentValue as? Int ?? 0) != 0
                case .int: return state.currentValue != nil
                }
            }
        } else {
            toWrite = tweakStates.filter(\.isModified)
        }

        if toWrite.isEmpty && !forceAll {
            statusMessage = "No changes to apply"
            return
        }

        isLoading = true
        statusMessage = forceAll ? "Force rewriting..." : "Applying \(toWrite.count) tweaks..."
        lastError = ""

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }

            let dir = (path as NSString).deletingLastPathComponent
            guard wq_grant(dir) else {
                DispatchQueue.main.async {
                    self.statusMessage = "Grant failed"
                    self.lastError = "wq_grant failed during apply"
                    self.isLoading = false
                }
                return
            }

            // Backup
            let backupPath = path + self.backupSuffix
            if !FileManager.default.fileExists(atPath: backupPath) {
                try? FileManager.default.copyItem(atPath: path, toPath: backupPath)
            }

            guard let plistData = FileManager.default.contents(atPath: path) else {
                DispatchQueue.main.async {
                    self.statusMessage = "Cannot read plist"
                    self.isLoading = false
                }
                return
            }

            var format = PropertyListSerialization.PropertyListFormat.binary
            guard let plist = try? PropertyListSerialization.propertyList(
                from: plistData, options: .mutableContainersAndLeaves, format: &format
            ) as? NSMutableDictionary else {
                DispatchQueue.main.async {
                    self.statusMessage = "Cannot parse plist"
                    self.isLoading = false
                }
                return
            }

            guard let extra = plist["CacheExtra"] as? NSMutableDictionary else {
                DispatchQueue.main.async {
                    self.statusMessage = "No CacheExtra"
                    self.isLoading = false
                }
                return
            }

            // Step 1: Write all enabled tweaks to CacheExtra (backward compat)
            var writeCount = 0
            for state in toWrite {
                if let val = state.currentValue {
                    extra[state.tweak.key] = val
                    if let alt = state.tweak.extraKey {
                        extra[alt] = val
                    }
                    writeCount += 1
                }
            }
            if forceAll {
                for state in self.tweakStates {
                    if case .bool = state.tweak.type, (state.currentValue as? Bool) == false {
                        extra[state.tweak.key] = false
                    }
                }
            }
            plist["CacheExtra"] = extra

            // Step 2: Patch gate flags in CacheData (greenTea=false, notGreenTea=true)
            // This tells iOS to trust CacheExtra values instead of querying the daemon.
            var cdStatus = "Not present"
            if var cacheData = plist["CacheData"] as? Data {
                let result = self.patchGateFlags(&cacheData)
                cdStatus = result
                plist["CacheData"] = cacheData
                print("[gestalt] CacheData gate flags: \(cdStatus)")
            }

            // Step 3: Write the plist
            do {
                let outputData = try PropertyListSerialization.data(
                    fromPropertyList: plist, format: .binary, options: 0
                )

                chflags(path, 0)
                try (outputData as NSData).write(toFile: path, options: .atomic)

                let immRet = chflags(path, UInt32(UF_IMMUTABLE))
                let immOk = immRet == 0
                DispatchQueue.main.async { self.isImmutable = immOk }

                // Verify
                var verified = 0
                if let verifyData = FileManager.default.contents(atPath: path),
                   let verifyDict = try? PropertyListSerialization.propertyList(
                    from: verifyData, options: [], format: nil
                   ) as? [String: Any],
                   let verifyExtra = verifyDict["CacheExtra"] as? [String: Any] {
                    for state in toWrite {
                        if verifyExtra[state.tweak.key] != nil { verified += 1 }
                    }
                }

                DispatchQueue.main.async {
                    self.modifiedCount = writeCount
                    self.hasBackup = true
                    self.hasCacheData = plist["CacheData"] != nil
                    self.cacheDataPatchInfo = cdStatus
                    self.statusMessage = "CacheExtra: \(writeCount) (\(verified) ok). Gates: \(cdStatus). REBOOT required."
                    self.isLoading = false
                }
            } catch {
                DispatchQueue.main.async {
                    self.statusMessage = "Write failed: \(error.localizedDescription)"
                    self.lastError = error.localizedDescription
                    self.isLoading = false
                }
            }
        }
    }

    // MARK: - CacheData Gate Flag Patching
    //
    // CacheData layout: N slots × 9 bytes
    //   Bytes [0 ..< N*8]:       value slots (8 bytes LE each)
    //   Bytes [N*8 ..< N*8+N]:   validity bytes (1 = trust cached value)
    //
    // Only the two gate flags need patching here; all tweak values go in CacheExtra.
    //   greenTea    = false (0) → enables cache overrides
    //   notGreenTea = true  (1) → confirms cache overrides enabled

    private func patchGateFlags(_ data: inout Data) -> String {
        let size = data.count
        guard size >= 9 && size % 9 == 0 else {
            return "size \(size) not valid (need multiple of 9)"
        }
        let slotCount = size / 9

        var patched = 0
        var log = ""

        func patchSlot(key: String, label: String, value: UInt64) {
            let idx = Int(mg_cache_index(key))
            guard idx >= 0 && idx < slotCount else {
                log += "\(label): not found (\(idx)) "
                return
            }
            let valueOff = idx * 8
            let validOff = slotCount * 8 + idx
            data.replaceSubrange(valueOff ..< valueOff + 8,
                                 with: withUnsafeBytes(of: value.littleEndian) { Data($0) })
            data[validOff] = 1
            log += "\(label)=\(value)@\(idx) "
            patched += 1
        }

        patchSlot(key: kGreenTeaKey,    label: "greenTea",    value: 0)
        patchSlot(key: kNotGreenTeaKey, label: "notGreenTea", value: 1)

        return patched > 0 ? "OK (\(log.trimmingCharacters(in: .whitespaces)))" : "FAIL: \(log)"
    }

    // MARK: - Respring

    func respring() {
        let path = "/usr/bin/killall"
        var pid: pid_t = 0
        var argv: [UnsafeMutablePointer<CChar>?] = [
            strdup(path), strdup("SpringBoard"), nil
        ]
        let ret = posix_spawn(&pid, path, nil, nil, &argv, nil)
        argv.compactMap { $0 }.forEach { free($0) }
        if ret == 0 {
            statusMessage = "Respring sent"
        } else {
            statusMessage = "Respring failed (code \(ret)) — reboot manually"
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
                chflags(path, 0)
                try FileManager.default.removeItem(atPath: path)
                try FileManager.default.copyItem(atPath: backupPath, toPath: path)
                DispatchQueue.main.async {
                    self.statusMessage = "Backup restored — REBOOT to take effect"
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

    // MARK: - Bulk

    func enableAll(in category: TweakCategory) {
        for i in tweakStates.indices {
            guard tweakStates[i].tweak.category == category else { continue }
            if case .bool = tweakStates[i].tweak.type {
                tweakStates[i].currentValue = true
                tweakStates[i].isModified = true
            }
        }
    }

    func disableAll(in category: TweakCategory) {
        for i in tweakStates.indices {
            guard tweakStates[i].tweak.category == category else { continue }
            if case .bool = tweakStates[i].tweak.type {
                tweakStates[i].currentValue = false
                tweakStates[i].isModified = true
            }
        }
    }

    // MARK: - Eligibility

    func writeEligibility() {
        isLoading = true
        statusMessage = "Searching for eligibility container..."
        eligibilityStatus = ""

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }

            let eligibility: [String: Any] = [
                "OS_ELIGIBILITY_DOMAIN_GREYMATTER": [
                    "os_eligibility_answer_source_t": 3,
                    "os_eligibility_answer_t": 4,
                    "context": [
                        "OS_ELIGIBILITY_CONTEXT_ELIGIBLE_DEVICE_LANGUAGES": ["en"]
                    ],
                    "status": [
                        "OS_ELIGIBILITY_INPUT_DEVICE_LANGUAGE": 3,
                        "OS_ELIGIBILITY_INPUT_DEVICE_REGION_CODE": 3,
                        "OS_ELIGIBILITY_INPUT_EXTERNAL_BOOT_DRIVE": 3,
                        "OS_ELIGIBILITY_INPUT_GENERATIVE_MODEL_SYSTEM": 3,
                        "OS_ELIGIBILITY_INPUT_SHARED_IPAD": 3,
                        "OS_ELIGIBILITY_INPUT_SIRI_LANGUAGE": 3
                    ]
                ],
                "OS_ELIGIBILITY_DOMAIN_CALCIUM": [
                    "os_eligibility_answer_source_t": 3,
                    "os_eligibility_answer_t": 2,
                    "status": [
                        "OS_ELIGIBILITY_INPUT_CHINA_CELLULAR": 2
                    ]
                ]
            ]

            var wrote = false
            let bases = [
                "/var/containers/Shared/SystemGroup",
                "/private/var/containers/Shared/SystemGroup"
            ]

            for base in bases {
                if !wq_grant(base) { continue }
                guard let items = try? FileManager.default.contentsOfDirectory(atPath: base) else { continue }

                for item in items where item.lowercased().contains("eligib") {
                    let containerPath = "\(base)/\(item)"
                    let candidates = [
                        "\(containerPath)/Library/Caches/eligibility.plist",
                        "\(containerPath)/Library/eligibility.plist",
                        "\(containerPath)/eligibility.plist"
                    ]

                    for candidate in candidates {
                        let dir = (candidate as NSString).deletingLastPathComponent
                        guard wq_grant(dir) else { continue }
                        do {
                            if !FileManager.default.fileExists(atPath: dir) {
                                try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
                            }
                            let data = try PropertyListSerialization.data(
                                fromPropertyList: eligibility, format: .binary, options: 0
                            )
                            try (data as NSData).write(toFile: candidate, options: .atomic)
                            wrote = true
                            DispatchQueue.main.async { self.eligibilityStatus = "OK" }
                            break
                        } catch {}
                    }
                    if wrote { break }
                }
                if wrote { break }
            }

            DispatchQueue.main.async {
                if wrote {
                    self.statusMessage = "Eligibility written — REBOOT required"
                } else {
                    self.statusMessage = "Eligibility: no accessible path"
                    self.eligibilityStatus = "N/A"
                    self.lastError = "eligibilityd not in SystemGroup container"
                }
                self.isLoading = false
            }
        }
    }

    // MARK: - Immutable Flag

    func checkImmutable() {
        guard let path = plistPath else { return }
        var st = stat()
        if stat(path, &st) == 0 {
            isImmutable = (st.st_flags & UInt32(UF_IMMUTABLE)) != 0
        }
    }

    func setImmutable() {
        guard let path = plistPath else { return }
        isLoading = true

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

            let ret = chflags(path, UInt32(UF_IMMUTABLE))
            DispatchQueue.main.async {
                if ret == 0 {
                    self.isImmutable = true
                    self.statusMessage = "Plist locked (immutable)"
                } else {
                    let err = String(cString: strerror(errno))
                    self.statusMessage = "chflags failed: \(err)"
                    self.lastError = "errno \(errno): \(err)"
                }
                self.isLoading = false
            }
        }
    }

    func clearImmutable() {
        guard let path = plistPath else { return }
        let dir = (path as NSString).deletingLastPathComponent
        guard wq_grant(dir) else { return }
        if chflags(path, 0) == 0 {
            isImmutable = false
            statusMessage = "Immutable flag cleared"
        }
    }
}

import Foundation
import Darwin

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

// MARK: - Binary Plist In-Place Patcher

struct BPlistPatcher {
    private var bytes: [UInt8]
    private let objectCount: Int
    private let offsetTableOffset: Int
    private let offsetSize: Int
    private let objectRefSize: Int
    private var objectOffsets: [Int]

    init?(data: Data) {
        guard data.count >= 40 else { return nil }
        let arr = Array(data)
        guard arr[0] == 0x62 && arr[1] == 0x70 && arr[2] == 0x6C && arr[3] == 0x69 &&
              arr[4] == 0x73 && arr[5] == 0x74 && arr[6] == 0x30 && arr[7] == 0x30 else {
            return nil // Not "bplist00"
        }
        self.bytes = arr
        let trailerStart = arr.count - 32
        self.offsetSize = Int(arr[trailerStart + 6])
        self.objectRefSize = Int(arr[trailerStart + 7])
        self.objectCount = BPlistPatcher.readBigEndian(arr, offset: trailerStart + 8, size: 8)
        self.offsetTableOffset = BPlistPatcher.readBigEndian(arr, offset: trailerStart + 24, size: 8)

        var offsets = [Int]()
        for i in 0..<self.objectCount {
            let off = BPlistPatcher.readBigEndian(arr, offset: self.offsetTableOffset + i * self.offsetSize, size: self.offsetSize)
            offsets.append(off)
        }
        self.objectOffsets = offsets
    }

    static func readBigEndian(_ data: [UInt8], offset: Int, size: Int) -> Int {
        var val = 0
        for i in 0..<size {
            val = (val << 8) | Int(data[offset + i])
        }
        return val
    }

    func readRef(_ offset: Int) -> Int {
        BPlistPatcher.readBigEndian(bytes, offset: offset, size: objectRefSize)
    }

    enum BPObject {
        case null
        case bool(Bool)
        case int(Int64)
        case real(Double)
        case string(String)
        case data(Data)
        case array([Int])
        case dict(keys: [Int], values: [Int])
        case uid(Int)
        case unknown
    }

    func objectAt(_ index: Int) -> BPObject {
        guard index < objectCount else { return .unknown }
        let off = objectOffsets[index]
        return parseObject(at: off)
    }

    func parseObject(at off: Int) -> BPObject {
        guard off < bytes.count else { return .unknown }
        let marker = bytes[off]
        let hi = marker >> 4
        let lo = marker & 0x0F

        switch hi {
        case 0x0:
            if marker == 0x08 { return .bool(false) }
            if marker == 0x09 { return .bool(true) }
            if marker == 0x00 { return .null }
            return .unknown
        case 0x1: // int
            let byteCount = 1 << Int(lo)
            var val: Int64 = 0
            for i in 0..<byteCount {
                val = (val << 8) | Int64(bytes[off + 1 + i])
            }
            return .int(val)
        case 0x2: // real
            return .unknown
        case 0x4: // data
            let (count, dataStart) = readCountAndStart(off: off, lo: lo)
            let d = Data(bytes[dataStart..<(dataStart + count)])
            return .data(d)
        case 0x5: // ASCII string
            let (count, strStart) = readCountAndStart(off: off, lo: lo)
            if let s = String(bytes: bytes[strStart..<(strStart + count)], encoding: .ascii) {
                return .string(s)
            }
            return .unknown
        case 0x6: // Unicode string
            let (count, strStart) = readCountAndStart(off: off, lo: lo)
            var chars = [UInt16]()
            for i in 0..<count {
                let c = UInt16(bytes[strStart + i*2]) << 8 | UInt16(bytes[strStart + i*2 + 1])
                chars.append(c)
            }
            if let s = String(utf16CodeUnits: chars, count: count) as String? {
                return .string(s)
            }
            return .unknown
        case 0x8: // uid
            let n = Int(lo) + 1
            var val = 0
            for i in 0..<n { val = (val << 8) | Int(bytes[off + 1 + i]) }
            return .uid(val)
        case 0xA: // array
            let (count, refsStart) = readCountAndStart(off: off, lo: lo)
            var refs = [Int]()
            for i in 0..<count {
                refs.append(readRef(refsStart + i * objectRefSize))
            }
            return .array(refs)
        case 0xD: // dict
            let (count, refsStart) = readCountAndStart(off: off, lo: lo)
            var keys = [Int]()
            var vals = [Int]()
            for i in 0..<count {
                keys.append(readRef(refsStart + i * objectRefSize))
            }
            for i in 0..<count {
                vals.append(readRef(refsStart + count * objectRefSize + i * objectRefSize))
            }
            return .dict(keys: keys, values: vals)
        default:
            return .unknown
        }
    }

    private func readCountAndStart(off: Int, lo: UInt8) -> (Int, Int) {
        if lo != 0x0F {
            return (Int(lo), off + 1)
        }
        let intMarker = bytes[off + 1]
        let intLen = 1 << Int(intMarker & 0x0F)
        var count = 0
        for i in 0..<intLen {
            count = (count << 8) | Int(bytes[off + 2 + i])
        }
        return (count, off + 2 + intLen)
    }

    func stringAt(_ index: Int) -> String? {
        if case .string(let s) = objectAt(index) { return s }
        return nil
    }

    // Find the object index for a given string
    func findStringIndex(_ target: String) -> Int? {
        for i in 0..<objectCount {
            if stringAt(i) == target { return i }
        }
        return nil
    }

    // Find all dictionaries and their key-value mappings
    func findDicts() -> [(index: Int, keys: [Int], values: [Int])] {
        var result = [(index: Int, keys: [Int], values: [Int])]()
        for i in 0..<objectCount {
            if case .dict(let keys, let values) = objectAt(i) {
                result.append((i, keys, values))
            }
        }
        return result
    }

    // Patch a boolean value at a given object index: false(0x08) ↔ true(0x09)
    mutating func patchBool(objectIndex: Int, value: Bool) -> Bool {
        guard objectIndex < objectCount else { return false }
        let off = objectOffsets[objectIndex]
        let current = bytes[off]
        if current == 0x08 || current == 0x09 {
            bytes[off] = value ? 0x09 : 0x08
            return true
        }
        return false
    }

    // Patch an integer value at a given object index (only if same byte-size)
    mutating func patchInt(objectIndex: Int, value: Int64) -> Bool {
        guard objectIndex < objectCount else { return false }
        let off = objectOffsets[objectIndex]
        let marker = bytes[off]
        guard marker >> 4 == 0x1 else { return false }
        let byteCount = 1 << Int(marker & 0x0F)
        var v = value
        for i in stride(from: byteCount - 1, through: 0, by: -1) {
            bytes[off + 1 + i] = UInt8(v & 0xFF)
            v >>= 8
        }
        return true
    }

    func toData() -> Data {
        Data(bytes)
    }
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

            // Analyze CacheData structure
            var cacheDataInfo = ""
            if let cdBlob = plist["CacheData"] as? Data {
                cacheDataInfo = self.analyzeCacheData(cdBlob)
            }

            let keyCount = extra.count
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
                self.cacheDataPatchInfo = cacheDataInfo
                self.statusMessage = "Loaded \(keyCount) keys"
                self.isLoading = false
            }
        }
    }

    // MARK: - Analyze CacheData structure

    private func analyzeCacheData(_ data: Data) -> String {
        guard let patcher = BPlistPatcher(data: data) else {
            return "Not binary plist (\(data.prefix(8).map { String(format: "%02x", $0) }.joined()))"
        }

        var keyCount = 0
        var tweakKeysFound = 0
        let tweakKeys = Set(Self.allTweaks.map(\.key))

        let dicts = patcher.findDicts()
        for d in dicts {
            for ki in d.keys {
                if let s = patcher.stringAt(ki) {
                    keyCount += 1
                    if tweakKeys.contains(s) { tweakKeysFound += 1 }
                }
            }
        }

        return "\(data.count)B, \(dicts.count) dicts, \(keyCount) string keys, \(tweakKeysFound) tweak keys found"
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

            // Step 1: Write all enabled tweaks to CacheExtra
            var writeCount = 0
            for state in toWrite {
                if let val = state.currentValue {
                    extra[state.tweak.key] = val
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

            // Step 2: Patch CacheData in-place (raw byte patching, preserves option flags)
            var cachePatched = 0
            var cacheDataStatus = "No CacheData"
            if let cacheBlob = plist["CacheData"] as? Data {
                let result = self.patchCacheDataInPlace(
                    cacheBlob, tweaks: toWrite, forceAll: forceAll
                )
                cachePatched = result.patched
                cacheDataStatus = result.status
                if let newBlob = result.data {
                    plist["CacheData"] = newBlob
                }
                print("[Gestalt] CacheData patch: \(cacheDataStatus)")
            }

            // Step 3: Write the plist
            do {
                let outputData = try PropertyListSerialization.data(
                    fromPropertyList: plist, format: .binary, options: 0
                )

                chflags(path, 0) // Clear immutable
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
                    self.cacheDataPatchInfo = cacheDataStatus
                    self.statusMessage = "Wrote \(writeCount) tweaks (\(verified) verified). CacheData: \(cachePatched) patched. REBOOT required."
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

    // MARK: - CacheData In-Place Patching

    private struct PatchResult {
        let data: Data?
        let patched: Int
        let status: String
    }

    private func patchCacheDataInPlace(
        _ blob: Data, tweaks: [TweakState], forceAll: Bool
    ) -> PatchResult {
        guard var patcher = BPlistPatcher(data: blob) else {
            return PatchResult(data: nil, patched: 0, status: "Not bplist00")
        }

        let dicts = patcher.findDicts()
        if dicts.isEmpty {
            return PatchResult(data: nil, patched: 0, status: "No dicts found")
        }

        // Build a map of key-string → (dictIndex, valueObjectIndex) for ALL dicts
        var keyToValue = [String: (dictIdx: Int, valObjIdx: Int)]()
        for d in dicts {
            for (i, ki) in d.keys.enumerated() {
                if let s = patcher.stringAt(ki), i < d.values.count {
                    keyToValue[s] = (d.index, d.values[i])
                }
            }
        }

        var patched = 0
        var notFound = [String]()

        // Patch boolean tweaks
        let allStates = forceAll ? tweakStates : []
        let tweaksToPatch = tweaks + allStates.filter { s in
            if case .bool = s.tweak.type, (s.currentValue as? Bool) == false {
                return !tweaks.contains(where: { $0.id == s.id })
            }
            return false
        }

        for state in tweaksToPatch {
            guard let entry = keyToValue[state.tweak.key] else {
                notFound.append(state.tweak.key)
                continue
            }

            switch state.tweak.type {
            case .bool:
                let val = state.currentValue as? Bool ?? false
                if patcher.patchBool(objectIndex: entry.valObjIdx, value: val) {
                    print("[Gestalt] CacheData patched \(state.tweak.key) = \(val)")
                    patched += 1
                } else {
                    print("[Gestalt] CacheData: \(state.tweak.key) not a bool object")
                }
            case .int:
                if let val = state.currentValue as? Int {
                    if patcher.patchInt(objectIndex: entry.valObjIdx, value: Int64(val)) {
                        print("[Gestalt] CacheData patched \(state.tweak.key) = \(val)")
                        patched += 1
                    }
                }
            case .pick:
                if let val = state.currentValue as? Int, val != 0 {
                    if patcher.patchInt(objectIndex: entry.valObjIdx, value: Int64(val)) {
                        print("[Gestalt] CacheData patched \(state.tweak.key) = \(val)")
                        patched += 1
                    }
                }
            }
        }

        let status = "\(patched) patched, \(notFound.count) not in CacheData"
        return PatchResult(data: patcher.toData(), patched: patched, status: status)
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

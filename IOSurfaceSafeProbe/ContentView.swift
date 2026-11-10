import SwiftUI

struct ContentView: View {
    @StateObject private var cache = CacheManager()
    @StateObject private var console = Console()
    @State private var showLog = false
    @State private var searchText = ""
    @State private var sortOption: SortOption = .sizeDesc
    @State private var showCleanConfirm = false
    @State private var selectedApp: AppCacheInfo? = nil
    @State private var showSortMenu = false
    @State private var didInit = false

    private var filteredApps: [AppCacheInfo] {
        cache.sortedApps(by: sortOption, search: searchText)
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 20) {
                    headerCard
                    if !cache.apps.isEmpty {
                        actionBar
                        statsRow
                        searchAndSort
                        appList
                    } else if !cache.isScanning {
                        scanPrompt
                    }
                    logSection
                }
                .padding(.horizontal)
                .padding(.bottom, 30)
            }
            .background(Color(.systemGroupedBackground))
            .navigationTitle("CacheWipe")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button { cache.selectAll() } label: {
                            Label("Select All", systemImage: "checkmark.circle")
                        }
                        Button { cache.deselectAll() } label: {
                            Label("Deselect All", systemImage: "circle")
                        }
                        Divider()
                        Button { cache.selectByCategory(.large) } label: {
                            Label("Select Large Only", systemImage: "arrow.up.circle")
                        }
                        Button { cache.selectByCategory(.medium) } label: {
                            Label("Select Medium Only", systemImage: "minus.circle")
                        }
                        Divider()
                        Button {
                            showLog.toggle()
                        } label: {
                            Label(showLog ? "Hide Log" : "Show Log",
                                  systemImage: showLog ? "terminal.fill" : "terminal")
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                            .font(.title3)
                    }
                    .disabled(cache.apps.isEmpty)
                }
            }
            .onAppear {
                guard !didInit else { return }
                didInit = true
                console.start()
                cache.detectGroup()
            }
            .overlay { scanOverlay }
            .overlay { cleanOverlay }
            .sheet(item: $selectedApp) { app in
                AppDetailSheet(app: app)
            }
            .confirmationDialog(
                "Clean \(cache.selectedCount) apps?",
                isPresented: $showCleanConfirm,
                titleVisibility: .visible
            ) {
                Button("Clean \(formatBytes(cache.selectedSize))", role: .destructive) {
                    cache.cleanSelected()
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This will delete cache files from the selected apps. Apps may rebuild their caches over time.")
            }
        }
    }

    // MARK: - Header

    private var headerCard: some View {
        VStack(spacing: 16) {
            ZStack {
                Circle()
                    .stroke(Color(.systemGray4), lineWidth: 8)
                    .frame(width: 120, height: 120)
                if cache.totalCacheSize > 0 {
                    Circle()
                        .trim(from: 0, to: cache.selectedSize > 0
                              ? min(1.0, Double(cache.selectedSize) / Double(cache.totalCacheSize))
                              : 0)
                        .stroke(
                            LinearGradient(
                                colors: [.red, .orange],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            ),
                            style: StrokeStyle(lineWidth: 8, lineCap: .round)
                        )
                        .frame(width: 120, height: 120)
                        .rotationEffect(.degrees(-90))
                        .animation(.easeInOut(duration: 0.5), value: cache.selectedSize)
                }
                VStack(spacing: 2) {
                    Image(systemName: "trash.circle.fill")
                        .font(.system(size: 32))
                        .foregroundStyle(
                            cache.totalCacheSize > 0
                            ? AnyShapeStyle(LinearGradient(colors: [.red, .orange], startPoint: .topLeading, endPoint: .bottomTrailing))
                            : AnyShapeStyle(.secondary)
                        )
                }
            }

            Text(cache.totalCacheSize > 0 ? formatBytes(cache.totalCacheSize) : "---")
                .font(.system(size: 38, weight: .bold, design: .rounded))
                .contentTransition(.numericText())
                .animation(.snappy, value: cache.totalCacheSize)

            Text(cache.statusMessage.isEmpty ? "Tap Scan to find caches" : cache.statusMessage)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            if let date = cache.lastScanDate {
                Text("Last scan: \(date.formatted(date: .omitted, time: .shortened))")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }

            if cache.freedSpace > 0 {
                HStack(spacing: 6) {
                    Image(systemName: "checkmark.seal.fill")
                        .foregroundStyle(.green)
                    Text("Freed \(formatBytes(cache.freedSpace))")
                        .fontWeight(.semibold)
                }
                .font(.subheadline)
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
                .background(.green.opacity(0.15), in: Capsule())
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 24)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 20))
        .padding(.top, 8)
    }

    // MARK: - Action Buttons

    private var actionBar: some View {
        HStack(spacing: 12) {
            Button {
                cache.scanCaches()
            } label: {
                Label("Rescan", systemImage: "arrow.clockwise")
                    .font(.subheadline.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
            }
            .buttonStyle(.bordered)
            .tint(.blue)
            .disabled(cache.isScanning || cache.isCleaning)

            Button {
                showCleanConfirm = true
            } label: {
                Label("Clean (\(cache.selectedCount))", systemImage: "trash.fill")
                    .font(.subheadline.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
            }
            .buttonStyle(.borderedProminent)
            .tint(.red)
            .disabled(cache.selectedCount == 0 || cache.isCleaning || cache.isScanning)
        }
    }

    private var scanPrompt: some View {
        VStack(spacing: 16) {
            Image(systemName: "magnifyingglass.circle")
                .font(.system(size: 48))
                .foregroundStyle(.blue.opacity(0.6))
            Button {
                cache.scanCaches()
            } label: {
                Label("Scan Caches", systemImage: "magnifyingglass")
                    .font(.headline)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 14)
            }
            .buttonStyle(.borderedProminent)
            .tint(.blue)
            .disabled(cache.isScanning)

            if cache.detectedGroup == "none" {
                Label("No App Group detected", systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
        }
        .padding(.vertical, 30)
    }

    // MARK: - Stats Row

    private var statsRow: some View {
        HStack(spacing: 12) {
            StatCard(
                title: "Apps",
                value: "\(cache.apps.count)",
                icon: "app.badge",
                color: .blue
            )
            StatCard(
                title: "Selected",
                value: formatBytes(cache.selectedSize),
                icon: "checkmark.circle",
                color: .orange
            )
            StatCard(
                title: "Categories",
                value: "\(cache.apps.filter { $0.sizeCategory == .large }.count) big",
                icon: "chart.bar",
                color: .purple
            )
        }
    }

    // MARK: - Search & Sort

    private var searchAndSort: some View {
        HStack(spacing: 8) {
            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                TextField("Search apps...", text: $searchText)
                    .textFieldStyle(.plain)
                if !searchText.isEmpty {
                    Button { searchText = "" } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .padding(10)
            .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 10))

            Menu {
                ForEach(SortOption.allCases, id: \.self) { opt in
                    Button {
                        sortOption = opt
                    } label: {
                        if opt == sortOption {
                            Label(opt.rawValue, systemImage: "checkmark")
                        } else {
                            Text(opt.rawValue)
                        }
                    }
                }
            } label: {
                Image(systemName: "arrow.up.arrow.down.circle.fill")
                    .font(.title2)
                    .foregroundStyle(.blue)
            }
        }
    }

    // MARK: - App List

    private var appList: some View {
        LazyVStack(spacing: 0) {
            ForEach(filteredApps) { app in
                if let idx = cache.apps.firstIndex(where: { $0.id == app.id }) {
                    AppRow(
                        app: app,
                        isSelected: Binding(
                            get: { cache.apps[idx].selected },
                            set: { cache.apps[idx].selected = $0 }
                        ),
                        onTap: { selectedApp = app }
                    )
                    if app.id != filteredApps.last?.id {
                        Divider().padding(.leading, 56)
                    }
                }
            }
        }
        .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 16))
    }

    // MARK: - Log Section

    private var logSection: some View {
        Group {
            if showLog {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Label("Console Log", systemImage: "terminal.fill")
                            .font(.subheadline.weight(.semibold))
                        Spacer()
                        Button { showLog = false } label: {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundStyle(.secondary)
                        }
                    }
                    ScrollView {
                        Text(console.output.isEmpty ? "No output yet" : console.output)
                            .font(.system(.caption2, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(height: 200)
                }
                .padding()
                .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 16))
            }
        }
    }

    // MARK: - Overlays

    @ViewBuilder
    private var scanOverlay: some View {
        if cache.isScanning {
            Color.black.opacity(0.4)
                .ignoresSafeArea()
                .overlay {
                    VStack(spacing: 16) {
                        ZStack {
                            Circle()
                                .stroke(Color.white.opacity(0.2), lineWidth: 6)
                                .frame(width: 70, height: 70)
                            Circle()
                                .trim(from: 0, to: cache.scanProgressValue)
                                .stroke(Color.blue, style: StrokeStyle(lineWidth: 6, lineCap: .round))
                                .frame(width: 70, height: 70)
                                .rotationEffect(.degrees(-90))
                                .animation(.easeInOut(duration: 0.3), value: cache.scanProgressValue)
                            Text("\(Int(cache.scanProgressValue * 100))%")
                                .font(.system(.headline, design: .rounded))
                                .foregroundStyle(.white)
                        }
                        Text("Scanning...")
                            .font(.headline)
                            .foregroundStyle(.white)
                        if !cache.scanProgress.isEmpty {
                            Text(cache.scanProgress)
                                .font(.caption)
                                .foregroundStyle(.white.opacity(0.7))
                        }
                    }
                    .padding(32)
                    .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 20))
                }
                .transition(.opacity)
        }
    }

    @ViewBuilder
    private var cleanOverlay: some View {
        if cache.isCleaning {
            Color.black.opacity(0.4)
                .ignoresSafeArea()
                .overlay {
                    VStack(spacing: 16) {
                        ProgressView()
                            .scaleEffect(1.5)
                            .tint(.white)
                        Text("Cleaning...")
                            .font(.headline)
                            .foregroundStyle(.white)
                        if !cache.cleaningApp.isEmpty {
                            Text(cache.cleaningApp)
                                .font(.caption)
                                .foregroundStyle(.white.opacity(0.7))
                                .lineLimit(1)
                        }
                    }
                    .padding(32)
                    .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 20))
                }
        }
    }
}

// MARK: - Subviews

struct StatCard: View {
    let title: String
    let value: String
    let icon: String
    let color: Color

    var body: some View {
        VStack(spacing: 6) {
            Image(systemName: icon)
                .font(.title3)
                .foregroundStyle(color)
            Text(value)
                .font(.system(.subheadline, design: .rounded, weight: .bold))
                .lineLimit(1)
                .minimumScaleFactor(0.7)
            Text(title)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 12)
        .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 12))
    }
}

struct AppRow: View {
    let app: AppCacheInfo
    @Binding var isSelected: Bool
    let onTap: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 10)
                    .fill(iconColor.opacity(0.15))
                    .frame(width: 42, height: 42)
                Text(iconLetter)
                    .font(.system(.title3, design: .rounded, weight: .bold))
                    .foregroundStyle(iconColor)
            }

            VStack(alignment: .leading, spacing: 3) {
                Text(app.displayName)
                    .font(.system(.body, weight: .medium))
                    .lineLimit(1)
                HStack(spacing: 8) {
                    Text(app.formattedSize)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    if app.bundleID != app.displayName {
                        Text(app.bundleID)
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                            .lineLimit(1)
                    }
                }
            }

            Spacer()

            Toggle("", isOn: $isSelected)
                .labelsHidden()
                .tint(.green)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .contentShape(Rectangle())
        .onTapGesture { onTap() }
    }

    private var iconColor: Color {
        switch app.sizeCategory {
        case .large: return .red
        case .medium: return .orange
        case .small: return .blue
        }
    }

    private var iconLetter: String {
        let name = app.displayName
        return String(name.prefix(1)).uppercased()
    }
}

struct AppDetailSheet: View {
    let app: AppCacheInfo
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                Section {
                    VStack(spacing: 12) {
                        ZStack {
                            RoundedRectangle(cornerRadius: 18)
                                .fill(sizeColor.opacity(0.15))
                                .frame(width: 72, height: 72)
                            Text(String(app.displayName.prefix(1)).uppercased())
                                .font(.system(size: 32, weight: .bold, design: .rounded))
                                .foregroundStyle(sizeColor)
                        }
                        Text(app.displayName)
                            .font(.title2.weight(.bold))
                        if app.bundleID != app.displayName {
                            Text(app.bundleID)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                    .listRowBackground(Color.clear)
                }

                Section("Cache Breakdown") {
                    HStack {
                        Label("Library/Caches", systemImage: "folder.fill")
                        Spacer()
                        Text(app.formattedCacheSize)
                            .foregroundStyle(.secondary)
                    }
                    HStack {
                        Label("tmp", systemImage: "clock.arrow.circlepath")
                        Spacer()
                        Text(app.formattedTmpSize)
                            .foregroundStyle(.secondary)
                    }
                    HStack {
                        Label("Total", systemImage: "sum")
                            .fontWeight(.semibold)
                        Spacer()
                        Text(app.formattedSize)
                            .fontWeight(.semibold)
                    }
                }

                Section("Container") {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Path")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text(app.path)
                            .font(.system(.caption2, design: .monospaced))
                            .textSelection(.enabled)
                    }
                    HStack {
                        Text("Category")
                        Spacer()
                        Text(app.sizeCategory.rawValue)
                            .foregroundStyle(sizeColor)
                            .font(.subheadline.weight(.medium))
                    }
                }
            }
            .navigationTitle("App Details")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
        }
        .presentationDetents([.medium, .large])
    }

    private var sizeColor: Color {
        switch app.sizeCategory {
        case .large: return .red
        case .medium: return .orange
        case .small: return .blue
        }
    }
}

private func formatBytes(_ bytes: UInt64) -> String {
    ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
}

#Preview {
    ContentView()
}

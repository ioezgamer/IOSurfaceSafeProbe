import SwiftUI

struct TweaksView: View {
    @StateObject private var gestalt = GestaltManager.shared
    @State private var searchText = ""
    @State private var showApplyConfirm = false
    @State private var showRestoreConfirm = false
    @State private var expandedCategory: TweakCategory? = .display

    private var pendingCount: Int {
        gestalt.tweakStates.filter(\.isModified).count
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    headerCard
                    if gestalt.gestaltAccessible {
                        applyBar
                        searchBar
                        tweaksList
                    } else if !gestalt.isLoading {
                        loadPrompt
                    }
                }
                .padding(.horizontal)
                .padding(.bottom, 30)
            }
            .background(Color(.systemGroupedBackground))
            .navigationTitle("Tweaks")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        if gestalt.hasBackup {
                            Button(role: .destructive) {
                                showRestoreConfirm = true
                            } label: {
                                Label("Restore Backup", systemImage: "arrow.uturn.backward")
                            }
                        }
                        Button {
                            gestalt.loadGestalt()
                        } label: {
                            Label("Reload", systemImage: "arrow.clockwise")
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                            .font(.title3)
                    }
                }
            }
            .onAppear { gestalt.loadGestalt() }
            .overlay { loadingOverlay }
            .confirmationDialog("Apply Changes?", isPresented: $showApplyConfirm, titleVisibility: .visible) {
                Button("Apply \(pendingCount) tweaks", role: .destructive) {
                    gestalt.applyChanges()
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This modifies the MobileGestalt cache. A backup will be created automatically. Reboot required to take effect.")
            }
            .confirmationDialog("Restore Backup?", isPresented: $showRestoreConfirm, titleVisibility: .visible) {
                Button("Restore Original", role: .destructive) {
                    gestalt.restoreBackup()
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This will undo all MobileGestalt modifications and restore the original plist. Reboot required.")
            }
        }
    }

    // MARK: - Header

    private var headerCard: some View {
        VStack(spacing: 14) {
            ZStack {
                Circle()
                    .fill(
                        LinearGradient(
                            colors: [.purple, .indigo],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        ).opacity(0.2)
                    )
                    .frame(width: 80, height: 80)
                Image(systemName: "wrench.and.screwdriver.fill")
                    .font(.system(size: 34))
                    .foregroundStyle(
                        LinearGradient(
                            colors: [.purple, .indigo],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
            }

            Text("MobileGestalt Tweaks")
                .font(.title3.weight(.bold))

            if gestalt.gestaltAccessible {
                HStack(spacing: 20) {
                    VStack(spacing: 2) {
                        Text("\(GestaltManager.allTweaks.count)")
                            .font(.system(.title3, design: .rounded, weight: .bold))
                        Text("Available")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    Divider().frame(height: 30)
                    VStack(spacing: 2) {
                        Text("\(pendingCount)")
                            .font(.system(.title3, design: .rounded, weight: .bold))
                            .foregroundStyle(pendingCount > 0 ? .orange : .primary)
                        Text("Modified")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    if gestalt.hasBackup {
                        Divider().frame(height: 30)
                        VStack(spacing: 2) {
                            Image(systemName: "checkmark.shield.fill")
                                .font(.title3)
                                .foregroundStyle(.green)
                            Text("Backup")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }

            if !gestalt.statusMessage.isEmpty {
                Text(gestalt.statusMessage)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 20)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 20))
        .padding(.top, 8)
    }

    // MARK: - Apply Bar

    private var applyBar: some View {
        HStack(spacing: 12) {
            if gestalt.hasBackup {
                Button {
                    showRestoreConfirm = true
                } label: {
                    Label("Restore", systemImage: "arrow.uturn.backward")
                        .font(.subheadline.weight(.semibold))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 12)
                }
                .buttonStyle(.bordered)
                .tint(.orange)
            }

            Button {
                showApplyConfirm = true
            } label: {
                Label("Apply (\(pendingCount))", systemImage: "checkmark.circle.fill")
                    .font(.subheadline.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
            }
            .buttonStyle(.borderedProminent)
            .tint(.purple)
            .disabled(pendingCount == 0 || gestalt.isLoading)
        }
    }

    // MARK: - Search

    private var searchBar: some View {
        HStack {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(.secondary)
            TextField("Search tweaks...", text: $searchText)
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
    }

    // MARK: - Tweaks List

    private var tweaksList: some View {
        VStack(spacing: 12) {
            ForEach(TweakCategory.allCases, id: \.self) { category in
                let states = filteredStates(for: category)
                if !states.isEmpty {
                    categorySection(category: category, states: states)
                }
            }
        }
    }

    private func filteredStates(for category: TweakCategory) -> [TweakState] {
        gestalt.tweakStates.filter { state in
            state.tweak.category == category &&
            (searchText.isEmpty ||
             state.tweak.name.localizedCaseInsensitiveContains(searchText) ||
             state.tweak.description.localizedCaseInsensitiveContains(searchText))
        }
    }

    @ViewBuilder
    private func categorySection(category: TweakCategory, states: [TweakState]) -> some View {
        VStack(spacing: 0) {
            Button {
                withAnimation(.easeInOut(duration: 0.25)) {
                    expandedCategory = expandedCategory == category ? nil : category
                }
            } label: {
                HStack {
                    Image(systemName: category.icon)
                        .font(.title3)
                        .foregroundStyle(.purple)
                        .frame(width: 30)
                    Text(category.rawValue)
                        .font(.headline)
                        .foregroundStyle(.primary)
                    Spacer()
                    Text("\(states.count)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(Color(.systemGray5), in: Capsule())
                    Image(systemName: expandedCategory == category ? "chevron.up" : "chevron.down")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 12)
            }

            if expandedCategory == category {
                Divider().padding(.leading, 56)

                // Category quick actions
                HStack(spacing: 8) {
                    Button("Enable All") { gestalt.enableAll(in: category) }
                        .font(.caption.weight(.medium))
                        .buttonStyle(.bordered)
                        .tint(.green)
                    Button("Disable All") { gestalt.disableAll(in: category) }
                        .font(.caption.weight(.medium))
                        .buttonStyle(.bordered)
                        .tint(.red)
                    Spacer()
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 8)

                ForEach(states) { state in
                    Divider().padding(.leading, 56)
                    tweakRow(state: state)
                }
            }
        }
        .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 16))
    }

    @ViewBuilder
    private func tweakRow(state: TweakState) -> some View {
        if let idx = gestalt.tweakStates.firstIndex(where: { $0.id == state.id }) {
            VStack(alignment: .leading, spacing: 8) {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 6) {
                            Text(state.tweak.name)
                                .font(.system(.body, weight: .medium))
                            if state.isModified {
                                Image(systemName: "circle.fill")
                                    .font(.system(size: 6))
                                    .foregroundStyle(.orange)
                            }
                        }
                        Text(state.tweak.description)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }

                    Spacer()

                    switch state.tweak.type {
                    case .bool:
                        Toggle("", isOn: Binding(
                            get: { gestalt.tweakStates[idx].currentValue as? Bool ?? false },
                            set: { newVal in
                                gestalt.tweakStates[idx].currentValue = newVal
                                gestalt.tweakStates[idx].isModified = true
                            }
                        ))
                        .labelsHidden()
                        .tint(.purple)
                    case .int:
                        EmptyView()
                    case .pick(let options):
                        Menu {
                            ForEach(options, id: \.value) { opt in
                                Button {
                                    gestalt.setPickValue(id: state.id, value: opt.value)
                                } label: {
                                    VStack {
                                        Text(opt.label)
                                        Text(opt.detail)
                                    }
                                }
                            }
                        } label: {
                            let current = state.currentValue as? Int ?? 0
                            let label = options.first(where: { $0.value == current })?.label ?? "\(current)"
                            Text(label)
                                .font(.caption.weight(.medium))
                                .padding(.horizontal, 10)
                                .padding(.vertical, 6)
                                .background(Color.purple.opacity(0.15), in: Capsule())
                        }
                    }
                }

                if case .pick(let options) = state.tweak.type {
                    let current = state.currentValue as? Int ?? 0
                    if let opt = options.first(where: { $0.value == current }), current != 0 {
                        Text("Current: \(opt.label) — \(opt.detail)")
                            .font(.caption2)
                            .foregroundStyle(.purple)
                    }
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
        }
    }

    // MARK: - Load Prompt

    private var loadPrompt: some View {
        VStack(spacing: 16) {
            Image(systemName: "wrench.and.screwdriver")
                .font(.system(size: 48))
                .foregroundStyle(.purple.opacity(0.6))
            Text("Tap to load MobileGestalt tweaks")
                .font(.subheadline)
                .foregroundStyle(.secondary)
            Button {
                gestalt.loadGestalt()
            } label: {
                Label("Load Tweaks", systemImage: "bolt.fill")
                    .font(.headline)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 14)
            }
            .buttonStyle(.borderedProminent)
            .tint(.purple)
        }
        .padding(.vertical, 30)
    }

    // MARK: - Loading Overlay

    @ViewBuilder
    private var loadingOverlay: some View {
        if gestalt.isLoading {
            Color.black.opacity(0.4)
                .ignoresSafeArea()
                .overlay {
                    VStack(spacing: 16) {
                        ProgressView()
                            .scaleEffect(1.5)
                            .tint(.white)
                        Text(gestalt.statusMessage)
                            .font(.headline)
                            .foregroundStyle(.white)
                    }
                    .padding(32)
                    .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 20))
                }
        }
    }
}

//
//  ContentView.swift
//  IOSurfaceSafeProbe
//
//  Cache cleaner UI
//

import SwiftUI

struct ContentView: View {
    @StateObject private var cache = CacheManager()
    @StateObject private var console = Console()
    @State private var showLog = false
    
    var body: some View {
        NavigationStack {
            List {
                // Status header
                Section {
                    VStack(spacing: 12) {
                        Image(systemName: "trash.circle.fill")
                            .font(.system(size: 56))
                            .foregroundStyle(.blue)
                        
                        Text(cache.totalCacheSize > 0
                             ? ByteCountFormatter.string(fromByteCount: Int64(cache.totalCacheSize), countStyle: .file)
                             : "---")
                            .font(.system(size: 34, weight: .bold, design: .rounded))
                        
                        Text(cache.statusMessage.isEmpty ? "Tap Scan to find caches" : cache.statusMessage)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 16)
                }
                .listRowBackground(Color.clear)

                if cache.needsTrollStore {
                    Section {
                        HStack(spacing: 10) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundStyle(.yellow)
                            VStack(alignment: .leading, spacing: 4) {
                                Text("TrollStore Required")
                                    .font(.headline)
                                Text("Sideloader groups detected. The exploit only works when installed via TrollStore, which preserves the app's entitlements.")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .padding(.vertical, 4)
                    }
                }
                
                // Actions
                Section {
                    Button {
                        cache.scanCaches()
                    } label: {
                        Label("Scan Caches", systemImage: "magnifyingglass")
                    }
                    .disabled(cache.isScanning || cache.isCleaning)
                    
                    Button(role: .destructive) {
                        cache.cleanSelected()
                    } label: {
                        Label("Clean Selected", systemImage: "trash")
                    }
                    .disabled(cache.apps.isEmpty || cache.isCleaning || cache.isScanning)
                }
                
                // App list
                if !cache.apps.isEmpty {
                    Section("Apps (\(cache.apps.count))") {
                        ForEach(Array(cache.apps.enumerated()), id: \.element.id) { index, app in
                            HStack {
                                Toggle(isOn: Binding(
                                    get: { cache.apps[index].selected },
                                    set: { cache.apps[index].selected = $0 }
                                )) {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(app.bundleID)
                                            .font(.system(.body, design: .monospaced))
                                            .lineLimit(1)
                                        Text(app.formattedSize)
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                    }
                                }
                                .toggleStyle(.switch)
                            }
                        }
                    }
                }
                
                // Freed space result
                if cache.freedSpace > 0 {
                    Section {
                        HStack {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundStyle(.green)
                            Text("Freed \(ByteCountFormatter.string(fromByteCount: Int64(cache.freedSpace), countStyle: .file))")
                                .fontWeight(.semibold)
                        }
                    }
                }
                
                // Log toggle
                Section {
                    DisclosureGroup("Console Log", isExpanded: $showLog) {
                        ScrollView {
                            Text(console.output.isEmpty ? "No output yet" : console.output)
                                .font(.system(.caption2, design: .monospaced))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .frame(height: 180)
                    }
                }
            }
            .navigationTitle("CacheWipe")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    if cache.isScanning || cache.isCleaning {
                        ProgressView()
                    }
                }
            }
            .onAppear {
                console.start()
                cache.detectGroup()
            }
            .overlay {
                if cache.isScanning {
                    Color.black.opacity(0.3)
                        .ignoresSafeArea()
                        .overlay {
                            VStack(spacing: 12) {
                                ProgressView()
                                    .scaleEffect(1.5)
                                Text("Scanning...")
                                    .font(.headline)
                            }
                            .padding(30)
                            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 16))
                        }
                }
            }
        }
    }
}

#Preview {
    ContentView()
}

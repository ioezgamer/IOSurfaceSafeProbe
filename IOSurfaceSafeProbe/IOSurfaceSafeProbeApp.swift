//
//  IOSurfaceSafeProbeApp.swift
//  IOSurfaceSafeProbe
//
//  Cache cleaner for iOS 26/27 using worse_query sandbox escape
//

import SwiftUI

@main
struct IOSurfaceSafeProbeApp: App {
    var body: some Scene {
        WindowGroup {
            MainTabView()
        }
    }
}

struct MainTabView: View {
    @State private var selectedTab = 0

    var body: some View {
        TabView(selection: $selectedTab) {
            ContentView()
                .tabItem {
                    Label("Cache", systemImage: "trash.circle.fill")
                }
                .tag(0)

            TweaksView()
                .tabItem {
                    Label("Tweaks", systemImage: "wrench.and.screwdriver.fill")
                }
                .tag(1)

            ResearchView()
                .tabItem {
                    Label("Research", systemImage: "shield.lefthalf.filled.badge.checkmark")
                }
                .tag(2)
        }
        .tint(.purple)
    }
}

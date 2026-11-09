# IOSurfaceSafeProbe

**Cache cleaner for iOS 26.0 – 26.7.2 / 27.2** using the [worse_query](https://github.com/forcequitOS/worse_query) sandbox escape.

## What it does

- Scans app containers for cache and temp files
- Shows per-app cache sizes
- Lets you select which apps to clean
- Deletes cache/tmp contents to free storage

## Requirements

- iOS 26.0 – 26.7.2 or iOS 27.2
- An **App Group** configured in your Apple Developer account
- Sideloading via AltStore, SideStore, or Xcode

## Setup

1. Create an App Group identifier at [developer.apple.com](https://developer.apple.com) (e.g. `group.com.yourname.cachewipe`)
2. Update the App Group in:
   - `IOSurfaceSafeProbe/IOSurfaceSafeProbe.entitlements`
   - `IOSurfaceSafeProbe/CacheManager.swift` (the `appGroup` constant)
3. Build and sideload to your device

## Build

Open `IOSurfaceSafeProbe.xcodeproj` in Xcode and build for your device.

GitHub Actions builds automatically on push (unsigned IPA as artifact).

## Credits

- [worse_query](https://github.com/forcequitOS/worse_query) by Taj C (forcequit) — GPL-3.0
- This project is also licensed under GPL-3.0

## Disclaimer

This is for personal/educational use only. Not intended for App Store distribution.

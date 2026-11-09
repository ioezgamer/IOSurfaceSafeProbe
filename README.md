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

1. The build-time App Group request is \`group.com.ioezgamer.iosurfacesafeprobe\` in \`IOSurfaceSafeProbe/IOSurfaceSafeProbe.entitlements\`, matching the fallback in \`IOSurfaceSafeProbe/CacheManager.swift\`.
2. When SideStore re-signs the IPA, the *final signed entitlements* and provisioning profile determine which App Groups iOS allows. The source \`.entitlements\` file cannot be updated dynamically at runtime.
3. The app tries App Groups from its embedded provisioning profile, then the build-time identifier. It validates candidates with \`FileManager.containerURL(forSecurityApplicationGroupIdentifier:)\`. If no usable group is found, the screen shows an error instead of silently reporting zero caches.
4. If SideStore embeds no readable provisioning profile, use the **App Group (SideStore)** field to enter a group actually assigned to **this app**. This value is saved locally; leave it blank for automatic selection. SideStore's own App Group is not automatically available to CacheWipe.

### Find the identifier assigned to the installed app

If you can obtain an IPA **after SideStore has signed it**, on a Mac run:

\`\`\`sh
mkdir -p signed-inspect
unzip -q CacheWipe-signed.ipa -d signed-inspect
codesign -d --entitlements :- signed-inspect/Payload/*.app
\`\`\`

Look for \`com.apple.security.application-groups\`. You can also inspect the embedded provisioning profile:

\`\`\`sh
security cms -D -i signed-inspect/Payload/*.app/embedded.mobileprovision
\`\`\`

The profile lists authorized groups; the signed entitlements are the authoritative list requested by the installed binary. Compare them. If the key is absent, typing a guessed group name cannot grant the entitlement. SideStore's free-Apple-ID signing may omit or rewrite capabilities; a paid developer account is not automatically assumed.

**Error -1:** \`worse_query.m\` returns -1 when \`containerURLForSecurityApplicationGroupIdentifier\` returns nil. A working App Group is necessary for the app's own shared container, but does not by itself authorize access to another app's private files.

## Build

Open `IOSurfaceSafeProbe.xcodeproj` in Xcode and build for your device.

GitHub Actions builds automatically on push (unsigned IPA as artifact).

## Credits

- [worse_query](https://github.com/forcequitOS/worse_query) by Taj C (forcequit) — GPL-3.0
- This project is also licensed under GPL-3.0

## Disclaimer

This is for personal/educational use only. Not intended for App Store distribution. Removing other apps' caches may cause data loss or disrupt app state. Review all selected paths before cleaning.

# WP01.03 native reconciliation

The accepted [native reconciliation policy](https://github.com/ArcForges/ArcForges-Design/blob/7abe9bc4c1964a23d5dc3894dbe3a0357ec31a00/docs/assurance/wp01-03-native-reconciliation-policy.md) governs this bounded disposition. DesktopPlatform owns the native producer toolchain and capability packages; products consume exact published packages.

| Existing surface | Disposition and owner |
|---|---|
| ArcMediaNative | Keep in DesktopPlatform; production imports belong to ArcForges.Native.Media. |
| ArcSlateColorNative | Keep in DesktopPlatform; production imports belong to ArcForges.Native.Colour. |
| ArcSlateImageNative | Keep in DesktopPlatform; production imports belong to ArcForges.Native.Image. |
| ArcSlateOtioNative | Keep in DesktopPlatform; production imports belong to ArcForges.Native.Otio. |
| Metal bridge | Keep the existing macOS-only probe source; no Windows runtime package or functional graphics claim. |
| Legacy NativeInterop bindings | Move the independent ABI oracle to tests/NativeAbiTests/Oracle. Keep the non-packable project identity as a name-only scaffold. |
| arcscope-mdf-abi | Remains absent and excluded; do not restore the retired MDF ABI. |

Each admitted Windows library currently exposes only ABI version, build information and last-error probes. The existing package allowlist and immutable native-win-x64-r3 provenance profile remain unchanged. OpenTimelineIO stays at the selected v0.18.1 overlay and vcpkg stays at 36677bbd0b3bf11da7376e62e14bffcc54d2eaeb; this reconciliation does not upgrade upstream inputs.

Production LibraryImport declarations have one capability owner. The bounded source check in ArchitectureTests rejects duplicate or unowned LibraryImport declarations in the current source format, DllImport declarations, and explicit production project references into tests. It is not a general C# or evaluated MSBuild dependency analyser. The independent test oracle retains its ABI layout, null/error and loader checks; it is not a production dependency. The ContentSandbox project remains a scaffold and does not establish hostile-input containment.

Read-only product source scans found no LibraryImport, DllImport, NativeLibrary, NativeSmoke, ArcSlateNative or PlatformBroker occurrences in src at these clean commits:

- ArcNotes: e40423a1b14ce8341de35748cc2a093c7c9b77a7.
- ArcScope: d247dcff36fd1123a70e5e59967a9b2294a2eeac.
- ArcSlate: b0d255f54fb560a534cc493d5645ca4bc7b4bd0e.

There was therefore no matching product-side source copy to move or delete. This bounded source scan does not prove future product integrations.

Functional Instruments, Pdf and Graphics admission remains WP13 work. Hostile-input parser integration requires the WP03 contracts, WP08 transport and WP11 restricted helper before WP13 composition. No signed PlatformBroker or existing parser isolation is claimed. Later admission must update the allowlist, dependency and licence closure, provenance, independent consumer evidence and containment tests together.

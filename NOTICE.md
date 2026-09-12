# DesktopPlatform notices

DesktopPlatform is licensed under AGPL-3.0-only. Corresponding Source, including the source commit
recorded in each package, is available at https://github.com/ArcForges/DesktopPlatform.

The current `ArcForges.Build.Policy` NuGet contains only first-party policy sources and no third-party
runtime binaries. The four Windows runtime NuGets ship their actual DLL closure, app-local Visual C++
runtime files, upstream licence texts, SPDX records and build recipes. The Media package also includes
matching FFmpeg/libusb source archives. Each package's SBOM records the complete shared/static build
dependency closure; the table below names the primary dependencies.

| Component | Selected version | Licence | Use |
|---|---|---|---|
| .NET SDK/runtime and Microsoft analyzers | Pinned SDK and package locks | MIT | Managed build and tests |
| xUnit | Package locks | Apache-2.0 | Tests only |
| FFmpeg | 9.0.1 | LGPL-2.1-or-later configuration | Shared media runtime behind owned C ABI |
| libusb | 1.0.30 | LGPL-2.1-or-later | Device-access runtime |
| miniaudio | 0.11.25 | Unlicense OR MIT-0 | Audio foundation |
| OpenTimelineIO | 0.18.1, pinned overlay | Apache-2.0 | Owned OTIO shim |
| OpenColorIO / OpenEXR / Imath | 2.5.2 / 3.4.14 / 3.2.2 | BSD-3-Clause | Colour/image shim dependencies |
| OpenImageIO | 3.1.14.0 | Apache-2.0 | Owned image shim |

Exact native inputs use vcpkg `36677bbd0b3bf11da7376e62e14bffcc54d2eaeb` and the retained OTIO overlay.
MDF was removed from both producer build graphs. See [native builds](deploy/README.md) and the
[dependency register](docs/compliance/third-party-license-register.md). The binary SBOM and file hashes
are generated from each actual native artifact, not inferred from this overview.

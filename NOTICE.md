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

## AFV2-ENV-01 managed and Python dependency draft

This pending managed/tooling upgrade records the exact dependency identities in
[the current inventory](docs/dependency-upgrade/afv2-env-01-managed.json) and its new
dependency receipt. Earlier native disclosures retain their original versions;
the active native catalogue and new native qualification remain separate. The
managed slice does not republish retired native capabilities.

| Current component family | Selected versions | Licence / terms |
|---|---|---|
| Microsoft .NET SDK/runtime/compiler, analyzers, Sqlite, Extensions and test tooling | SDK/workload 11.0.100; exact individual locks | MIT |
| Azure SDK, Application Insights and OpenTelemetry | Exact current locks (including ApplicationInsights 3.2.0 and OpenTelemetry 1.21.0) | MIT / Apache-2.0 as recorded per package |
| Avalonia / MicroCom | 12.1.6, BuildServices 11.3.2 / 0.11.7 | MIT |
| gRPC / Google.Protobuf | 2.85.0 / 3.36.2 | Apache-2.0 / BSD-3-Clause |
| xUnit / runner / analyzers | 4.0.3 / 4.0.1 / 2.3.0 | Apache-2.0 |
| SQLitePCLRaw wrappers | 3.0.5 | Apache-2.0 |
| SQLite | 3.54.1 | Public domain, exact LICENSE.txt record `LicenseRef-SQLite-Public-Domain`; https://sqlite.org/copyright.html |
| Tmds.DBus.Protocol / coverlet.collector | 0.95.2 / 10.1.0 | MIT |

Python components below are CI hook, isolated build or installer tools. Their
original licence files/METADATA evidence and exact artifact hashes are recorded;
they are not bundled into capability runtime packages.

| Python coordinate | Licence |
|---|---|
| cfgv/3.5.0 | MIT |
| cython/3.3.1 | Apache-2.0 |
| distlib/0.4.4 | PSF-2.0 |
| filelock/4.2.10 | MIT |
| identify/2.6.20 | MIT |
| nodeenv/1.12.0 | BSD-3-Clause |
| packaging/26.3 | Apache-2.0 OR BSD-2-Clause |
| pip/26.3 | MIT |
| platformdirs/4.14.5 | MIT |
| pre-commit/4.7.0 | MIT |
| python-discovery/1.9.5 | MIT |
| pyyaml/6.0.3 | MIT |
| setuptools/84.2.1 | MIT |
| virtualenv/21.15.6 | MIT |
| wheel/0.48.0 | MIT |

This attribution does not replace upstream licence/notice files retained by the original distributions or the existing native source/legal records.

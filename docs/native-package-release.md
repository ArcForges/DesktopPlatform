# Existing native ABI package release

## Scope fixed before implementation

Base: DesktopPlatform `7bdbf6c4656721088081cdf85c9f1ec8d78bc848`. The requested delivery is the
complete existing Windows x64 ABI and its actual dependencies, not new media/timeline business APIs.
The four owned libraries currently expose ABI version, dependency build information and thread-local
error queries. Metal remains macOS-only and is outside this Windows package admission.

The package identities follow the Design package registry: `ArcForges.Native.Abstractions`, managed
`ArcForges.Native.Media`, `.Colour`, `.Image`, `.Otio`, and their matching `.Runtime.win-x64` packages.
`ArcForges.Build.Policy` remains in the same verified release. Shared product placeholders remain excluded.

## Findings and repair plan

1. Main publication and native validation were independent workflows. In runs 34675014058/34675014032,
   upload completed at 05:15:11 UTC while native validation completed at 05:16:10 UTC. Route PRs and main
   releases through one reusable gate: native compilation/tests and source checks precede packing;
   package consumers and the aggregate gate precede publication. Keep each main run independent.
2. Native outputs were only copied into a producer test directory. Export immutable staged artifacts
   with commit, RID, hashes, imports and exports. Packing must consume that artifact from the same run;
   missing, changed or mismatched native assets must fail before upload.
   Validation also exposed global installed vcpkg libraries with older Vulkan-Headers/OpenEXR/OpenJPH
   versions than the pinned checkout. Use an isolated Windows installed tree shared by CMake and MSBuild;
   verify installed recipe and release-library hashes instead of inferring provenance from vcpkg HEAD.
3. The current managed interop project is a test probe. Add per-capability public bindings for all
   existing entry points, sharing fixed-width status/layout/error handling in Native.Abstractions.
   Use generated LibraryImport and explicit application-directory loading without PATH/CWD fallback.
4. Admit real RID packages containing the owned DLL, complete non-system DLL closure, C headers and
   import library. Record static and shared upstream dependencies, preserve licences and pinned source
   records, include corresponding FFmpeg/libusb sources and build recipes, and distinguish Windows
   system API dependencies from redistributed Visual C++ runtime files.
5. Prove the delivered bytes in an external consumer with an empty NuGet cache and no producer source
   references. Exercise each package independently and together, publish/run Windows x64 Native AOT,
   verify deployed native hashes, and reject missing/tampered libraries and incompatible RID/version
   pairs. Retain portable Build.Policy consumer checks on Windows and Linux.

## Closure evidence

Development checks completed: locked managed restore/build, four architecture checks, formatting and
actionlint. Ten real development packages (`1.0.0-ci.native.4`) passed the twelve package guards and
isolated Build.Policy checks. All four native bindings independently and together executed through
Native AOT; a separate C17 caller linked the packaged headers/import libraries and called all entry
points. Missing owned/transitive DLLs, modified DLLs and an incompatible RID were rejected. These early
fixtures used the existing installed libraries and are not the final dependency-provenance evidence.

Final isolated dependency rebuild and hosted PR validation are in progress. Record their actual
results before marking the PR ready. No new native package is claimed as uploaded to nuget.org yet.
Existing ABI queries do not establish decode/encode, image processing, timeline editing, hostile-content
sandbox or GPU functionality. Those APIs and their product acceptance remain separate implementation work.

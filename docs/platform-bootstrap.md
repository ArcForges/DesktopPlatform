# DesktopPlatform extraction and package pipeline

This is historical extraction evidence at the source revisions below. The current
[runtime and ownership policy](runtime-ownership.md), reviewed on 2026-09-20, governs
repository/runtime assignments; the old Design snapshot is not current authority.

## Initial extraction plan

Base: `99bfe7d695ed0d65a0d035af7d219fc9b86100f5` in `ArcForges/DesktopPlatform`.
Design authority: `ArcForges/ArcForges-Design` commit `f6e0cd2` (merged final review),
`docs/architecture/01-solution-and-project-layout.md`, package registry and staged WP02 publication.

1. Preserve shared desktop mechanisms, ContentSandbox scaffold, native C ABI sources, classic vcpkg,
   Windows IDE entry point, native ABI checks and attribution. Remove MDF from both native entry points.
2. Remove product/Cloud/Web/Mobile/Contracts/SDK/extension sources, their tests and obsolete whole-family
   instructions, work logs and delivery workflows. Their complete source remains at the base commit;
   the independent old copy and all other repositories are untouched.
3. Rebuild platform-only solutions, package pins and architecture checks. Existing placeholders remain
   explicitly non-packable. NativeInterop is a name-only scaffold. Independent ABI oracle bindings live only in NativeAbiTests; production bindings belong to the Native capability packages.
4. Add the real `ArcForges.Build.Policy` package and an explicit release allowlist. Build and pack with
   an allocated version; verify metadata/hash and restore in an isolated consumer with a private cache.
   PRs retain candidates. Initial delivery used a manually triggered main-branch NuGet OIDC release;
   the current automatic publication behavior is recorded below.
5. Validate locked restore, warnings-as-errors build, policy and native checks, package consumer and
   negative fixtures, workflow syntax and final diff. Record actual evidence separately from pending
   NuGet account setup and future capability/RID acceptance.

## Scope and source disposition

The removed monorepo applications and JSON contract implementation belong to separate repositories.
Removal is an ownership extraction, not a claim that new product or proto implementations exist.
Shared placeholder libraries are retained for follow-on implementation but are not release artifacts.
The first publication supported build policy. The subsequent [native package release](native-package-release.md)
admits the four existing Windows ABIs with their real native closure and package-consumer validation.
This bootstrap does not close every WP02 obligation across all nine implementation repositories or the WP06 native gates.

## Local validation evidence

- 15 remaining C# projects: locked restore and Release build passed with zero warnings/errors using
  .NET SDK 10.0.400 on Windows x64. Four platform ownership/package/source checks passed; dotnet format passed.
- `ArcForges.Build.Policy` 1.0.0-ci.1 packed successfully. An external temporary consumer with an empty
  cache restored the exact bytes, repeated locked restore, built and ran. Four installed-policy negative
  cases and six package/version/manifest guard tests passed. This was a local development candidate from
  an uncommitted working tree, not a public release/source attestation.
- CMake runtime-shared and shim-static built, staged and passed 1 + 3 native CTests. The C# LibraryImport
  test passed against those app-local DLLs. The independent `win.slnx` Release|x64 pre-push check passed.
  Local native tools: CMake 4.4.3, MSVC 19.51.36256; vcpkg matched the committed 36677bbd baseline.
  Hosted CI still pins CMake 4.3.3; local evidence does not substitute for that exact hosted toolchain.
- actionlint 1.7.12, pre-commit clang-format, local Markdown file links and Git whitespace checks passed.

At extraction time, NuGet account setup was deferred and no NuGet/npm package was published. Subsequent
setup completed NuGet trusted publishing and the GitHub `nuget` environment. Main-branch
[run 34673898986](https://github.com/ArcForges/DesktopPlatform/actions/runs/34673898986) successfully
authenticated through OIDC and uploaded `ArcForges.Build.Policy` `1.0.0-ci.2.1`.

## Automatic publication after main updates

The publication workflow now runs on every push to `main`, including merged PRs. It allocates an
immutable prerelease version, completes the reusable native-build/source/package gate,
then publishes the tested bytes. No manual release form or approval step is part of the configured
flow. Independent runs prevent newer merges from replacing queued releases. See the current
[package production instructions](../eng/packaging/README.md) for numbering, setup and recovery.

Main push [run 34675014058](https://github.com/ArcForges/DesktopPlatform/actions/runs/34675014058)
proved the automatic trigger and upload. It also exposed that the independent native gate finished
after upload; the subsequent native release change joins them into the ordered gate described above.
The initial extraction evidence does not establish full product capability, other native RIDs,
sandbox, application, mobile-device or commercial-operation acceptance. Current ABI/AOT evidence is
recorded separately in the native release document.

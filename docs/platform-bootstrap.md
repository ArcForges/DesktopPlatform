# DesktopPlatform extraction and package pipeline

## Plan fixed before changes

Base: `99bfe7d695ed0d65a0d035af7d219fc9b86100f5` in `ArcForges/DesktopPlatform`.
Design authority: `ArcForges/ArcForges-Design` commit `f6e0cd2` (merged final review),
`docs/architecture/01-solution-and-project-layout.md`, package registry and staged WP02 publication.

1. Preserve shared desktop mechanisms, ContentSandbox scaffold, native C ABI sources, classic vcpkg,
   Windows IDE entry point, native ABI checks and attribution. Remove MDF from both native entry points.
2. Remove product/Cloud/Web/Mobile/Contracts/SDK/extension sources, their tests and obsolete whole-family
   instructions, work logs and delivery workflows. Their complete source remains at the base commit;
   the independent old copy and all other repositories are untouched.
3. Rebuild platform-only solutions, package pins and architecture checks. Existing placeholders remain
   explicitly non-packable. NativeInterop remains an internal ABI probe, pending capability separation.
4. Add the real `ArcForges.Build.Policy` package and an explicit release allowlist. Build and pack with
   an allocated version; verify metadata/hash and restore in an isolated consumer with a private cache.
   PRs retain candidates; a main-branch manual release publishes those tested bytes using NuGet OIDC.
5. Validate locked restore, warnings-as-errors build, policy and native checks, package consumer and
   negative fixtures, workflow syntax and final diff. Record actual evidence separately from pending
   NuGet account setup and future capability/RID acceptance.

## Scope and source disposition

The removed monorepo applications and JSON contract implementation belong to separate repositories.
Removal is an ownership extraction, not a claim that new product or proto implementations exist.
Shared placeholder libraries are retained for follow-on implementation but are not release artifacts.
The first publication supports build policy. Runtime capability NuGets require their own ABI, native
asset, licence/SBOM and real AOT consumer admission before adding them to the publication allowlist.
This bootstrap does not close every WP02 obligation across all ten repositories or the WP06 native gates.

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

NuGet account setup is intentionally deferred by the user. `YOUR_NUGET_USERNAME` is the explicit
placeholder; dry-run candidate validation works without credentials, while actual publication rejects
it. No NuGet/npm package was published. No full capability AOT, macOS/ARM64/Linux native release matrix,
sandbox, application, mobile-device or commercial-operation acceptance is claimed here.

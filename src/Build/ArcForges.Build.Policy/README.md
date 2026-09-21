# ArcForges.Build.Policy

Portable MSBuild defaults and enforcement for C# 14 repositories: nullable, deterministic builds,
warnings-as-errors, package locks, central package versions and AOT/trim warning escalation.
This build-only AGPL-3.0-only package contains no runtime assembly or native dependency.

Declare the exact version in your repository's `Directory.Packages.props` and reference the package
with `PrivateAssets="all"`. Each repository owns its `global.json`, target frameworks, runtime/AOT host
settings and package locks. This package never invokes CMake/vcpkg and does not set output/cache paths.
Normal NuGet `build/` imports activate after restore; it intentionally does not flow transitively.

Diagnostics AFP001–AFP003 reject missing central management, inline overrides and floating versions;
AFP004–AFP005 reject compiler-policy or lock-policy overrides. Invalid package graphs may additionally
be rejected directly by NuGet. Check compiler settings with `dotnet msbuild -getProperty:LangVersion`.

Owned assemblies also expose `AssemblyMetadataAttribute` keys `ArcForges.SourceCommit`,
`ArcForges.BuildId`, `ArcForges.PipelineRun`, `ArcForges.SourceDateEpoch` and `ArcForges.BuildKind`.
CI identity uses the full Git SHA and actual GitHub run ID/attempt, with the commit timestamp in
Unix seconds; this deterministic source time is not wall-clock compilation time. AFP006 rejects
incomplete or mismatched CI identity. Non-repository local consumer fixtures remain explicitly
local (source `local`, epoch `0` when Git metadata is unavailable) and cannot establish publication.
The owner's candidate tooling separately seals dirty state and rejects dirty/local publication.

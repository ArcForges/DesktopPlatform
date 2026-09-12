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

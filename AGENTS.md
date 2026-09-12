# DesktopPlatform contributor instructions

This repository owns shared desktop mechanisms, C# interop, CMake/vcpkg and capability NuGet production.
The product applications, Cloud, AI, Web, Mobile and business RPC schemas have separate repositories.
The accepted architecture lives in [ArcForges-Design](https://github.com/ArcForges/ArcForges-Design).

- Work on a focused branch in `.worktree/`. Preserve the primary checkout and unrelated repositories.
- Use C# 14 / .NET 10 from `global.json`, C++20 and C17-compatible public C ABI headers.
- Keep native toolchains here. Consumers use exact published package versions and committed lock files;
  never add Git submodules or sibling source dependencies. Business proto generation belongs to Contracts.
- Put dependency versions in `Directory.Packages.props`, restore locked, retain warnings-as-errors and
  AOT/trim diagnostics. Native interop uses owned C ABI / LibraryImport, never a C++ ABI.
- Add SPDX headers to source/configuration; preserve third-party notices and source provenance.
- New projects are non-packable by default. Admit a package explicitly in `eng/packaging/packages.json`
  only when its behavior and dependency closure are verified. Never publish placeholders as capabilities.
- Keep build inputs declarative; executable packaging verification is the portable Python tool under `eng/`.
  Do not add tracked PowerShell or shell helper scripts.
- Record what actually ran. A successful package-policy smoke does not prove native capability AOT,
  product behavior, release signing or NuGet publication. Run the checks documented in the README.

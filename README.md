# ArcForges DesktopPlatform

Shared desktop mechanisms and native interoperability for ArcChat, ArcNotes, ArcScope and ArcSlate.
This repository owns the CMake/vcpkg toolchain, narrow C ABIs, C# wrappers and capability NuGet packages.
Product applications and services build independently from published packages.

## Current implementation

- Five native shim foundations: media, OpenTimelineIO, colour, image and macOS Metal. Their existing
  ABI/version/error probes are retained; full product capabilities are still implementation work.
- Shared C# mechanism and ContentSandbox scaffolds, explicitly excluded from NuGet publication.
- `ArcForges.Build.Policy`: portable C# build defaults and enforced central package-version rules.
- Platform-only managed and Windows IDE solutions, native ABI CI, package verification and NuGet OIDC CI.

See [extraction scope and evidence](docs/platform-bootstrap.md). The accepted product family design is
maintained in [ArcForges-Design](https://github.com/ArcForges/ArcForges-Design).

## Build and verify

Install the .NET SDK selected by `global.json` and Python 3.11 or newer. No Mobile/Web workloads are needed.

```powershell
dotnet restore DesktopPlatform.slnx --locked-mode
dotnet build DesktopPlatform.slnx -c Release --no-restore
dotnet test --project tests/ArchitectureTests/ArcForges.Tests.ArchitectureTests.csproj -c Release --no-build
python eng/packaging/packages.py pack --version 1.0.0-ci.1
python eng/packaging/packages.py smoke --directory artifacts/packages --version 1.0.0-ci.1
```

CMake 4.3.3, Ninja 1.13.1, sccache and a C++20 compiler are needed only for native producer builds.
Follow [native prerequisites and commands](deploy/README.md). `win.slnx` additionally builds the native
Windows projects and stages their DLLs for `NativeAbiTests`; CI uses the independent CMake path.

## Packages and Contracts

[Package publishing](eng/packaging/README.md) documents the release allowlist, candidate verification,
NuGet trusted-publisher setup and consumer examples. Only admitted packages are published; current
shared placeholders and native probes are not advertised as complete runtime packages.
Every push to `main`, including a merged PR, automatically allocates a prerelease version, builds and
verifies the candidate on Windows/Linux, then publishes the tested bytes to nuget.org through OIDC.
No manual workflow run, version entry or publish checkbox is required.

Contracts is a separate repository with handwritten proto as the business RPC authority. It also owns
schema validation, compatibility checks, generators and generated SDK packaging:

| Consumer | Published dependency |
|---|---|
| C# desktop / Cloud | `ArcForges.Contracts.*` NuGets: generated protobuf messages and gRPC stubs |
| TypeScript Web / Mobile | `@arcforges/proto`, `@arcforges/api-client`; Mobile also `@arcforges/rn-transport` |
| AI / Cloud internal integration | Separate internal schema/client package; never imported by public SDKs |

Consumers reference exact NuGet/npm versions and commit their locks. They neither clone Contracts nor
run its generators during ordinary builds. Contracts CI publishes both ecosystems from one reviewed
schema commit and records descriptor/package hashes. Compatible additive changes can roll out without
simultaneously updating every consumer; breaking changes require a new protocol major and migration.
There are no Git submodules. This extraction does not create or publish the separate Contracts repository.

## Licence

[AGPL-3.0-only](LICENSE). See [NOTICE.md](NOTICE.md) and the
[dependency register](docs/compliance/third-party-license-register.md) for attribution.

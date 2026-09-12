# NuGet package production

`packages.json` admits ten packages in one exact-version release set:

| Packages | Delivered content |
|---|---|
| `ArcForges.Build.Policy` | Portable build defaults and central-version/lock enforcement; no runtime dependencies |
| `ArcForges.Native.Abstractions` | Shared status, ABI version and error values; bounded error handling and native loader |
| `ArcForges.Native.Media`, `.Colour`, `.Image`, `.Otio` | Source-generated C# bindings for every existing entry point |
| Each capability's `.Runtime.win-x64` | Actual owned DLL, full non-system DLL closure, CRT, C headers, import library and provenance |

The four existing ABIs provide version, dependency build-information and thread-local error queries.
Media processing, image processing, timeline editing and GPU operations are not implemented by these
bindings. Shared placeholders, the internal ABI probe project and macOS Metal are excluded from this
Windows release. See [scope and validation evidence](../../docs/native-package-release.md).

## Local and PR candidates

Build/test/install both Windows CMake profiles and stage their audited native payload as described in
[native producer builds](../../deploy/README.md). Then run from this repository:

```powershell
dotnet restore DesktopPlatform.slnx --locked-mode
dotnet build DesktopPlatform.slnx -c Release --no-restore
dotnet test --project tests/ArchitectureTests/ArcForges.Tests.ArchitectureTests.csproj -c Release --no-build
python eng/packaging/packages.py pack --version 1.0.0-ci.local.1
python -m unittest discover -s eng/packaging -p 'test_*.py' -v
python eng/packaging/packages.py smoke --version 1.0.0-ci.local.1
python eng/packaging/native_consumer.py --version 1.0.0-ci.local.1
```

Use a new empty `--directory` for each subsequent candidate and pass it to verification/consumption;
use `--native-directory` when packing from an alternate staged payload. For guard tests set
`ARCFORGES_PACKAGE_DIRECTORY` to that candidate directory. The tools reject overwriting candidates.
Consumers retain temporary directories outside the repository for inspecting projects and lock files.

PR and main CI share one reusable gate, in this order:

1. Compile/test both native profiles, execute producer C# ABI tests, audit dependency/source closure
   and upload `native-stage-<run-id>-<producer-attempt>`. Source/secret checks run alongside native build.
2. After native and source gates succeed, download and hash-check that source commit's native artifact.
   Restore/build/test managed projects, pack the allowlist once, and verify content and negative fixtures.
3. Consume those exact packages in independent Windows/Linux Build.Policy projects. On Windows, also
   build/run JIT and Native AOT callers of each native package separately and all four together, link/run
   a C17 caller from packaged headers/import libraries, and reject wrong RID and missing/tampered DLLs.
4. The aggregate gate requires every job to succeed. Only the main workflow can then authenticate and
   upload the same candidate bytes. Failed or skipped prerequisites cannot reach publication.

CI records source commit/version/package SHA256 and native artifact digest in `manifest.json` and tests
those bytes. Consumers use an empty NuGet cache and source mapping forcing ArcForges
packages to the candidate feed. Their build/run and negative central-version/compiler/lock fixtures
must pass. CI retains the candidate as `nuget-candidate-<run-id>-<producer-attempt>` for 30 days.
The producer exports that exact artifact name to consumers and publication, so retrying a consumer
continues to use the original tested bytes and rebuilding in another attempt has a distinct artifact. These artifacts are
internal test inputs, not stable public feed availability. Local builds with uncommitted changes are
only development evidence; public candidates always come from a clean CI checkout.

## First-time nuget.org setup

Configure [NuGet trusted publishing](https://learn.microsoft.com/en-us/nuget/nuget-org/trusted-publishing)
using the NuGet account that owns the packages. No long-lived API key is needed.

| Setting | Value |
|---|---|
| Repository owner | `ArcForges` |
| Repository | `DesktopPlatform` |
| Workflow filename | `publish-nuget.yml` |
| Environment | `nuget` |
| Package scope | `ArcForges.*` (the repository allowlist limits this workflow to reviewed package IDs) |
| Permissions | Publish new packages and new versions |
| GitHub repository variable `NUGET_USER` | Your NuGet profile username, not email |

Create the GitHub `nuget` environment, restrict deployments to `main`, and leave required reviewers and
wait timers unset for unattended publication. The workflow independently rejects publication outside
pushes to this repository's main branch, rejects a missing or placeholder `NUGET_USER` before expensive
work, and requests `id-token: write` only in the publish job. PR candidate validation needs no NuGet
account. These account settings are external prerequisites; committing YAML does not configure them.

## Release

Every push to `ArcForges/DesktopPlatform` `main`, including a merged PR, automatically starts
**Publish NuGet**. There is no manual dispatch form, version input or publish checkbox. PRs, other
branches and tags do not publish; PR CI continues to produce and verify internal candidates.

The workflow allocates `1.0.0-ci.<workflow-run-number>.<run-attempt>` once before build, for example
`1.0.0-ci.3.1`, then `1.0.0-ci.4.1`. GitHub owns the counter; no version commit or tag is written back
to the repository. The counter continues from earlier runs of this workflow, and failed runs can leave
gaps. Re-running all jobs uses the new attempt suffix. Retrying only failed downstream jobs retains
the already allocated version and producer artifact. This remains a prerelease stream; changing the
`1.0.0` release line or stable-release policy requires changing the workflow through a reviewed PR.

Each main push runs independently with its own immutable version, so a later merge cannot cancel or
replace a pending publication. The run performs the complete gate above on the merged commit. Only after all candidate jobs
succeed does it obtain an OIDC credential and upload those exact `.nupkg` bytes. The summary records
the version and source commit. The account must own or be allowed to create each admitted package ID.
NuGet validation and indexing follow upload; a successful push does not mean search/restore is already
available. See [NuGet publication status](https://learn.microsoft.com/en-us/nuget/nuget-org/publish-a-package#package-validation-and-indexing).

Versions are immutable. `1.0.0-ci.1` cannot be renamed/promoted to `1.0.0`: the latter is a new candidate
and must run through all gates. Local builds and PR candidates never upload to the public feed.
Duplicate versions fail; there is deliberately no `--skip-duplicate`. NuGet cannot atomically publish
ten packages. If upload partially succeeds, inspect the registry and retained manifest and re-run all
jobs to allocate a new complete version; do not promote a partial release set or retry it blindly.
Retrying only failed consumers before upload keeps the original candidate. A bad published version is superseded by a new
version; consumers retain their prior exact version/lock until the upgrade is approved.

## Consume

After **all required package IDs** at the selected version are available on the feed, pin the version
shown in its successful run. Automatic producer publication never changes consumer pins or locks.
The example version below is illustrative, not a claim of public availability:

```xml
<!-- Directory.Packages.props -->
<Project>
  <PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally></PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="ArcForges.Build.Policy" Version="1.0.0-ci.10.1" />
    <PackageVersion Include="ArcForges.Native.Media" Version="1.0.0-ci.10.1" />
    <PackageVersion Include="ArcForges.Native.Media.Runtime.win-x64" Version="1.0.0-ci.10.1" />
  </ItemGroup>
</Project>
```

```xml
<!-- Consumer.csproj -->
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <RuntimeIdentifier>win-x64</RuntimeIdentifier>
    <PublishAot>true</PublishAot>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="ArcForges.Build.Policy" PrivateAssets="all" />
    <PackageReference Include="ArcForges.Native.Media" />
    <PackageReference Include="ArcForges.Native.Media.Runtime.win-x64" />
  </ItemGroup>
</Project>
```

```csharp
using ArcForges.Native.Media;
Console.WriteLine(MediaAbi.GetAbiVersion());
Console.WriteLine(MediaAbi.GetBuildInfo());
Console.WriteLine(MediaAbi.GetLastError());
```

The managed package pulls the exact same `Native.Abstractions` version; the RID package also requires
its exact managed version. Add equivalent pairs for Colour, Image or Otio as needed. Commit the lock
created by the first restore; CI restores with `--locked-mode`. Consumers do not build CMake/vcpkg.

The native loader validates the per-library app-local manifest and DLL hashes before using absolute
paths, with only DLL-directory dependencies and Windows system libraries allowed. Missing DLLs do not
fall back to PATH or the working directory. Keep all runtime files together when publishing. To replace
an upstream DLL with a compatible modified build, update its hashes in each affected app-local manifest;
there is no secret or vendor signature required by this check. The product installer owns application
directory write permissions, signing, upgrades and rollback. Source archives and recipes ship with the
Media runtime; every runtime includes its upstream notices and SPDX records, including static inputs.

Each owner commits `global.json` and package locks and restores locked in CI. Build policy is a direct,
private build dependency and never leaks as a transitive runtime dependency. Contracts publishes its own
NuGet and npm SDK packages; this repository does not duplicate that schema generation pipeline.

## Admit further capabilities

Add only implemented, verified packages with explicit metadata, version compatibility, licence/source
closure and a real isolated package consumer. Extend the validator and consumer proof with
that capability. Native capabilities require one explicit managed
package and matching per-RID runtime package, complete transitive native assets under `runtimes/<rid>/native`,
ABI/AOT evidence, and NOTICE/SBOM. New content-parsing APIs also require the relevant sandbox acceptance;
the existing metadata/error queries do not accept untrusted media. New RIDs need native producer and
real package consumer execution on those targets before admission.

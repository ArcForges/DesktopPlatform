# NuGet package production

`packages.json` is the explicit publication allowlist. Its current sole entry is
`ArcForges.Build.Policy`; it ships portable `.props`/`.targets`, README, AGPL licence and NOTICE.
Its dependency closure is empty: no C# runtime, native binary or product code.
Shared placeholders and internal ABI probes have `IsPackable=false` and are not release capabilities.

## Local and PR candidates

After locked restore, run `python eng/packaging/packages.py pack --version 1.0.0-ci.1`, then
`python eng/packaging/packages.py smoke --version 1.0.0-ci.1`. Use a different empty `--directory`
for each subsequent local candidate. The tool rejects overwriting an existing candidate.
The smoke retains a temporary directory outside the repository for inspecting logs and lock files.

PR CI builds and packs once, records source commit/version/package SHA256 in `manifest.json`, and tests
those bytes on Windows and Linux. Consumers use an empty NuGet cache and source mapping forcing ArcForges
packages to the candidate feed. Their build/run and negative central-version/compiler/lock fixtures
must pass. CI retains the candidate as the `nuget-candidate` artifact for 30 days. These artifacts are
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
| Package scope | `ArcForges.Build.Policy` (expand only with reviewed package admission) |
| Permissions | Publish new packages and new versions |
| GitHub repository variable `NUGET_USER` | `YOUR_NUGET_USERNAME` placeholder; replace with your NuGet profile username, not email |

Create the GitHub `nuget` environment and restrict deployments to `main`. Maintainers can also configure
required reviewers. The workflow independently rejects public publication outside this repository's main
branch, checks `NUGET_USER` before expensive work, and requests `id-token: write` only in the publish job.
The workflow currently falls back to `YOUR_NUGET_USERNAME`, as requested. Dry-run validation needs no
NuGet account; actual publication explicitly rejects this placeholder. These account settings are external
prerequisites; committing YAML does not configure a NuGet account.

## Release

Run **Publish NuGet** from GitHub Actions on `main`. Set an exact version and keep `publish=false` to
exercise the full candidate flow without publishing. Set `publish=true` for an actual publication.
The same run builds/tests the allocated version, verifies its manifest again, obtains a temporary OIDC
credential and pushes the same `.nupkg` bytes. The account must own or be allowed to create the package ID.

Versions are immutable. `1.0.0-ci.1` cannot be renamed/promoted to `1.0.0`: the latter is a new candidate
and must run through all gates. No automatic push occurs on PRs, branch pushes, tags or ordinary builds.
Duplicate versions fail; there is deliberately no `--skip-duplicate`. If publication partially succeeds,
inspect the registry and retained manifest before retrying; never rebuild different bytes under that version.
If a release has to be rebuilt, allocate a new version. A bad published version is superseded by a new
version; consumers retain their prior exact version/lock until the upgrade is approved.

## Consume

After the selected version actually exists on the feed:

```xml
<!-- Directory.Packages.props -->
<Project>
  <PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally></PropertyGroup>
  <ItemGroup><PackageVersion Include="ArcForges.Build.Policy" Version="1.0.0" /></ItemGroup>
</Project>
```

```xml
<!-- Consumer.csproj -->
<ItemGroup><PackageReference Include="ArcForges.Build.Policy" PrivateAssets="all" /></ItemGroup>
```

Each owner commits `global.json` and package locks and restores locked in CI. Build policy is a direct,
private build dependency and never leaks as a transitive runtime dependency. Contracts publishes its own
NuGet and npm SDK packages; this repository does not duplicate that schema generation pipeline.

## Admit further capabilities

Add only implemented, verified packages with explicit metadata, version compatibility, licence/source
closure and a real isolated package consumer. Extend the package-kind validator and consumer proof with
that capability rather than bypassing them. Native capabilities additionally require one explicit managed
package and matching per-RID runtime package, complete transitive native assets under `runtimes/<rid>/native`,
ABI/AOT/sandbox evidence, and NOTICE/SBOM. Existing native CMake/ABI tests are producer foundations; this
bootstrap does not publish native probes as finished capabilities or claim those later gates passed.

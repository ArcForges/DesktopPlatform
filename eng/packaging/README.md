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
| Package scope | `ArcForges.Build.Policy` (expand only with reviewed package admission) |
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
replace a pending publication. The run builds and packs the merged commit, verifies the manifest and
tests the same package bytes in isolated Windows and Linux consumers. Only after all candidate jobs
succeed does it obtain an OIDC credential and upload those exact `.nupkg` bytes. The summary records
the version and source commit. The account must own or be allowed to create each admitted package ID.
NuGet validation and indexing follow upload; a successful push does not mean search/restore is already
available. See [NuGet publication status](https://learn.microsoft.com/en-us/nuget/nuget-org/publish-a-package#package-validation-and-indexing).

Versions are immutable. `1.0.0-ci.1` cannot be renamed/promoted to `1.0.0`: the latter is a new candidate
and must run through all gates. Local builds and PR candidates never upload to the public feed.
Duplicate versions fail; there is deliberately no `--skip-duplicate`. If publication partially succeeds,
inspect the registry and retained manifest before retrying; never rebuild different bytes under that version.
If a release has to be rebuilt, allocate a new version. A bad published version is superseded by a new
version; consumers retain their prior exact version/lock until the upgrade is approved.

## Consume

After the selected version actually exists on the feed, pin the version shown in its successful run
(the version below is an example). Automatic producer publication never changes consumer pins or locks:

```xml
<!-- Directory.Packages.props -->
<Project>
  <PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally></PropertyGroup>
  <ItemGroup><PackageVersion Include="ArcForges.Build.Policy" Version="1.0.0-ci.2.1" /></ItemGroup>
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

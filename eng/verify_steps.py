# SPDX-License-Identifier: AGPL-3.0-only
"""Local verification steps of DesktopPlatform, loaded by eng/verify.py (which injects `Step`).

The full profile is every job of .github/workflows/pr-gate.yml with its called native-abi.yml and
package-validation.yml (the PR gate, which is also the publication candidate), on this workstation, each on the host
the hosted job used:
- lane `win` (Windows, in <main checkout>/.worktree/_verify): the `native-win-x64` job (`native`: the IDE licence
  evaluation, vcpkg install of the pinned ports from the existing C:\\vcpkg into the checkout's installed root, the
  shim-static CMake preset with sccache in the reviewed MSVC toolset's developer environment, CTest, the NativeAbi
  layout tests and the sccache proof; `native-stage`: the audited native runtime packages), after the locked restore
  the NativeAbi tests need; then the win-x64 Native AOT compile probes of `package-validation.yml`.
- lane `wsl` (WSL Debian, in ~/.cache/arcforges-verify/DesktopPlatform): the clone identity, the `licence-policy`,
  `runtime-policy` and `reconciliation-policy` jobs, then the `pack` job up to its tests (locked restore, format,
  accounting unittest, Release build, every test suite but the architecture gate and the timing-sensitive LocalRpc
  suite, four test projects at a time), then the linux-x64 Native AOT compile probes. Everything that runs dotnet in the clone is in this lane: concurrent restores or builds of shared
  projects in one checkout would race.
- lane `wsl-policy`: the Python-only jobs that read neither the clone identity nor build outputs: `design-policy`,
  `reference-policy`, `provenance-policy`, `stage-integration` and `repository-hooks`.
- lane `scan`: the secret scan (pinned gitleaks image digest, .gitleaks.toml) over the pushed range ({range}), in WSL
  Docker without network and with a read-only mount of the clone; `actionlint` only when .github/workflows/** changed.
- after every lane (the exclusive phase is the only point after both hosts' lanes): the LocalRpc suite alone (a 400 ms
  stream lifetime and a fixed 500 ms settle window; one of its tests failed under the concurrent native build and
  passed alone), the hand-off of the native stage
  and its licence evidence from Windows into the clone (hosted: artifacts `native-stage-*` and
  `native-licence-policy-*`), then the rest of `pack`: the architecture gate, invariant accounting and the reason
  registry; the pack itself; the packaging unittest against the packed candidate.

Differences from the hosted jobs (eng/verify_local.py names each where it happens):
- GitHub run identity: the candidate version is 1.0.0-ci.1.1 and accounting uses run 1, attempt 1 (hosted: the run id
  and attempt); `allocate-version` is the same `packages.py version` check of that version.
- Artifacts are not uploaded; the native hand-off is a copy between the two verification checkouts at the same commit.
- The secret scan covers the pushed range, not the full history: history before it was scanned when it was pushed.
  The hosted secret-scan receipt (RP-09) cannot be produced locally by design, so the architecture gate accepts that
  one finding and nothing else; `architecture_evidence.py secret` is not run.
- Not reproduced: GitHub dependency review (a GitHub service; external PRs keep it; locked restores with NuGet audit
  cover vulnerable packages locally) and CodeQL (deep-check.yml's weekly schedule, unchanged).
- The clone has the identity of a checkout of ArcForges/DesktopPlatform (`clone-identity`): its `origin` URL, which the
  runtime-ownership and reconciliation checks require, and `origin/main` at the merge base, which the provenance audits
  of `native.py stage` and `packages.py pack` compare against (hosted: the checkout and the PR base). Nothing is fetched
  from that URL. The provenance step passes the merge base as `--base` (hosted: the PR base from the event).
- vcpkg binary caching uses the user's default archive cache (hosted: actions/cache), sccache the user's default cache
  through a server on a port of its own that the step stops; vcpkg is the existing C:\\vcpkg at the pinned commit
  (Env.md section 6).
- `CI` and `GITHUB_ACTIONS` are not set: with them the build identity and evidence scripts require a GitHub run.
Every change runs the full profile: the provenance, runtime-ownership and reconciliation inventories cover every
tracked file, Markdown included, and the design policy verifies the generated documents.
"""

import os

REPOSITORY = "DesktopPlatform"
RID_WIN, RID_LINUX = "win-x64", "linux-x64"

_VSWHERE = os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"),
                        "Microsoft Visual Studio", "Installer", "vswhere.exe")
_VCPKG = os.environ.get("VCPKG_ROOT") or "C:\\vcpkg"

# Tool versions that key a reusable pass (the python running eng/verify.py is added by the core).
FINGERPRINT = {
    "win": {
        "dotnet-sdks": ["dotnet", "--list-sdks"],
        "dotnet-runtimes": ["dotnet", "--list-runtimes"],
        "visual-studio": [_VSWHERE, "-latest", "-products", "*", "-requires",
                          "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationVersion"],
        "cmake": ["cmake", "--version"],
        "ninja": ["ninja", "--version"],
        "sccache": ["sccache", "--version"],
        "vcpkg": ["git", "-C", _VCPKG, "rev-parse", "HEAD"],
        "python": ["python", "--version"],
    },
    "wsl": {
        "dotnet-sdks": "dotnet --list-sdks | tr '\\n' ' '",
        "dotnet-runtimes": "dotnet --list-runtimes | tr '\\n' ' '",
        "clang": "clang --version | head -n 1",
        "cmake": "cmake --version | head -n 1",
        "python": "python --version",
    },
}

# The environment of the hosted workflows, without CI=true (see above).
ENV = {"DOTNET_NOLOGO": "true", "DOTNET_CLI_TELEMETRY_OPTOUT": "true", "TESTINGPLATFORM_TELEMETRY_OPTOUT": "1"}

# Timeouts are five to ten times the durations measured on this workstation (18 logical processors, all lanes
# concurrently), with a floor of five minutes; the native step's allows a cold vcpkg build of the pinned ports.

# Test projects that eng/verify_local.py managed-tests runs concurrently. Measured on the 15 projects in WSL (18 logical
# processors, warm, no other lane): 60-61 s one at a time, 22-23 s with 4, 18 s with 8; 4 leaves the processors to the
# concurrent Windows lane for 4 s more.
TEST_JOBS = 4

# The AOT compile probes of package-validation.yml: (step suffix, project, RIDs).
AOT_PROBES = [
    ("local-rpc", "tests/LocalRpcAotTests/LocalRpcAotTests.csproj", (RID_LINUX, RID_WIN)),
    ("local-rpc-service", "tests/LocalRpcServiceAotTests/LocalRpcServiceAotTests.csproj", (RID_LINUX, RID_WIN)),
    ("secrets", "tests/SecretStoreSelectionAotTests/SecretStoreSelectionAotTests.csproj", (RID_LINUX, RID_WIN)),
    ("content-sandbox", "src/DesktopHelpers/ArcForges.ContentSandbox/ArcForges.ContentSandbox.csproj", (RID_LINUX, RID_WIN)),
    ("grpc-web", "tests/ReleaseArtifactTests/GrpcWeb/GrpcWebAotProbe.csproj", (RID_LINUX, RID_WIN)),
    ("tableview", "eng/verification/probe-evidence/Prf09.TableViewProbe.csproj", (RID_WIN,)),
    ("realtime", "tests/ReleaseArtifactTests/Realtime/RealtimeAotProbe.csproj", (RID_LINUX, RID_WIN)),
]

# pr-gate.yml's secret scan (same pinned image digest, config and redaction), over the pushed range, without network
# and with a read-only mount of the verification clone.
SECRET_SCAN = (
    "docker run --rm --network none -v \"$PWD:/repo:ro\" "
    "-e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/repo "
    "ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f "
    "git /repo --redact --no-banner --verbose --config /repo/.gitleaks.toml "
    "--log-opts=\"--full-history {range}\""
)

# actionlint as pinned in the product repositories' CI, cached once in WSL; the archive is checked on every run.
# actionlint 1.7.12 does not know the concurrency `queue` key of publish-nuget.yml, which GitHub accepts (the
# publication runs on every main push), so that one message is ignored.
ACTIONLINT = (
    "set -euo pipefail; v=1.7.12; "
    "sum=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8; "
    "d=\"$HOME/.cache/arcforges-verify/tools\"; t=\"$d/actionlint_${v}_linux_amd64.tar.gz\"; mkdir -p \"$d\"; "
    "if [ ! -f \"$t\" ]; then "
    "curl --fail --silent --show-error --location --output \"$t.part\" "
    "\"https://github.com/rhysd/actionlint/releases/download/v${v}/actionlint_${v}_linux_amd64.tar.gz\"; "
    "echo \"$sum  $t.part\" | sha256sum --check --quiet; mv \"$t.part\" \"$t\"; fi; "
    "echo \"$sum  $t\" | sha256sum --check --quiet; "
    "mkdir -p \"$d/actionlint-$v\"; tar -xzf \"$t\" -C \"$d/actionlint-$v\" actionlint; "
    "\"$d/actionlint-$v/actionlint\" -ignore 'unexpected key \"queue\" for \"concurrency\" section'"
)


def select_profile(changed: list[str]) -> str:
    return "full"


def workflows_changed(changed: list[str]) -> bool:
    return any(path.startswith(".github/workflows/") for path in changed)


def pwsh(script: str) -> list[str]:
    return ["pwsh", "-NoProfile", "-NonInteractive", "-Command",
            "$ErrorActionPreference = 'Stop'; " + script + "; exit $LASTEXITCODE"]


def win(step_id: str, cmd: list[str], timeout: int, **options) -> Step:
    return Step(step_id, "win", cmd, timeout=timeout, env=ENV, **options)


def wsl(step_id: str, cmd: str, timeout: int, **options) -> Step:
    return Step(step_id, "wsl", cmd, timeout=timeout, env=ENV, **options)


def unittest(pattern: str, directory: str = "eng") -> str:
    return f"python -m unittest discover -s {directory} -p '{pattern}' -v"


# The Native AOT linker locates MSVC through vswhere, which hosted Windows runners have on PATH.
VSWHERE_ON_PATH = "$env:PATH = (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\\Installer') + ';' + $env:PATH; "


def aot_win(name: str, project: str) -> Step:
    return win(f"win-aot-{name}", pwsh(
        VSWHERE_ON_PATH + f"dotnet restore {project} --locked-mode; if ($LASTEXITCODE) {{ exit $LASTEXITCODE }}; "
        f"dotnet publish {project} -c Release -r {RID_WIN} --no-restore"), 900)


def aot_linux(name: str, project: str) -> Step:
    return wsl(f"wsl-aot-{name}", f"set -e; dotnet restore {project} --locked-mode; "
               f"dotnet publish {project} -c Release -r {RID_LINUX} --no-restore", 900)


VERSION_PROPERTIES = "-p:PackageVersion=1.0.0-ci.1.1 -p:Version=1.0.0-ci.1.1"  # eng/verify_local.py VERSION

STEPS = [
    # native-abi.yml, native-win-x64 (the restore is the job's `dotnet restore DesktopPlatform.slnx --locked-mode`)
    win("win-restore", ["dotnet", "restore", "DesktopPlatform.slnx", "--locked-mode"], 600),
    win("win-native", ["python", "eng/verify_local.py", "native"], 5400),
    win("win-native-stage", ["python", "eng/verify_local.py", "stage"], 600),
    # package-validation.yml, the win-x64 Native AOT compile probes
    *[aot_win(name, project) for name, project, rids in AOT_PROBES if RID_WIN in rids],
    # pr-gate.yml licence-policy, runtime-policy and reconciliation-policy; package-validation.yml pack, up to its tests
    wsl("clone-identity", "set -e; git config remote.origin.url https://github.com/ArcForges/DesktopPlatform.git; "
        "git update-ref refs/remotes/origin/main {base}", 60),
    wsl("wsl-restore", "dotnet restore DesktopPlatform.slnx --locked-mode", 600),
    wsl("licence-policy", "set -e; python eng/dependency_policy.py; " + unittest("test_dependency_policy.py") + "; "
        + unittest("test_desktop_rids.py") + "; " + unittest("test_licence_boundary.py") + "; "
        "python eng/licence_boundary.py --evaluate-managed --report artifacts/evidence/licence-managed.json", 900),
    wsl("runtime-policy", "set -e; " + unittest("test_runtime_ownership.py") + "; "
        "python eng/runtime_ownership.py --evaluate-managed --naming-assets artifacts/naming-assets; "
        + unittest("test_architecture_evidence.py") + "; "
        "python eng/architecture_evidence.py naming --runtime-report artifacts/evidence/runtime-ownership.json "
        "--assets artifacts/naming-assets --output artifacts/evidence/naming-architecture.json", 900),
    wsl("reconciliation-policy", "set -e; " + unittest("test_reconciliation.py") + "; python eng/reconciliation.py", 900),
    wsl("format", "dotnet format DesktopPlatform.slnx --verify-no-changes --no-restore", 900),
    wsl("accounting-tests", unittest("test_*.py", "eng/accounting"), 300),
    wsl("wsl-build", "dotnet build DesktopPlatform.slnx -c Release --no-restore -p:EmitCompilerGeneratedFiles=true "
        + VERSION_PROPERTIES, 1200),
    wsl("managed-tests", f"python eng/verify_local.py managed-tests --jobs {TEST_JOBS}", 1800),
    # package-validation.yml, the linux-x64 Native AOT compile probes
    *[aot_linux(name, project) for name, project, rids in AOT_PROBES if RID_LINUX in rids],
    # pr-gate.yml design-policy, reference-policy, provenance-policy, stage-integration and repository-hooks
    wsl("design-policy", "set -e; " + unittest("test_design_policy.py") + "; " + unittest("test_build_identity.py")
        + "; python eng/design_policy.py", 600, lane="wsl-policy"),
    wsl("reference-policy", "set -e; " + unittest("test_reference_baselines.py") + "; python eng/reference_baselines.py",
        900, lane="wsl-policy"),
    wsl("provenance-policy", "set -e; " + unittest("test_*.py", "tests/tooling")
        + "; python eng/check_provenance.py --owner DesktopPlatform --base {base}; python eng/native_provenance.py",
        600, lane="wsl-policy"),
    wsl("stage-integration", "set -e; " + unittest("test_*.py", "eng/stage_integration")
        + "; python eng/stage_integration/stage_integration.py verify --report artifacts/evidence/stage-integration.json",
        600, lane="wsl-policy"),
    wsl("repository-hooks", "python eng/verify_local.py hooks", 900, lane="wsl-policy"),
    # pr-gate.yml secret-scan (over the pushed range) and actionlint (when a workflow changed)
    wsl("secret-scan", SECRET_SCAN, 600, lane="scan"),
    wsl("actionlint", ACTIONLINT, 300, lane="actionlint", when=workflows_changed),
    # After every lane: the timing-sensitive test projects alone, the native hand-off, then the rest of pack
    wsl("timing-sensitive-tests", "python eng/verify_local.py managed-tests --timing-sensitive", 900, exclusive=True),
    win("native-handoff", ["python", "eng/verify_local.py", "handoff", "{sha}"], 600, exclusive=True),
    wsl("architecture-gate", "python eng/verify_local.py architecture", 900, exclusive=True),
    wsl("pack", "python eng/verify_local.py pack", 1200, exclusive=True),
    wsl("packaging-tests", unittest("test_*.py", "eng/packaging"), 600, exclusive=True),
]

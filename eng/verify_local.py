#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""The multi-command steps of the local pre-push verification (eng/verify_steps.py), each the local form of a hosted
job of .github/workflows/pr-gate.yml, native-abi.yml or package-validation.yml (keep them in step):

  python eng/verify_local.py native          Windows: native-abi.yml `native-win-x64` from vcpkg install to the NativeAbi tests
  python eng/verify_local.py stage           Windows: native-abi.yml, stage the audited native runtime packages
  python eng/verify_local.py naming          Windows: the `runtime-policy` naming evidence that `pack` binds
  python eng/verify_local.py managed-tests   both: the test suites of `pack` "Build and test" (Windows) and of
                                             `linux-platform` (Linux), which runs this command itself
  python eng/verify_local.py architecture    Windows: `pack`, the architecture gate, invariant accounting and reason registry
  python eng/verify_local.py pack            Windows: `pack`, the version check and "Pack explicit release allowlist"
  python eng/verify_local.py packaging-tests Windows: `pack`, "Verify rejection of invalid versions and altered candidates"
  python eng/verify_local.py hooks           Linux: pr-gate.yml `repository-hooks` (hash-pinned pre-commit closure)

Only the GitHub-bound parts differ, each named where it happens: run ids and artifacts have local equivalents (the local
identity RUN/ATTEMPT below, and the same files produced on the leg's own machine where a hosted job downloads another
job's artifact), and the hosted secret-scan receipt (RP-09) cannot be produced locally by design
(eng/architecture_evidence.py refuses local RP-09 evidence), so the architecture gate accepts exactly that one finding
and nothing else; the secret scan itself runs in the hook. Nothing is carried between the two legs' machines.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUN, ATTEMPT = "1", "1"  # the local CI identity: hosted runs use GITHUB_RUN_ID and GITHUB_RUN_ATTEMPT
VERSION = f"1.0.0-ci.{RUN}.{ATTEMPT}"  # pr-gate.yml allocates 1.0.0-ci.<run id>.<attempt> for a PR
RESULTS = ROOT / "artifacts/evidence/test-results"
WORKFLOW = ROOT / ".github/workflows/package-validation.yml"
# Where `pack` reads the native licence evidence: native-abi.yml uploads artifacts/evidence/licence-ide.json and
# artifacts/cmake/**/licence-boundary.json as `native-licence-policy-*`, which `pack` downloads here.
NATIVE_EVIDENCE = ROOT / "artifacts/evidence/native-architecture"
PORTS = ["opencolorio[core]", "openimageio[core]", "openexr[core]", "imath[core]"]
TRIPLET = "x64-windows-static-md"
PRESET = "win-x64-shim-static"
CTEST = r"^(arc_native_abi_c17_layout_tests|arc_native_abi_cpp20_tests|arcslate_image_abi\.hello|arcslate_image_abi\.codec\.[a-z0-9_]+)$"
SCCACHE_PORT = "4229"  # a server of its own, so a developer's sccache server is never reused or stopped
ARCHITECTURE = ("architecture-tests", "tests/ArchitectureTests/ArcForges.Tests.ArchitectureTests.csproj")
# The one architecture finding a local run produces by design (see the module docstring).
LOCAL_RP09 = {"Rule": "RP-09", "Path": "", "Message": "Missing, stale or failing canonical naming/secret gate evidence.",
              "Line": 0}
# Test projects with timing-sensitive tests (a 400 ms stream lifetime, a fixed 500 ms settle window): they run alone, after
# every lane (measured: under the concurrent native build the flow-control test failed; alone it passed 5 of 5).
TIMING_SENSITIVE = ("src/BuildingBlocks/ArcForges.LocalRpc/Tests/ArcForges.LocalRpc.Tests.csproj",)
ARCHITECTURE_FACT = "ArcForges.Tests.ArchitectureTests.EvaluatedPolicyTests.ActualDesktopProjectsSatisfyTheSharedArchitecturePolicy"
# The opt-in of the OS secret-store integration tier (ArcForges-Design 16-testing-strategy section 1). Every suite started here is a
# routine suite, so it never inherits the opt-in: a stray value is removed for each child (eng/verify_steps.py also refuses it).
OS_SECRET_STORE_OPT_IN = "ARCFORGES_OS_SECRET_STORE_TESTS"


class Failure(Exception):
    pass


def routine_env(env: dict[str, str] | None = None) -> dict[str, str]:
    """The environment for a routine child (`env`, or this process's): the same, without the OS secret-store tier's opt-in."""
    result = dict(os.environ if env is None else env)
    result.pop(OS_SECRET_STORE_OPT_IN, None)
    return result


def run(argv: list[str], env: dict[str, str] | None = None, cwd: Path = ROOT, capture: bool = False) -> str:
    print("+ " + " ".join(argv), flush=True)
    result = subprocess.run(argv, cwd=cwd, env=routine_env(env), text=True, encoding="utf-8", errors="replace",
                            stdout=subprocess.PIPE if capture else None, stderr=subprocess.STDOUT if capture else None)
    if capture:
        print(result.stdout, end="", flush=True)
    if result.returncode != 0:
        raise Failure(f"{Path(argv[0]).name} {argv[1] if len(argv) > 1 else ''} failed with exit code {result.returncode}.")
    return result.stdout if capture else ""


# ------------------------------------------------------------------------------------------------------------ Windows

def visual_studio() -> Path:
    vswhere = Path(os.environ["ProgramFiles(x86)"]) / "Microsoft Visual Studio/Installer/vswhere.exe"
    path = subprocess.check_output([str(vswhere), "-latest", "-products", "*", "-requires",
                                    "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"],
                                   text=True).strip()
    if not path:
        raise Failure("Visual Studio with the MSVC x64 tools was not found.")
    return Path(path)


def vcpkg_root() -> Path:
    root = Path(os.environ.get("VCPKG_ROOT") or "C:/vcpkg")
    sys.path.insert(0, str(ROOT / "eng/packaging"))
    import native  # noqa: PLC0415 - the pinned commit lives in the staging tool
    actual = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    if actual != native.VCPKG_COMMIT:
        raise Failure(f"{root} is at {actual}; the native stage requires the pinned vcpkg {native.VCPKG_COMMIT}. "
                      "Never change the shared vcpkg checkout to pass this check (Env.md section 6); ask the user.")
    return root


def developer_environment(toolset: str, vcpkg: Path) -> dict[str, str]:
    """vcvars64 for the reviewed MSVC toolset, as the hosted step's `call vcvars64.bat -vcvars_ver=`. The pinned vcpkg
    and the dotnet selected before (the user-local SDK root of global.json) are put back, as the hosted step does."""
    script = visual_studio() / "VC/Auxiliary/Build/vcvars64.bat"
    output = subprocess.run(f'cmd /d /s /c ""{script}" -vcvars_ver={toolset} >nul && set"', capture_output=True,
                            text=True, shell=False)
    if output.returncode != 0:
        raise Failure(f"vcvars64 -vcvars_ver={toolset} failed: {output.stdout[-2000:]}{output.stderr[-2000:]}")
    env = dict(line.split("=", 1) for line in output.stdout.splitlines() if "=" in line and not line.startswith("="))
    dotnet = shutil.which("dotnet")
    if dotnet:
        env["PATH"] = str(Path(dotnet).parent) + os.pathsep + env.get("PATH", env.get("Path", ""))
        env.pop("Path", None)
    env["VCPKG_ROOT"] = str(vcpkg)
    env["SCCACHE_SERVER_PORT"] = SCCACHE_PORT
    env.setdefault("ARCFORGES_VERIFY", "1")
    return env


def vcpkg_toolchain(expected: str) -> dict[str, str]:
    """The environment for native.py when vcpkg built the ports with a CMake other than the reviewed one (the profile's
    vcpkgCMake; hosted CI puts exactly that version first on PATH). Env.md section 6: the existing vcpkg is used as it is and a
    local version difference is not a build failure, so the local verification passes that one version, read from the ports'
    build records, as ARCFORGES_LOCAL_NATIVE_TOOLCHAIN; native.py records it in the stage's SBOM, and every other check stays."""
    found: dict[str, list[str]] = {}
    for info in sorted((ROOT / "artifacts/vcpkg-installed").glob("*/share/*/vcpkg_abi_info.txt")):
        for line in info.read_text(encoding="utf-8").splitlines():
            if line.startswith("cmake "):
                found.setdefault(line.split(" ", 1)[1], []).append(info.parent.name)
    if not found:
        raise Failure("the native dependencies have no vcpkg build records; `native` did not install them")
    if len(found) != 1:
        raise Failure(f"vcpkg built the native dependencies with several CMake versions: {found}")
    version = next(iter(found))
    if version == expected:
        return {}
    print(f"local toolchain: vcpkg built the native dependencies with CMake {version} (reviewed: {expected}); "
          "the stage records it and is local verification evidence only", flush=True)
    return {"ARCFORGES_LOCAL_NATIVE_TOOLCHAIN": f"vcpkgCMake={version}"}


def staged_toolchain() -> dict[str, str]:
    """The allowance this leg's native stage was produced with (its SBOMs' localToolchain), for the steps that verify it."""
    recorded = {json.dumps(json.loads(path.read_text(encoding="utf-8")).get("localToolchain"), sort_keys=True)
                for path in (ROOT / "artifacts/native-packages").glob("*/sbom.json")}
    if not recorded:
        raise Failure("artifacts/native-packages has no native stage; `win-native-stage` did not complete")
    if len(recorded) != 1:
        raise Failure(f"the native stage packages record different toolchains: {recorded}")
    local = json.loads(next(iter(recorded)))
    if local is None:
        return {}
    print(f"local toolchain: the native stage was built with vcpkg CMake {local['vcpkgCMake']} (local verification only)", flush=True)
    return {"ARCFORGES_LOCAL_NATIVE_TOOLCHAIN": f"vcpkgCMake={local['vcpkgCMake']}"}


def sccache_stats(env: dict[str, str]) -> str:
    return run(["sccache", "--show-stats"], env=env, capture=True)


def command_native(_: argparse.Namespace) -> None:
    vcpkg = vcpkg_root()
    run(["python", "eng/licence_boundary.py", "--evaluate-ide", "--report", "artifacts/evidence/licence-ide.json"])
    profile = json.loads((ROOT / "eng/provenance/artifact-profiles/native-win-x64-r4.json").read_text(encoding="utf-8"))
    toolset = profile["buildTools"]["msvcToolset"]
    # "Install native dependencies": classic mode into the checkout's installed root; the binary cache is the user's
    # default vcpkg archive cache (hosted CI restores its own with actions/cache).
    run([str(vcpkg / "vcpkg.exe"), "install", *[f"{port}:{TRIPLET}" for port in PORTS],
         f"--x-install-root={ROOT / 'artifacts/vcpkg-installed'}",
         f"--overlay-triplets={ROOT / 'eng/native/vcpkg/triplets'}"])
    vcpkg_toolchain(profile["buildTools"]["vcpkgCMake"])
    env = developer_environment(toolset, vcpkg)
    run(["sccache", "--start-server"], env=env)
    try:
        run(["sccache", "--zero-stats"], env=env)
        # A fresh configure, as on a hosted runner: re-applying the preset to an existing cache leaves the compiler
        # entry at its preset value `cl`, which native.py stage rejects as an unreviewed compiler. The build directory's
        # objects stay, so Ninja and sccache still rebuild only what changed.
        run(["cmake", "--preset", PRESET, "--fresh"], env=env)
        build = run(["cmake", "--build", "--preset", PRESET], env=env, capture=True)
        run(["cmake", "--install", f"artifacts/cmake/win-x64/{PRESET.removeprefix('win-x64-')}"], env=env)
        run(["ctest", "--test-dir", f"artifacts/cmake/win-x64/{PRESET.removeprefix('win-x64-')}", "--output-on-failure",
             "-R", CTEST], env=env)
        run(["dotnet", "test", "--project", "tests/NativeAbiTests/ArcForges.Tests.NativeAbiTests.csproj",
             "--filter", "Category=NativeAbiLayout", "--no-restore"], env=env)
        # "Prove sccache actually cached": the launcher must be consulted and every compilation cacheable. An
        # incremental build that compiles nothing (Ninja ran no "Building C/CXX object" edge) makes no compile request.
        stats = sccache_stats(env)
        requests = int(re.search(r"Compile requests\s+(\d+)", stats).group(1))
        non_cacheable = int(re.search(r"Non-cacheable compilations\s+(\d+)", stats).group(1))
        compiled = len(re.findall(r"Building CX?X? object", build))
        if requests <= 0 and compiled:
            raise Failure("sccache saw no compile requests; the launcher is not wired up.")
        if non_cacheable > 0:
            raise Failure(f"sccache reported {non_cacheable} non-cacheable compilations; debug information must stay Embedded.")
        print(f"sccache: {requests} compile requests for {compiled} compiled objects, 0 non-cacheable.", flush=True)
    finally:
        subprocess.run(["sccache", "--stop-server"], env=env, capture_output=True)


def command_stage(_: argparse.Namespace) -> None:
    vcpkg = vcpkg_root()
    profile = json.loads((ROOT / "eng/provenance/artifact-profiles/native-win-x64-r4.json").read_text(encoding="utf-8"))
    env = dict(os.environ, **vcpkg_toolchain(profile["buildTools"]["vcpkgCMake"]))
    # native.py refuses an existing stage (hosted CI starts from an empty checkout); the previous commit's is removed.
    shutil.rmtree(ROOT / "artifacts/native-packages", ignore_errors=True)
    run(["python", "eng/packaging/native.py", "stage", "--vcpkg-root", str(vcpkg)], env=env)


def command_naming(_: argparse.Namespace) -> None:
    """The naming evidence that `pack` binds (RP-01, RP-08): the hosted `runtime-policy` job evaluates it and `pack`
    downloads its artifact; the Windows leg evaluates it itself with the same two commands, for this commit. The Linux
    leg still runs the whole `runtime-policy` job."""
    run(["python", "eng/runtime_ownership.py", "--evaluate-managed", "--naming-assets", "artifacts/naming-assets"])
    run(["python", "eng/architecture_evidence.py", "naming", "--runtime-report", "artifacts/evidence/runtime-ownership.json",
         "--assets", "artifacts/naming-assets", "--output", "artifacts/evidence/naming-architecture.json"])


def native_evidence() -> list[str]:
    """Puts the native licence evidence of `native` where `pack` reads it, as the download of `native-licence-policy-*`
    lays it out (upload-artifact keeps the paths below their common directory, artifacts/): evidence/licence-ide.json and
    cmake/<preset>/licence-boundary.json. The files are this leg's own, so nothing is carried between machines; a
    missing report, or one of another commit (or a dirty IDE evaluation), fails here instead of in the gate."""
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    ide = ROOT / "artifacts/evidence/licence-ide.json"
    reports = sorted((ROOT / "artifacts/cmake").rglob("licence-boundary.json"))
    if not ide.is_file() or not reports:
        raise Failure("the native licence evidence is missing; `win-native` did not complete")
    rows = json.loads(ide.read_text(encoding="utf-8")).get("repositories") or [{}]
    if [(row.get("repository"), row.get("commit"), row.get("dirty")) for row in rows] != [("DesktopPlatform", head, False)]:
        raise Failure(f"artifacts/evidence/licence-ide.json is not the clean IDE licence evaluation of {head}: "
                      f"{[(row.get('repository'), row.get('commit'), row.get('dirty')) for row in rows]}")
    for report in reports:
        commit = json.loads(report.read_text(encoding="utf-8")).get("commit")
        if commit != head:
            raise Failure(f"{report.relative_to(ROOT).as_posix()} is the configure receipt of {commit}, not {head}")
    shutil.rmtree(NATIVE_EVIDENCE, ignore_errors=True)
    copied = []
    for source in [ide, *reports]:
        relative = source.relative_to(ROOT / "artifacts").as_posix()
        destination = NATIVE_EVIDENCE / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        copied.append(relative)
    print(f"native licence evidence of {head}: {', '.join(copied)}", flush=True)
    return copied


# -------------------------------------------------------------------------------------------------------------- Linux

def command_hooks(_: argparse.Namespace) -> None:
    """repository-hooks: the hash-pinned pre-commit closure in a virtual environment of its own (a dependency restore,
    keyed by the requirements file), then the hooks over every file."""
    requirements = ROOT / "eng/requirements-ci.txt"
    key = hashlib.sha256(requirements.read_bytes()).hexdigest()[:16]
    venv = Path.home() / ".cache/arcforges-verify/venvs" / f"desktopplatform-precommit-{key}"
    python = venv / "bin/python"
    if not (venv / ".complete").is_file():
        shutil.rmtree(venv, ignore_errors=True)
        run([sys.executable, "-m", "venv", str(venv)])
        run([str(python), "-m", "pip", "install", "--disable-pip-version-check", "--require-hashes", "-r",
             str(requirements)])
        (venv / ".complete").write_text(key, encoding="utf-8")
    run([str(venv / "bin/pre-commit"), "run", "--all-files", "--show-diff-on-failure", "--color=never"])


# ---------------------------------------------------------------------------------------------------------- Both legs

def suites() -> list[tuple[str | None, str]]:
    """The test projects of the hosted "Build and test platform ownership" step, in its order, with the TRX name of
    the accounting suites; read from the workflow so that the two lists cannot drift. Every `dotnet test` of the step must be either one of the two loops over the accounting suite tables or a plain line read here, so a line of
    another shape fails closed instead of being skipped."""
    text = WORKFLOW.read_text(encoding="utf-8")
    marker = "      - name: Build and test platform ownership\n"
    if text.count(marker) != 1:
        raise Failure(f"cannot find the 'Build and test platform ownership' step in {WORKFLOW.relative_to(ROOT)}")
    step = text.split(marker, 1)[1]
    following = re.search(r"^      - ", step, re.MULTILINE)
    step = step[:following.start()] if following else step
    tables = re.findall(r"Name = '([^']+)'; Project = '([^']+)'", step)
    plain = re.findall(r"^\s*dotnet test --project (\S+) -c Release --no-build$", step, re.MULTILINE)
    loops = len(re.findall(r"dotnet test --project \$suite\.Project ", step))
    total = len(re.findall(r"\bdotnet\s+test\b", step))
    if loops != 2 or total != loops + len(plain) or not tables or step.count("$lateAccountingSuites = @(") != 1:
        raise Failure(f"the test lines of {WORKFLOW.relative_to(ROOT)} changed shape ({total} `dotnet test --project`, {loops} "
                      f"suite loops, {len(plain)} plain lines, {len(tables)} accounting suites); update eng/verify_local.py")
    # The hosted step runs the first accounting table, the plain lines, then the late accounting table; the order is kept.
    early, late = step.split("$lateAccountingSuites = @(", 1)[0], step.split("$lateAccountingSuites = @(", 1)[1]
    first = re.findall(r"Name = '([^']+)'; Project = '([^']+)'", early)
    second = re.findall(r"Name = '([^']+)'; Project = '([^']+)'", late)
    found: list[tuple[str | None, str]] = [*first, *[(None, project) for project in plain], *second]
    if ARCHITECTURE not in found or len(found) != len(set(project for _, project in found)):
        raise Failure(f"cannot read the test suites of {WORKFLOW.relative_to(ROOT)}; update eng/verify_local.py")
    return found


def test_suite(name: str | None, project: str) -> tuple[str, int, float, str]:
    argv = ["dotnet", "test", "--project", project, "-c", "Release", "--no-build"]
    if name:
        argv += ["--results-directory", str(RESULTS), "--report-xunit-trx", "--report-xunit-trx-filename", f"{name}.trx"]
    started = time.monotonic()
    result = subprocess.run(argv, cwd=ROOT, env=routine_env(), text=True, encoding="utf-8", errors="replace",
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return project, result.returncode, time.monotonic() - started, f"+ {' '.join(argv)}\n{result.stdout}"


def command_managed_tests(args: argparse.Namespace) -> None:
    """Every suite of the hosted step except the architecture gate, which needs the native evidence of the Windows
    leg and runs in `architecture` there, and except the timing-sensitive ones, which `--timing-sensitive` runs alone.
    Test projects run concurrently (bounded by --jobs); each one's output is printed whole when it ends. The same on both
    legs, and the test step of the hosted `linux-platform` job."""
    RESULTS.mkdir(parents=True, exist_ok=True)
    selected = [suite for suite in suites() if suite != ARCHITECTURE and (suite[1] in TIMING_SENSITIVE) == args.timing_sensitive]
    if args.timing_sensitive and len(selected) != len(TIMING_SENSITIVE):
        raise Failure(f"the timing-sensitive projects {TIMING_SENSITIVE} are not all in {WORKFLOW.relative_to(ROOT)}")
    for name, _ in selected:
        if name:
            (RESULTS / f"{name}.trx").unlink(missing_ok=True)
    failures = []
    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        for project, code, seconds, output in pool.map(lambda suite: test_suite(*suite), selected):
            print(output, flush=True)
            print(f"==> {project}: exit {code} in {seconds:.0f}s", flush=True)
            if code:
                failures.append(project)
    print(f"==> {len(selected)} test projects in {time.monotonic() - started:.0f}s with {args.jobs} concurrent", flush=True)
    if failures:
        raise Failure("Platform validation failed: " + ", ".join(failures))


# ---------------------------------------------------------- Windows: the rest of `pack`, from this leg's native stage

def trx_failures(path: Path) -> list[str]:
    tree = ET.parse(path)
    names = {}
    for definition in tree.iter():
        if definition.tag.endswith("UnitTest"):
            method = next((child for child in definition if child.tag.endswith("TestMethod")), None)
            if method is not None:
                names[definition.get("id")] = f"{method.get('className')}.{method.get('name')}"
    return [names.get(result.get("testId"), result.get("testName", "?")) for result in tree.iter()
            if result.tag.endswith("UnitTestResult") and result.get("outcome") != "Passed"]


def command_architecture(_: argparse.Namespace) -> None:
    native_evidence()
    evidence = ROOT / "artifacts/evidence"
    gates = evidence / "architecture-gates.json"
    gates.unlink(missing_ok=True)
    # "Require successful external gates": the naming receipt (`naming`, this worktree) and no secret receipt,
    # which only the hosted secret-scan job can issue; the result must be exactly that.
    combine = subprocess.run(["python", "eng/architecture_evidence.py", "combine", "--naming",
                              str(evidence / "naming-architecture.json"), "--output", str(gates)], cwd=ROOT)
    rows = json.loads(gates.read_text(encoding="utf-8"))["evidence"] if gates.is_file() else []
    expected = [("RP-01", True), ("RP-08", True), ("RP-09", False)]
    if [(row["rule"], row["passed"]) for row in rows] != expected or combine.returncode != 1 \
            or [f["message"] for f in rows[2]["findings"]] != ["Existing hosted secret-scan evidence is required; not locally verified."]:
        raise Failure(f"architecture_evidence.py combine did not give exactly the local result {expected}: {rows}")
    print("Naming gates RP-01 and RP-08 passed for this commit; RP-09 is the hosted secret-scan receipt (not local).",
          flush=True)
    findings = evidence / "architecture-findings.json"
    findings.unlink(missing_ok=True)
    name, project = ARCHITECTURE
    _, code, seconds, output = test_suite(name, project)
    print(output, flush=True)
    if code:
        failed = trx_failures(RESULTS / f"{name}.trx")
        found = json.loads(findings.read_text(encoding="utf-8")) if findings.is_file() else None
        if failed != [ARCHITECTURE_FACT] or found != [LOCAL_RP09]:
            raise Failure(f"architecture gate failed beyond the hosted-only RP-09 receipt: tests {failed}, findings {found}")
        print("==> architecture gate: every rule passed except the hosted-only RP-09 receipt (expected locally)",
              flush=True)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    run(["python", "eng/accounting/accounting.py", "report", "--source-commit", head, "--ci-run", RUN,
         "--attempt", ATTEMPT])
    run(["python", "src/BuildingBlocks/ArcForges.Foundation/Errors/generate_registry.py", "--check"])


def command_pack(args: argparse.Namespace) -> None:
    # The provenance audit of `packages.py pack` compares against this clone's origin/main (hosted: the checkout of the
    # PR). The Linux leg pins origin/main of its own clone to the merge base; the Windows leg runs in a worktree of the
    # workstation's clone, whose refs it never moves, so it requires that origin/main is the merge base instead.
    main = subprocess.check_output(["git", "rev-parse", "origin/main"], cwd=ROOT, text=True).strip()
    if main != args.base:
        raise Failure(f"origin/main of this clone is {main}, not the merge base {args.base}: the pack's provenance audit "
                      "would compare against another commit. Rebase the branch onto origin/main (or fetch so that "
                      "origin/main is its merge base) and verify again")
    run(["python", "eng/packaging/packages.py", "version", "--version", VERSION])
    # packages.py refuses to overwrite a candidate (hosted CI starts from an empty checkout); the previous one goes.
    shutil.rmtree(ROOT / "artifacts/packages", ignore_errors=True)
    run(["python", "eng/packaging/packages.py", "pack", "--version", VERSION], env=dict(os.environ, **staged_toolchain()))


def command_packaging_tests(_: argparse.Namespace) -> None:
    """The packaging unittest against the packed candidate, with the toolchain allowance its native stage was produced with."""
    run(["python", "-m", "unittest", "discover", "-s", "eng/packaging", "-p", "test_*.py", "-v"],
        env=dict(os.environ, **staged_toolchain()))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("native", "stage", "naming", "hooks", "architecture", "packaging-tests"):
        sub.add_parser(name)
    sub.add_parser("pack").add_argument("--base", required=True, help="the merge base ({base} of eng/verify_steps.py)")
    tests = sub.add_parser("managed-tests")
    tests.add_argument("--jobs", type=int, default=1)
    tests.add_argument("--timing-sensitive", action="store_true", help="only the timing-sensitive projects")
    args = parser.parse_args()
    # Captured tool output (run(capture=True), the test projects') is printed into the step log, which eng/verify.py
    # writes and reads as UTF-8; a redirected stdout on Windows would use the ANSI code page (cp1252), where non-ASCII
    # compiler output raises UnicodeEncodeError and fails the step.
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")
    if os.environ.pop(OS_SECRET_STORE_OPT_IN, None) is not None:
        print(f"removed {OS_SECRET_STORE_OPT_IN} from the environment: every suite here is routine and never reaches a real OS "
              "secret store (only eng/os_secret_store_tier.py runs the tier)", flush=True)
    commands = {"native": command_native, "stage": command_stage, "naming": command_naming, "hooks": command_hooks,
                "managed-tests": command_managed_tests, "architecture": command_architecture, "pack": command_pack,
                "packaging-tests": command_packaging_tests}
    try:
        commands[args.command](args)
    except (Failure, subprocess.CalledProcessError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

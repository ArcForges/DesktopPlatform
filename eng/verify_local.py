#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""The multi-command steps of the local pre-push verification (eng/verify_steps.py), each the local form of a hosted
job of .github/workflows/pr-gate.yml, native-abi.yml or package-validation.yml (keep them in step):

  python eng/verify_local.py native          Windows: native-abi.yml `native-win-x64` from vcpkg install to the NativeAbi tests
  python eng/verify_local.py stage           Windows: native-abi.yml, stage the audited native runtime packages
  python eng/verify_local.py handoff SHA     Windows: the native-stage and native-licence artifact hand-off to the WSL clone
  python eng/verify_local.py hooks           WSL: pr-gate.yml `repository-hooks` (hash-pinned pre-commit closure)
  python eng/verify_local.py managed-tests   WSL: package-validation.yml `pack`, the test suites of "Build and test"
  python eng/verify_local.py architecture    WSL: `pack`, the architecture gate, invariant accounting and reason registry
  python eng/verify_local.py pack            WSL: `pack`, the version check and "Pack explicit release allowlist"

Only the GitHub-bound parts differ, each named where it happens: run ids and artifact uploads have local equivalents
(the local identity RUN/ATTEMPT below, and copies between the two verification checkouts), and the hosted secret-scan
receipt (RP-09) cannot be produced locally by design (eng/architecture_evidence.py refuses local RP-09 evidence), so the
architecture gate accepts exactly that one finding and nothing else; the secret scan itself runs in the hook.
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
WSL_CLONE = "$HOME/.cache/arcforges-verify/DesktopPlatform"  # eng/verify.py's WSL clone of this repository
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


class Failure(Exception):
    pass


def run(argv: list[str], env: dict[str, str] | None = None, cwd: Path = ROOT, capture: bool = False) -> str:
    print("+ " + " ".join(argv), flush=True)
    result = subprocess.run(argv, cwd=cwd, env=env, text=True, encoding="utf-8", errors="replace",
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


def require_vcpkg_cmake(expected: str) -> None:
    """native.py stage accepts only ports that vcpkg built with the reviewed CMake (the profile's vcpkgCMake; hosted CI
    puts exactly that version on PATH before `vcpkg install`). vcpkg takes the first suitable CMake it finds, so a newer
    one on PATH produces ports the stage rejects; this says so before the build instead of after it."""
    found = {}
    for info in (ROOT / "artifacts/vcpkg-installed" / TRIPLET / "share").glob("*/vcpkg_abi_info.txt"):
        for line in info.read_text(encoding="utf-8").splitlines():
            if line.startswith("cmake "):
                found.setdefault(line.split(" ", 1)[1], []).append(info.parent.name)
    if set(found) != {expected}:
        raise Failure(f"vcpkg built the native dependencies with CMake {sorted(found)} (ports {found}); the reviewed native "
                      f"profile requires CMake {expected} for vcpkg (eng/provenance/artifact-profiles/native-win-x64-r4.json). "
                      f"Make CMake {expected} the first CMake on PATH for this push, or let vcpkg use its own pinned CMake "
                      "download (VCPKG_FORCE_DOWNLOADED_BINARIES=1); installing tools is the user's decision.")


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
    require_vcpkg_cmake(profile["buildTools"]["vcpkgCMake"])
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
    # native.py refuses an existing stage (hosted CI starts from an empty checkout); the previous commit's is removed.
    shutil.rmtree(ROOT / "artifacts/native-packages", ignore_errors=True)
    run(["python", "eng/packaging/native.py", "stage", "--vcpkg-root", str(vcpkg)])


def wsl_path(path: Path) -> str:
    resolved = str(path.resolve())
    return "/mnt/" + resolved[0].lower() + resolved[2:].replace("\\", "/")


def command_handoff(args: argparse.Namespace) -> None:
    """The hosted hand-off is two artifacts: the native stage (`native-stage-*`, downloaded by `pack` into
    artifacts/native-packages) and the native licence evidence (`native-licence-policy-*`: artifacts/evidence/licence-ide.json
    and artifacts/cmake/**/licence-boundary.json, downloaded into artifacts/evidence/native-architecture). Here both
    are copied from this verification worktree into the WSL clone, after checking that both are at the verified commit."""
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if head != args.sha:
        raise Failure(f"the Windows verification worktree is at {head}, not {args.sha}")
    reports = sorted((ROOT / "artifacts/cmake").rglob("licence-boundary.json"))
    if not (ROOT / "artifacts/native-packages/native-artifact.json").is_file() or not reports:
        raise Failure("the native stage or its licence evidence is missing; the native steps did not complete")
    source = wsl_path(ROOT)
    copies = " ".join(f"mkdir -p \"$e/{r.parent.relative_to(ROOT / 'artifacts').as_posix()}\"; "
                      f"cp \"$s/{r.relative_to(ROOT).as_posix()}\" \"$e/{r.relative_to(ROOT / 'artifacts').as_posix()}\";"
                      for r in reports)
    script = (f"set -euo pipefail; d=\"{WSL_CLONE}\"; s='{source}'; "
              f"test \"$(git -C \"$d\" rev-parse HEAD)\" = {args.sha}; "
              "rm -rf \"$d/artifacts/native-packages\" \"$d/artifacts/evidence/native-architecture\"; "
              "mkdir -p \"$d/artifacts\"; cp -r \"$s/artifacts/native-packages\" \"$d/artifacts/native-packages\"; "
              "e=\"$d/artifacts/evidence/native-architecture\"; mkdir -p \"$e/evidence\"; "
              "cp \"$s/artifacts/evidence/licence-ide.json\" \"$e/evidence/licence-ide.json\"; "
              f"{copies} find \"$e\" \"$d/artifacts/native-packages\" -type f | wc -l")
    run(["wsl.exe", "-d", "Debian", "--exec", "bash", "-lc", script])


# ---------------------------------------------------------------------------------------------------------------- WSL

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


def suites() -> list[tuple[str | None, str]]:
    """The test projects of the hosted "Build and test platform ownership" step, in its order, with the TRX name of
    the accounting suites; read from the workflow so that the two lists cannot drift."""
    text = WORKFLOW.read_text(encoding="utf-8")
    found: list[tuple[str | None, str]] = []
    for match in re.finditer(r"Name = '([^']+)'; Project = '([^']+)'|dotnet test --project (\S+) -c Release --no-build$",
                             text, re.MULTILINE):
        found.append((match.group(1), match.group(2)) if match.group(1) else (None, match.group(3)))
    if len(found) < 10 or ARCHITECTURE not in found:
        raise Failure(f"cannot read the test suites of {WORKFLOW.relative_to(ROOT)}; update eng/verify_local.py")
    return found


def test_suite(name: str | None, project: str) -> tuple[str, int, float, str]:
    argv = ["dotnet", "test", "--project", project, "-c", "Release", "--no-build"]
    if name:
        argv += ["--results-directory", str(RESULTS), "--report-xunit-trx", "--report-xunit-trx-filename", f"{name}.trx"]
    started = time.monotonic()
    result = subprocess.run(argv, cwd=ROOT, text=True, encoding="utf-8", errors="replace", stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    return project, result.returncode, time.monotonic() - started, f"+ {' '.join(argv)}\n{result.stdout}"


def command_managed_tests(args: argparse.Namespace) -> None:
    """Every suite of the hosted step except the architecture gate, which needs the native evidence of the Windows
    lane and runs in `architecture`, and except the timing-sensitive ones, which `--timing-sensitive` runs alone. Test
    projects run concurrently (bounded by --jobs); each one's output is printed whole when it ends."""
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
    evidence = ROOT / "artifacts/evidence"
    gates = evidence / "architecture-gates.json"
    gates.unlink(missing_ok=True)
    # "Require successful external gates": the naming receipt of `runtime-policy` (this clone) and no secret receipt,
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


def command_pack(_: argparse.Namespace) -> None:
    run(["python", "eng/packaging/packages.py", "version", "--version", VERSION])
    # packages.py refuses to overwrite a candidate (hosted CI starts from an empty checkout); the previous one goes.
    shutil.rmtree(ROOT / "artifacts/packages", ignore_errors=True)
    run(["python", "eng/packaging/packages.py", "pack", "--version", VERSION])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("native", "stage", "hooks", "architecture", "pack"):
        sub.add_parser(name)
    sub.add_parser("handoff").add_argument("sha")
    tests = sub.add_parser("managed-tests")
    tests.add_argument("--jobs", type=int, default=1)
    tests.add_argument("--timing-sensitive", action="store_true", help="only the timing-sensitive projects")
    args = parser.parse_args()
    commands = {"native": command_native, "stage": command_stage, "handoff": command_handoff, "hooks": command_hooks,
                "managed-tests": command_managed_tests, "architecture": command_architecture, "pack": command_pack}
    try:
        commands[args.command](args)
    except (Failure, subprocess.CalledProcessError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""The local runner of the OS secret-store integration tier (ArcForges-Design docs/architecture/16-testing-strategy.md section 1).

The tier (tests/OsSecretStoreTests) is the only suite that reaches a real OS secret store. Its evidence is the hosted run
(.github/workflows/os-secret-store-tier.yml); a local run is weaker evidence, because the workstation's store is shared with the
user's applications, and it happens only on the user's explicit opt-in:

  Windows (Credential Manager), from a checkout:
    $env:ARCFORGES_OS_SECRET_STORE_TESTS = '1'; python eng/os_secret_store_tier.py; Remove-Item Env:ARCFORGES_OS_SECRET_STORE_TESTS
  Linux (Secret Service), only on the isolated Linux secret-store test host reached through the Linux MCP server
  (ArcForges-Design AD-0019 section 6), never in the verification account or a user's session keyring. The host carries the
  root-owned marker /etc/arcforges/isolated-secret-store-test-host, which its provisioning creates; no WSL distribution is a venue. From a checkout there:
    ARCFORGES_OS_SECRET_STORE_TESTS=1 python3 eng/os_secret_store_tier.py

Without the opt-in nothing runs and the tier is reported as not run, with the reason (exit code 3). The runner never sets the
opt-in itself and passes it only to the one `dotnet test` of the tier project, which runs alone (no other test or node process of the
run), sequentially, under the tier fixture's limits (4 entries at once, 32 store calls, 10 s per call, 5 minutes). The Linux tests
start a private dbus-daemon and gnome-keyring-daemon per test; without a Secret Service provider (gnome-keyring, dbus-daemon,
secret-tool, dbus-send) installed on that host they are skipped with the reason, never reported as passed. The run's name list
is written to artifacts/evidence/os-secret-store-tier/ and is kept with the run's evidence.
"""
from __future__ import annotations

import argparse
import os
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OPT_IN = "ARCFORGES_OS_SECRET_STORE_TESTS"
PROJECT = "tests/OsSecretStoreTests/ArcForges.Tests.OsSecretStoreTests.csproj"
# The isolated Linux test host marks itself with this root-owned file (ArcForges-Design AD-0019 section 6).
ISOLATED_HOST_MARKER = Path("/etc/arcforges/isolated-secret-store-test-host")
EVIDENCE = ROOT / "artifacts/evidence/os-secret-store-tier"
NOT_RUN = 3
# The fixture bounds the tier to five minutes; the process bound adds the cleanup allowance after a failed run (8 calls of at
# most 10 s) and the test host's start-up, so a failing run is never killed mid-cleanup.
PROCESS_TIMEOUT = 420


def isolated_host(marker: Path = ISOLATED_HOST_MARKER, lstat=os.lstat, geteuid=None) -> bool:
    """Whether this Linux host is the isolated secret-store test host and the runner its test account: the marker is a
    regular file (not a symbolic link) owned by root and writable by no one else, in a directory owned by root that no one
    else can write, and the runner is not root (the provisioning, not the test account, creates the marker)."""
    try:
        if (geteuid or os.geteuid)() == 0:
            return False
        for path, kind in ((marker.parent, stat.S_ISDIR), (marker, stat.S_ISREG)):
            status = lstat(path)
            if not kind(status.st_mode) or status.st_uid != 0 or status.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return False
        return True
    except (OSError, AttributeError):
        return False


def refusal(environ: dict[str, str], platform: str, isolated: bool = False) -> tuple[int, str] | None:
    """Why the tier must not run here, as (exit code, message); None when it may. `isolated` says whether this host carries
    the isolated test host's marker (only read on Linux)."""
    if environ.get(OPT_IN) != "1":
        return NOT_RUN, (f"NOT RUN: the OS secret-store tier needs the explicit opt-in {OPT_IN}=1 in this environment; without it "
                         "no test reaches a real OS secret store")
    if platform.startswith("linux") and not isolated:
        return 1, (f"REFUSED: the Linux Secret Service tier runs only on the isolated Linux secret-store test host, which carries "
                   f"the root-owned marker {ISOLATED_HOST_MARKER} in a root-owned directory, as its non-root test account (ArcForges-Design "
                   "AD-0019 section 6), never in the verification account, a WSL distribution or a user's session keyring")
    if not (platform.startswith("linux") or platform == "win32"):
        return 1, "REFUSED: the OS secret-store tier covers Windows and Linux only"
    return None


def build_command() -> list[str]:
    return ["dotnet", "build", PROJECT, "-c", "Release"]


def test_command() -> list[str]:
    return ["dotnet", "test", "--project", PROJECT, "-c", "Release", "--no-build", "--results-directory", str(EVIDENCE),
            "--report-xunit-trx", "--report-xunit-trx-filename", "os-secret-store-tier.trx"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--no-build", action="store_true", help="run the already built Release tier project")
    args = parser.parse_args()
    refused = refusal(dict(os.environ), sys.platform, sys.platform.startswith("linux") and isolated_host())
    if refused is not None:
        code, message = refused
        print(message, file=sys.stderr if code != NOT_RUN else sys.stdout, flush=True)
        return code
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    if not args.no_build:
        # The build runs no test, so it never needs the opt-in.
        build = {key: value for key, value in os.environ.items() if key != OPT_IN}
        print("+ " + " ".join(build_command()), flush=True)
        if subprocess.run(build_command(), cwd=ROOT, env=build).returncode:
            print("FAIL: the tier project did not build", file=sys.stderr, flush=True)
            return 1
    argv = test_command()
    print("+ " + " ".join(argv), flush=True)
    try:
        return subprocess.run(argv, cwd=ROOT, env=dict(os.environ), timeout=PROCESS_TIMEOUT).returncode
    except subprocess.TimeoutExpired:
        print(f"FAIL: the OS secret-store tier did not finish within {PROCESS_TIMEOUT} s", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())

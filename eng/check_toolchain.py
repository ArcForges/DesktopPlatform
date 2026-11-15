# SPDX-License-Identifier: AGPL-3.0-only
"""Check the effective managed build tools before local or hosted verification."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def command(arguments: list[str]) -> str:
    result = subprocess.run(arguments, cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                            timeout=60, env=dict(os.environ, DOTNET_CLI_UI_LANGUAGE="en-US"))
    if result.returncode:
        raise ValueError("Tool query failed: " + " ".join(arguments))
    return result.stdout.strip()


def check(tools: set[str]) -> dict:
    expected_python = (ROOT / ".python-version").read_text(encoding="utf-8").strip()
    invoking = platform.python_version()
    python = shutil.which("python")
    if invoking != expected_python or not python or command([python, "--version"]) != "Python " + expected_python:
        raise ValueError(f"Invoking Python {invoking} ({sys.executable}) and PATH Python ({python}) must both be {expected_python}")
    report = {"python": {"version": invoking, "executable": sys.executable, "pathExecutable": python}}
    if "dotnet" in tools:
        expected_sdk = json.loads((ROOT / "global.json").read_text(encoding="utf-8"))["sdk"]["version"]
        dotnet = shutil.which("dotnet")
        if not dotnet or command([dotnet, "--version"]) != expected_sdk:
            raise ValueError(f"PATH dotnet ({dotnet}) must select SDK {expected_sdk} from global.json")
        roots = []
        for line in command([dotnet, "--list-sdks"]).splitlines():
            if line.startswith(expected_sdk + " [") and line.endswith("]"):
                roots.append((Path(line.split("[", 1)[1][:-1]) / expected_sdk).resolve())
        effective = json.loads(command([dotnet, "msbuild", "src/Build/ArcForges.Build.Policy/ArcForges.Build.Policy.csproj",
                                        "-nologo", "-getProperty:NETCoreSdkVersion,MSBuildToolsPath"]))["Properties"]
        if effective["NETCoreSdkVersion"] != expected_sdk or Path(effective["MSBuildToolsPath"]).resolve() not in roots:
            raise ValueError("Effective MSBuild does not use the selected pinned SDK")
        override = os.environ.get("MSBuildSDKsPath")
        if override and Path(override).resolve() not in {(root / "Sdks").resolve() for root in roots}:
            raise ValueError("MSBuildSDKsPath conflicts with the pinned SDK")
        report["dotnet"] = {"version": expected_sdk, "executable": dotnet, "effective": effective}
    paths = command(["git", "ls-files", "--", "**/packages.lock.json", "eng/requirements-ci*.txt"]).splitlines()
    report["lockSha256Lf"] = {name: hashlib.sha256((ROOT / name).read_bytes().replace(b"\r\n", b"\n")).hexdigest()
                              for name in paths}
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools", nargs="+", choices=("python", "dotnet"), default=["python", "dotnet"])
    args = parser.parse_args()
    try:
        print(json.dumps(check(set(args.tools)), sort_keys=True))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("toolchain mismatch: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise actual tool selection and conflicting inputs without replacing executables."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ToolchainSelectionTests(unittest.TestCase):
    def invoke(self, root=ROOT, extra=None, tools=("python", "dotnet")):
        return subprocess.run([sys.executable, str(root / "eng/check_toolchain.py"), "--tools", *tools],
                              cwd=root, capture_output=True, text=True,
                              env=dict(os.environ, **(extra or {})), timeout=90)

    def test_effective_repository_tools_match_the_selectors(self):
        result = self.invoke()
        self.assertEqual(0, result.returncode, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(json.loads((ROOT / "global.json").read_text())["sdk"]["version"], report["dotnet"]["version"])
        self.assertIn("eng/requirements-ci.txt", report["lockSha256Lf"])

    def test_python_is_checked_even_for_a_dotnet_job(self):
        with tempfile.TemporaryDirectory(prefix="toolchain-selection-") as temporary:
            root = Path(temporary)
            (root / "eng").mkdir()
            shutil.copyfile(ROOT / "eng/check_toolchain.py", root / "eng/check_toolchain.py")
            (root / ".python-version").write_text("0.0.0\n")
            result = self.invoke(root, tools=("dotnet",))
            self.assertNotEqual(0, result.returncode)
            self.assertIn("must both be 0.0.0", result.stderr)

    def test_conflicting_msbuild_root_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="wrong-msbuild-root-") as temporary:
            result = self.invoke(extra={"MSBuildSDKsPath": temporary})
            self.assertNotEqual(0, result.returncode)
            self.assertIn("toolchain mismatch:", result.stderr)

    def test_python_only_job_does_not_require_dotnet(self):
        result = self.invoke(extra={"MSBuildSDKsPath": str(ROOT / "artifacts/not-an-sdk")}, tools=("python",))
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn("dotnet", json.loads(result.stdout))


if __name__ == "__main__":
    unittest.main()

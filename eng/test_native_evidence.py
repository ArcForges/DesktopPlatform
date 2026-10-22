# SPDX-License-Identifier: AGPL-3.0-only
"""The native licence evidence that the Windows leg's architecture gate reads (eng/verify_local.py native_evidence).

Hosted, native-abi.yml uploads artifacts/evidence/licence-ide.json and artifacts/cmake/**/licence-boundary.json as
`native-licence-policy-*` and `pack` downloads it into artifacts/evidence/native-architecture. Locally the Windows leg
produces both files itself and lays them out the same way, only for its own commit. These tests run on a throwaway
repository, on any operating system.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import verify_local


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


class NativeEvidence(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        git(self.root, "init", "-q")
        git(self.root, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "t")
        self.sha = git(self.root, "rev-parse", "HEAD")
        (self.root / "artifacts/evidence").mkdir(parents=True)
        self.ide = self.root / "artifacts/evidence/licence-ide.json"
        self.ide.write_text(json.dumps({"result": "passed", "repositories": [
            {"repository": "DesktopPlatform", "commit": self.sha, "dirty": False}]}), encoding="utf-8")
        self.report = self.root / "artifacts/cmake/win-x64/shim-static/licence-boundary.json"
        self.report.parent.mkdir(parents=True)
        self.report.write_text(json.dumps({"commit": self.sha, "result": "passed"}), encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def collect(self) -> list[str]:
        with mock.patch.object(verify_local, "ROOT", self.root), \
                mock.patch.object(verify_local, "NATIVE_EVIDENCE", self.root / "artifacts/evidence/native-architecture"):
            return verify_local.native_evidence()

    def test_the_evidence_is_laid_out_as_the_hosted_download(self) -> None:
        stale = self.root / "artifacts/evidence/native-architecture/cmake/win-x64/old/licence-boundary.json"
        stale.parent.mkdir(parents=True)
        stale.write_text("{}", encoding="utf-8")
        copied = self.collect()
        target = self.root / "artifacts/evidence/native-architecture"
        self.assertEqual(["evidence/licence-ide.json", "cmake/win-x64/shim-static/licence-boundary.json"], copied)
        self.assertEqual(self.ide.read_bytes(), (target / "evidence/licence-ide.json").read_bytes())
        self.assertEqual(self.report.read_bytes(), (target / "cmake/win-x64/shim-static/licence-boundary.json").read_bytes())
        self.assertFalse(stale.exists(), "evidence of an earlier configure must not reach the gate")

    def test_missing_evidence_fails(self) -> None:
        self.report.unlink()
        with self.assertRaisesRegex(verify_local.Failure, "native licence evidence is missing"):
            self.collect()

    def test_a_receipt_of_another_commit_is_refused(self) -> None:
        self.report.write_text(json.dumps({"commit": "0" * 40}), encoding="utf-8")
        with self.assertRaisesRegex(verify_local.Failure, "is the configure receipt of 0{40}, not"):
            self.collect()
        self.assertFalse((self.root / "artifacts/evidence/native-architecture").exists())

    def test_an_ide_evaluation_of_another_commit_or_a_dirty_tree_is_refused(self) -> None:
        for row in ({"repository": "DesktopPlatform", "commit": "0" * 40, "dirty": False},
                    {"repository": "DesktopPlatform", "commit": self.sha, "dirty": True}):
            self.ide.write_text(json.dumps({"result": "passed", "repositories": [row]}), encoding="utf-8")
            with self.assertRaisesRegex(verify_local.Failure, "is not the clean IDE licence evaluation of"):
                self.collect()
        self.assertFalse((self.root / "artifacts/evidence/native-architecture").exists())


if __name__ == "__main__":
    unittest.main()

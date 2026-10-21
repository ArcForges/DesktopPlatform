# SPDX-License-Identifier: AGPL-3.0-only
"""The native hand-off between the two legs of the local verification (eng/verify_local.py handoff and handoff-import).

The Windows leg packs the native stage and its licence evidence with a manifest of the commit and every file's SHA-256;
the Linux leg, on another machine, unpacks it only when the archive is the hand-off of its own commit and every file
matches. These tests run both halves on a throwaway repository, on any operating system.
"""
from __future__ import annotations

import argparse
import io
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import verify_local


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


class NativeHandoff(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        base = Path(self.temporary.name)
        self.windows, self.linux, self.inbox = base / "windows", base / "linux", base / "inbox"
        for root in (self.windows, self.linux):
            root.mkdir()
            git(root, "init", "-q")
            git(root, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m",
                root.name)
        self.sha = git(self.windows, "rev-parse", "HEAD")
        # In real use both legs check out the same commit; here the Linux clone is at a commit of its own (a different
        # message), which the tests use as "the commit the Linux leg verifies".
        self.assertNotEqual(self.sha, git(self.linux, "rev-parse", "HEAD"))
        stage = self.windows / "artifacts/native-packages"
        (stage / "pkg").mkdir(parents=True)
        (stage / "native-artifact.json").write_text('{"a": 1}', encoding="utf-8")
        (stage / "pkg/lib.so").write_bytes(b"\x7fELF native")
        (self.windows / "artifacts/evidence").mkdir(parents=True)
        (self.windows / "artifacts/evidence/licence-ide.json").write_text("{}", encoding="utf-8")
        report = self.windows / "artifacts/cmake/win-x64/shim-static/licence-boundary.json"
        report.parent.mkdir(parents=True)
        report.write_text('{"ok": true}', encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def pack(self) -> Path:
        with mock.patch.object(verify_local, "ROOT", self.windows):
            verify_local.command_handoff(argparse.Namespace(sha=self.sha))
        return self.windows / ".git/arcforges-verify/handoff" / verify_local.handoff_name(self.sha)

    def unpack(self, sha: str) -> None:
        with mock.patch.object(verify_local, "ROOT", self.linux), mock.patch.object(verify_local, "HANDOFF_DIR", self.inbox):
            verify_local.command_handoff_import(argparse.Namespace(sha=sha))

    def carry(self, archive: Path, sha: str) -> Path:
        self.inbox.mkdir(exist_ok=True)
        target = self.inbox / verify_local.handoff_name(sha)
        target.write_bytes(archive.read_bytes())
        return target

    def test_the_archive_round_trips_to_the_paths_pack_reads(self) -> None:
        archive = self.pack()
        linux_sha = git(self.linux, "rev-parse", "HEAD")
        with tarfile.open(archive) as packed:
            manifest = json.loads(packed.extractfile("handoff.json").read())
        self.assertEqual(self.sha, manifest["commit"])
        # Re-pack the same files under the Linux clone's commit to model the same commit on both machines.
        manifest["commit"] = linux_sha
        rebuilt = self.inbox / verify_local.handoff_name(linux_sha)
        self.inbox.mkdir()
        with tarfile.open(archive) as source, tarfile.open(rebuilt, "w:gz") as target:
            data = json.dumps(manifest).encode()
            info = tarfile.TarInfo("handoff.json")
            info.size = len(data)
            target.addfile(info, io.BytesIO(data))
            for member in source.getmembers():
                if member.name != "handoff.json":
                    target.addfile(member, source.extractfile(member))
        stale = self.linux / "artifacts/native-packages/old.txt"
        stale.parent.mkdir(parents=True)
        stale.write_text("from an earlier commit", encoding="utf-8")
        self.unpack(linux_sha)
        self.assertEqual(b"\x7fELF native", (self.linux / "artifacts/native-packages/pkg/lib.so").read_bytes())
        self.assertTrue((self.linux / "artifacts/evidence/native-architecture/evidence/licence-ide.json").is_file())
        self.assertTrue((self.linux / "artifacts/evidence/native-architecture/cmake/win-x64/shim-static/licence-boundary.json")
                        .is_file())
        self.assertFalse(stale.exists(), "an earlier commit's stage must not survive the hand-off")

    def test_a_missing_archive_fails(self) -> None:
        with self.assertRaisesRegex(verify_local.Failure, "is missing: run the Windows leg"):
            self.unpack(git(self.linux, "rev-parse", "HEAD"))

    def test_an_archive_of_another_commit_is_refused(self) -> None:
        archive = self.pack()
        linux_sha = git(self.linux, "rev-parse", "HEAD")
        self.carry(archive, linux_sha)
        with self.assertRaisesRegex(verify_local.Failure, "is not the native hand-off of"):
            self.unpack(linux_sha)
        self.assertFalse((self.linux / "artifacts/native-packages").exists())

    def test_a_clone_at_another_commit_is_refused(self) -> None:
        with self.assertRaisesRegex(verify_local.Failure, "is at"):
            self.unpack("0" * 40)

    def test_a_tampered_file_is_refused(self) -> None:
        archive = self.pack()
        linux_sha = git(self.linux, "rev-parse", "HEAD")
        tampered = self.inbox / verify_local.handoff_name(linux_sha)
        self.inbox.mkdir()
        with tarfile.open(archive) as source, tarfile.open(tampered, "w:gz") as target:
            manifest = json.loads(source.extractfile("handoff.json").read())
            manifest["commit"] = linux_sha
            data = json.dumps(manifest).encode()
            info = tarfile.TarInfo("handoff.json")
            info.size = len(data)
            target.addfile(info, io.BytesIO(data))
            for member in source.getmembers():
                if member.name == "handoff.json":
                    continue
                content = source.extractfile(member).read()
                if member.name.endswith("lib.so"):
                    content = b"altered"
                    member.size = len(content)
                target.addfile(member, io.BytesIO(content))
        with self.assertRaisesRegex(verify_local.Failure, "does not match its SHA-256"):
            self.unpack(linux_sha)
        self.assertFalse((self.linux / "artifacts/native-packages").exists())


if __name__ == "__main__":
    unittest.main()

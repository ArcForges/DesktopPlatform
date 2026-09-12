# SPDX-License-Identifier: AGPL-3.0-only
"""Release guards exercised against the actual candidate produced by pack."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import packages


class PackageGuards(unittest.TestCase):
    def fixture(self):
        source = packages.ROOT / "artifacts/packages"
        target = Path(tempfile.mkdtemp(prefix="package-guard-", dir=packages.ROOT / "artifacts")).resolve()
        packages.require(target.is_relative_to(packages.ROOT / "artifacts"), "Fixture escapes artifacts.")
        for path in source.iterdir():
            if path.is_file():
                shutil.copyfile(path, target / path.name)
        manifest = json.loads((target / "manifest.json").read_text())
        return target, manifest

    def test_canonical_versions(self):
        for value in ["1.0.0", "1.0.0-ci.123.2", "0.1.0-rc.1"]:
            self.assertEqual(value, packages.version(value))
        for value in ["v1.0.0", "1.0", "01.0.0", "1.0.0+build", "1.0.0-ci.01", "1.*", "../1.0.0", "1.0.0;echo unsafe"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                packages.version(value)

    def test_real_candidate_verifies(self):
        target, manifest = self.fixture()
        packages.verify(target, manifest["version"], manifest["sourceCommit"])

    def test_altered_package_is_rejected(self):
        target, manifest = self.fixture()
        package = target / manifest["packages"][0]["file"]
        package.write_bytes(package.read_bytes() + b"altered")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            packages.verify(target, manifest["version"], manifest["sourceCommit"])

    def test_unlisted_package_is_rejected(self):
        target, manifest = self.fixture()
        (target / "Unexpected.1.0.0.nupkg").write_bytes(b"unreviewed")
        with self.assertRaisesRegex(ValueError, "Unexpected or missing"):
            packages.verify(target, manifest["version"], manifest["sourceCommit"])

    def test_wrong_source_is_rejected(self):
        target, manifest = self.fixture()
        with self.assertRaisesRegex(ValueError, "source/version mismatch"):
            packages.verify(target, manifest["version"], "0" * 40)

    def test_candidate_cannot_be_overwritten(self):
        target, manifest = self.fixture()
        with self.assertRaisesRegex(ValueError, "never overwrite"):
            packages.pack(target, manifest["version"])


if __name__ == "__main__":
    unittest.main()

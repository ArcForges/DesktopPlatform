# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise the actual MSBuild package-policy target without restore or compilation."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "src/Build/ArcForges.Build.Policy/build/ArcForges.Build.Policy.targets"
ACCEPTED = "PACKAGE_POLICY_ACCEPTED"


class PackageVersionPolicyTests(unittest.TestCase):
    def evaluate(self, versions, *, centrally_managed=True, inline=None):
        with tempfile.TemporaryDirectory(prefix="arcforges-package-policy-") as temporary:
            root = Path(temporary)
            central = ET.Element("Project")
            properties = ET.SubElement(central, "PropertyGroup")
            ET.SubElement(properties, "ManagePackageVersionsCentrally").text = str(centrally_managed).lower()
            items = ET.SubElement(central, "ItemGroup")
            for name, version in versions:
                ET.SubElement(items, "PackageVersion", Include=name, Version=version)
            ET.ElementTree(central).write(root / "Directory.Packages.props", encoding="utf-8")

            project = ET.Element("Project")
            ET.SubElement(project, "Import", Project="Directory.Packages.props")
            references = ET.SubElement(project, "ItemGroup")
            for name, _ in versions:
                ET.SubElement(references, "PackageReference", Include=name, **(inline or {}))
            ET.SubElement(project, "Import", Project=str(POLICY))
            completed = ET.SubElement(project, "Target", Name="RecordPackagePolicyAcceptance",
                                      AfterTargets="ArcForgesVerifyPackagePolicy")
            ET.SubElement(completed, "Message", Text=ACCEPTED, Importance="high")
            path = root / "PolicyFixture.csproj"
            ET.ElementTree(project).write(path, encoding="utf-8")
            return subprocess.run(["dotnet", "msbuild", str(path), "-nologo",
                                   "-target:ArcForgesVerifyPackagePolicy"], cwd=ROOT,
                                  capture_output=True, text=True, env=os.environ.copy(), timeout=30)

    def assert_rejected(self, result, diagnostic):
        output = result.stdout + result.stderr
        self.assertNotEqual(0, result.returncode, output)
        self.assertIn(diagnostic, output)
        self.assertNotIn(ACCEPTED, output)

    def test_exact_real_versions_are_accepted(self):
        result = self.evaluate([
            ("Avalonia.Angle.Windows.Natives", "2.1.27548.20260419"),
            ("HarfBuzzSharp", "14.4.0.100"),
            ("Ordinary.Stable", "1.2.3"),
            ("ArcForges.Foundation", "1.0.0-ci.1.1"),
        ])
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn(ACCEPTED, result.stdout)

    def test_floating_ranges_and_wrong_segment_counts_are_rejected(self):
        for version in ["1.*", "1.2.*", "1.2.3.*", "1.2.3-ci.*", "[1.2.3,2.0.0)",
                        "[1.2.3]", "(,2.0.0]", "1.2.3.4.5", "1.2.3.4.5-ci.1.1", "1.2", ""]:
            with self.subTest(version=version):
                self.assert_rejected(self.evaluate([("Candidate", version)]), "AFP003")

    def test_inline_version_and_override_are_still_rejected(self):
        for attribute in ["Version", "VersionOverride"]:
            with self.subTest(attribute=attribute):
                self.assert_rejected(self.evaluate([("Candidate", "14.4.0.100")],
                                                   inline={attribute: "14.4.0.100"}), "AFP002")

    def test_central_management_is_still_required(self):
        self.assert_rejected(self.evaluate([("Candidate", "14.4.0.100")],
                                           centrally_managed=False), "AFP001")


if __name__ == "__main__":
    unittest.main()

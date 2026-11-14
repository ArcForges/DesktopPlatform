# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic resolver independence and real Git identity rejection tests."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import build_identity as identity


class CompilerPolicyTests(unittest.TestCase):
    """Real MSBuild evaluation of declared policy inputs; no restore, package or native execution."""

    def evaluate(self, language='14', sdk='10.0.400', **overrides):
        with tempfile.TemporaryDirectory(prefix='arcforges-compiler-policy-') as temporary:
            root = Path(temporary)
            policy = Path(__file__).resolve().parents[1] / 'src/Build/ArcForges.Build.Policy/build'
            settings = {'LangVersion': language, 'NETCoreSdkVersion': sdk, 'Nullable': 'enable',
                        'Deterministic': 'true', 'TreatWarningsAsErrors': 'true',
                        'RestorePackagesWithLockFile': 'true'}
            # SDK is a declared policy-input vector here. Actual SDK/C# compilation is distinct
            # author/native evidence; this target deliberately performs no SDK resolution.
            properties = ''.join(f'<{key}>{value}</{key}>' for key, value in settings.items())
            override_properties = ''.join(f'<{key}>{value}</{key}>' for key, value in overrides.items())
            project = root / 'PolicyFixture.csproj'
            project.write_text(f'''<Project>
  <PropertyGroup>{properties}</PropertyGroup>
  <Import Project="{policy / 'ArcForges.Build.Policy.props'}" />
  <PropertyGroup>{override_properties}</PropertyGroup>
  <Import Project="{policy / 'ArcForges.Build.Policy.targets'}" />
</Project>''', encoding='utf-8')
            environment = {key: value for key, value in os.environ.items()
                           if not key.startswith('GITHUB_') and key not in {'CI', 'MSBuildSDKsPath'}}
            return subprocess.run(['dotnet', 'msbuild', str(project), '-nologo',
                                   '-target:ArcForgesVerifyCompilerPolicy'], cwd=root,
                                  capture_output=True, text=True, env=environment, timeout=30)

    def test_explicit_supported_compiler_versions_are_accepted(self):
        for language, sdk in [('14', '10.0.400'), ('14', '11.0.100'), ('15', '11.0.100'), ('15', '11.0.101')]:
            with self.subTest(language=language, sdk=sdk):
                result = self.evaluate(language, sdk)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_existing_consumer_default_remains_csharp14(self):
        result = self.evaluate(language='')
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_csharp15_requires_a_stable_supported_sdk(self):
        for sdk in ['', '10.0.403', '11.0.99', '11.0.100-preview.1', 'latest', 'unknown']:
            with self.subTest(sdk=sdk):
                result = self.evaluate('15', sdk)
                self.assertNotEqual(0, result.returncode)
                self.assertIn('AFP004', result.stdout + result.stderr)

    def test_unknown_and_floating_language_versions_are_refused(self):
        for language in ['13', '16', 'latest', 'preview']:
            with self.subTest(language=language):
                result = self.evaluate(language, '11.0.100')
                self.assertNotEqual(0, result.returncode)
                self.assertIn('AFP004', result.stdout + result.stderr)

    def test_csharp15_cannot_weaken_existing_compiler_or_lock_guards(self):
        for overrides, diagnostic in [({'Nullable': 'disable'}, 'AFP004'),
                                      ({'Deterministic': 'false'}, 'AFP004'),
                                      ({'TreatWarningsAsErrors': 'false'}, 'AFP004'),
                                      ({'RestorePackagesWithLockFile': 'false'}, 'AFP005')]:
            with self.subTest(overrides=overrides):
                result = self.evaluate('15', '11.0.100', **overrides)
                self.assertNotEqual(0, result.returncode)
                self.assertIn(diagnostic, result.stdout + result.stderr)


class BuildIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.catalog = {'schemaVersion': 1, 'owner': 'fixture', 'axes': {}}
        for axis, kind in identity.KINDS.items():
            config = {'kind': kind}
            if kind == 'release':
                config['subject'] = 'fixture-app'
            elif kind != 'packages':
                config['sources'] = [axis + '.txt']
                self.write_axis(axis, 1)
            self.catalog['axes'][axis] = config
        self.write_lock('1.0.0')

    def write_lock(self, version):
        (self.root / 'packages.lock.json').write_text(json.dumps({'dependencies': {
            'net10.0': {'Dependency': {'type': 'Direct', 'resolved': version}}}}), encoding='utf-8')

    def write_axis(self, axis, version):
        kind = identity.KINDS[axis]
        if kind == 'native-abi':
            content = f'#define ARC_NATIVE_ABI_MAJOR UINT32_C({version})\n#define ARC_NATIVE_ABI_MINOR UINT32_C(0)\n'
        elif kind == 'contracts':
            content = f'package fixture.contract.v{version};\n'
        else:
            content = json.dumps([{'subject': axis + '-fixture',
                                   'version': version if kind == 'migrations' else str(version)}])
        (self.root / (axis + '.txt')).write_text(content, encoding='utf-8')

    def resolve(self, release='1.0.0'):
        with patch.object(identity, 'git', return_value='packages.lock.json'):
            packages = identity.dependency_versions(self.root)
        return identity.resolve_axes(self.root, self.catalog, release, packages)

    def test_nine_sources_change_independently(self):
        baseline = self.resolve()
        for axis in identity.AXES:
            with self.subTest(axis=axis):
                if axis == 'AppVersion':
                    changed = self.resolve('2.0.0')
                elif axis == 'PackageVersion':
                    self.write_lock('2.0.0')
                    changed = self.resolve()
                    self.write_lock('1.0.0')
                else:
                    self.write_axis(axis, 2)
                    changed = self.resolve()
                    self.write_axis(axis, 1)
                self.assertEqual([axis], [name for name in identity.AXES if baseline[name] != changed[name]])
        self.assertEqual(identity.canonical(baseline), identity.canonical(self.resolve()))

    def test_input_mutation_does_not_change_resolved_report(self):
        with patch.object(identity, 'git', return_value='packages.lock.json'):
            packages = identity.dependency_versions(self.root)
        before = identity.resolve_axes(self.root, self.catalog, '1.0.0', packages)
        expected = identity.canonical(before)
        packages[0]['version'] = '2.0.0'
        self.assertEqual(expected, identity.canonical(before))

    def test_invalid_axes_and_evidence_rejected(self):
        baseline = self.resolve()
        mutations = [lambda x: x.pop('ContractSet'), lambda x: x.update(Unknown={}),
                     lambda x: x['NativeAbiVersion']['values'].append(copy.deepcopy(x['NativeAbiVersion']['values'][0])),
                     lambda x: x['NativeAbiVersion']['values'][0].update(version='AppVersion'),
                     lambda x: x['NativeAbiVersion']['values'][0].update(source={}),
                     lambda x: x['NativeAbiVersion']['values'][0]['source'].update(sha256Lf='bad'),
                     lambda x: x['NativeAbiVersion']['values'][0]['source'].update(path='../escape')]
        for mutation in mutations:
            altered = copy.deepcopy(baseline)
            mutation(altered)
            with self.assertRaises(ValueError):
                identity.validate_axes(altered)

    def test_absence_requires_reason_and_future_owner(self):
        self.catalog['axes']['CapabilityVersion'] = {'kind': 'declarations', 'absence': 'not-produced',
                                                     'reason': 'No implementation', 'producer': 'WP09'}
        self.assertEqual('not-produced', self.resolve()['CapabilityVersion']['status'])
        self.catalog['axes']['CapabilityVersion'].pop('producer')
        with self.assertRaisesRegex(ValueError, 'producer'):
            self.resolve()

    def test_missing_and_cross_axis_sources_rejected(self):
        self.catalog['axes']['NativeAbiVersion']['sources'] = ['missing.h']
        with self.assertRaises(ValueError):
            self.resolve()
        self.catalog['axes']['NativeAbiVersion']['sources'] = ['../outside.h']
        with self.assertRaises(ValueError):
            self.resolve()
        self.catalog['axes']['NativeAbiVersion']['kind'] = 'release'
        with self.assertRaisesRegex(ValueError, 'cross-axis'):
            self.resolve()

    def test_real_git_identity_and_publication_rejections(self):
        def git(*args):
            subprocess.run(['git', *args], cwd=self.root, check=True, capture_output=True)
        git('init')
        git('add', '.')
        git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'fixture')
        local = identity.build_identity(self.root, {})
        with self.assertRaisesRegex(ValueError, 'publishable'):
            identity.validate_identity(local, publish=True)
        env = {'GITHUB_ACTIONS': 'true', 'GITHUB_SHA': local['sourceCommit'], 'GITHUB_RUN_ID': '123',
               'GITHUB_RUN_ATTEMPT': '2', 'GITHUB_REPOSITORY': 'ArcForges/DesktopPlatform'}
        ci = identity.build_identity(self.root, env)
        identity.validate_identity(ci, local['sourceCommit'], publish=True)
        self.assertEqual(ci, identity.build_identity(self.root, env))
        for field, value in [('sourceCommit', 'b' * 40), ('buildId', '123.3'), ('pipelineRun', 'https://example.invalid'),
                             ('runAttempt', None), ('sourceDateEpoch', 0), ('dirty', True), ('kind', 'unknown')]:
            altered = {**ci, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                identity.validate_identity(altered, local['sourceCommit'], publish=True)
        with self.assertRaises(ValueError):
            identity.build_identity(self.root, {**env, 'GITHUB_SHA': 'b' * 40})
        (self.root / 'untracked').write_text('dirty', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'dirty'):
            identity.build_identity(self.root, env)


if __name__ == '__main__':
    unittest.main()

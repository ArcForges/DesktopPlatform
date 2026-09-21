# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic resolver independence and real Git identity rejection tests."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import build_identity as identity


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

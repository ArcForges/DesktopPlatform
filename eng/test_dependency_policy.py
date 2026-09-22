# SPDX-License-Identifier: AGPL-3.0-only
"""Offline adversarial admission and publisher checks; no artifacts or registries."""
import copy
import json
from pathlib import Path
import sys
import unittest

from dependency_policy import ROOT, POLICY, audit, check_admission, check_history, closure, exact
sys.path.insert(0, str(Path(__file__).resolve().parent / 'packaging'))
from release_channels import selected, verified_tag


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((ROOT / POLICY).read_text())
        self.actual = closure(ROOT)

    def test_actual_policy_and_stable_closure(self):
        self.assertEqual(audit(stable=True)['result'], 'passed')

    def test_forbidden_licence(self):
        next(iter(self.policy['nugetClosure'].values()))['licence'] = 'GPL-3.0-only'
        with self.assertRaisesRegex(ValueError, 'Forbidden'):
            check_admission(self.policy, self.actual)

    def test_mutable_admitted_version(self):
        self.actual[next(iter(self.actual))] = 'different-content'
        with self.assertRaisesRegex(ValueError, 'Mutable'):
            check_admission(self.policy, self.actual)

    def test_unknown_dependency(self):
        self.actual['unreviewed/1.0.0'] = 'digest'
        with self.assertRaisesRegex(ValueError, 'Unadmitted'):
            check_admission(self.policy, self.actual)

    def test_floating_versions(self):
        for value in ['latest', 'main', '1.*', '[1.0.0,)', '1.0.0-SNAPSHOT', 'git+https://example.test/repo#v1']:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'Floating'):
                exact(value)

    def test_source_tag_and_missing_upgrade_review(self):
        for field, value in [('baselineCommit', 'v1.0.0'), ('upgradeChecks', {}), ('inputHashes', {})]:
            policy = copy.deepcopy(self.policy)
            policy['review'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                check_admission(policy, self.actual)

    def test_wrong_publisher(self):
        self.policy['publisher']['repository'] = 'someone/DesktopPlatform'
        with self.assertRaisesRegex(ValueError, 'Wrong publisher'):
            check_admission(self.policy, self.actual)

    def test_review_cannot_authorize_rewriting_an_existing_version(self):
        old = copy.deepcopy(self.policy)
        next(iter(self.policy['nugetClosure'].values()))['contentHash'] = 'new-reviewed-hash'
        with self.assertRaisesRegex(ValueError, 'Historical immutable'):
            check_history(self.policy, [old])

    def test_tag_ancestry_and_candidate_selection(self):
        env = {'GITHUB_REPOSITORY': 'ArcForges/DesktopPlatform', 'GITHUB_EVENT_NAME': 'push',
               'GITHUB_SHA': 'a' * 40, 'GITHUB_REF': 'refs/heads/main',
               'GITHUB_RUN_NUMBER': '22', 'GITHUB_RUN_ATTEMPT': '1'}
        seen = []
        self.assertEqual(selected(env, seen.append), '1.0.0-ci.22.1')
        self.assertEqual(seen, [])
        env['GITHUB_REF'] = 'refs/tags/v1.2.3'
        self.assertEqual(selected(env, seen.append), '1.2.3')
        self.assertEqual(seen, ['a' * 40])
        def unmerged(commit):
            raise ValueError('Tag is not on main')
        with self.assertRaisesRegex(ValueError, 'not on main'):
            selected(env, unmerged)
        for field, value in [('GITHUB_REF', 'refs/tags/v01.2.3'), ('GITHUB_REF', 'refs/tags/v1.2.3-rc.1'),
                             ('GITHUB_EVENT_NAME', 'pull_request'), ('GITHUB_REPOSITORY', 'fork/DesktopPlatform')]:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                selected({**env, field: value}, seen.append)

    def test_tag_is_peeled_and_matches_checked_source(self):
        seen = []
        def resolve(ref):
            self.assertEqual(ref, 'refs/tags/v1.2.3^{commit}')
            return 'a' * 40
        verified_tag('refs/tags/v1.2.3', 'a' * 40, resolve, seen.append)
        self.assertEqual(seen, ['a' * 40])
        with self.assertRaisesRegex(ValueError, 'tag target'):
            verified_tag('refs/tags/v1.2.3', 'b' * 40, resolve, seen.append)


if __name__ == '__main__':
    unittest.main()

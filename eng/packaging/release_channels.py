# SPDX-License-Identifier: AGPL-3.0-only
"""Select and authorize the original main or deliberate stable-tag candidate."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dependency_policy import audit

ROOT = Path(__file__).resolve().parents[2]
STABLE = r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)'


def selected(env, ancestor):
    if env.get('GITHUB_REPOSITORY') != 'ArcForges/DesktopPlatform' or env.get('GITHUB_EVENT_NAME') != 'push':
        raise ValueError('Wrong publisher repository or event')
    commit = env.get('GITHUB_SHA', '')
    if not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('Publisher requires exact source commit')
    ref = env.get('GITHUB_REF', '')
    if ref == 'refs/heads/main':
        run, attempt = env.get('GITHUB_RUN_NUMBER', ''), env.get('GITHUB_RUN_ATTEMPT', '')
        if not all(re.fullmatch('[1-9][0-9]*', part) for part in (run, attempt)):
            raise ValueError('Invalid immutable run identity')
        return f'1.0.0-ci.{run}.{attempt}'
    if not re.fullmatch('refs/tags/v' + STABLE, ref):
        raise ValueError('Publication requires main or a canonical stable tag')
    ancestor(commit)
    return ref.removeprefix('refs/tags/v')


def verified_tag(ref, commit, resolve, ancestor):
    if resolve(ref + '^{commit}') != commit:
        raise ValueError('Stable tag target differs from checked source')
    ancestor(commit)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-version')
    args = parser.parse_args()
    def ancestor(commit):
        verified_tag(os.environ['GITHUB_REF'], commit,
            lambda ref: subprocess.check_output(['git', 'rev-parse', '--verify', ref], cwd=ROOT, text=True).strip(),
            lambda sha: subprocess.run(['git', 'merge-base', '--is-ancestor', sha, 'origin/main'], cwd=ROOT, check=True))
    version = selected(os.environ, ancestor)
    if args.expected_version and args.expected_version != version:
        raise ValueError('Candidate version does not match publisher identity')
    audit(stable='-' not in version)
    if 'GITHUB_OUTPUT' in os.environ:
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
            output.write(f'version={version}\n')
    print(f'Authorized immutable candidate {version}')


if __name__ == '__main__':
    main()

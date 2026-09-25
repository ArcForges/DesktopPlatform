# SPDX-License-Identifier: AGPL-3.0-only
"""Select and authorize the original main or deliberate stable-tag candidate."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dependency_policy import audit

ROOT = Path(__file__).resolve().parents[2]
STABLE = r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)'
MAIN_CANDIDATE = re.compile(r'1\.0\.0-ci\.([1-9][0-9]*)\.([1-9][0-9]*)')


def selected(env, ancestor):
    """Allocate the candidate version once, before build (preflight): the current run and attempt on
    main, or the canonical stable tag. Publication authorizes it with `authorized`, never re-selects."""
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


def authorized(env, expected, ancestor):
    """Authorize publishing the candidate that preflight allocated for this run.

    The version is allocated once, before build. A failed-jobs-only retry keeps that allocation and
    its producer artifact while the publisher runs in a later attempt, so the candidate is validated
    against this run rather than re-derived from the publisher's own attempt: a main candidate must
    carry this run number and an allocation attempt no later than the current attempt. Re-running
    all jobs allocates and builds a new candidate. Stable tags do not depend on the attempt."""
    current = selected(env, ancestor)
    if env['GITHUB_REF'] != 'refs/heads/main':
        if expected != current:
            raise ValueError('Candidate version does not match publisher identity')
        return expected, None
    match = MAIN_CANDIDATE.fullmatch(expected or '')
    if not match or match[1] != env['GITHUB_RUN_NUMBER'] or int(match[2]) > int(env['GITHUB_RUN_ATTEMPT']):
        raise ValueError('Candidate version does not match publisher identity')
    return expected, int(match[2])


def bound_candidate(env, version, allocated, manifest, artifact_name):
    """The downloaded artifact is the authorized candidate: this source, version and workflow run,
    packed at or after the allocation attempt and no later than the current attempt, under the artifact
    name of that producing attempt. An artifact from another run, attempt or candidate is rejected."""
    build = manifest.get('build') if isinstance(manifest.get('build'), dict) else {}
    if manifest.get('version') != version or manifest.get('sourceCommit') != env['GITHUB_SHA']:
        raise ValueError('Candidate manifest does not match the authorized version and source')
    run_id, attempt = build.get('runId'), str(build.get('runAttempt') or '')
    if run_id != env.get('GITHUB_RUN_ID') or not re.fullmatch('[1-9][0-9]*', attempt):
        raise ValueError('Candidate was not produced by this workflow run')
    produced = int(attempt)
    if produced > int(env['GITHUB_RUN_ATTEMPT']) or (allocated is not None and produced < allocated):
        raise ValueError('Candidate producer attempt is outside its allocation')
    if artifact_name != f'nuget-candidate-{run_id}-{produced}':
        raise ValueError('Candidate artifact name does not match its producer')
    return produced


def publication(env, expected, manifest, artifact_name, ancestor):
    version, allocated = authorized(env, expected, ancestor)
    produced = bound_candidate(env, version, allocated, manifest, artifact_name)
    return version, allocated, produced


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-version', help='authorize this allocated candidate for publication')
    parser.add_argument('--manifest', type=Path, help='manifest.json of the downloaded candidate artifact')
    parser.add_argument('--artifact-name', help='name of the downloaded candidate artifact')
    args = parser.parse_args()
    def ancestor(commit):
        verified_tag(os.environ['GITHUB_REF'], commit,
            lambda ref: subprocess.check_output(['git', 'rev-parse', '--verify', ref], cwd=ROOT, text=True).strip(),
            lambda sha: subprocess.run(['git', 'merge-base', '--is-ancestor', sha, 'origin/main'], cwd=ROOT, check=True))
    if args.expected_version is None:
        version = selected(os.environ, ancestor)
        message = f'Allocated immutable candidate {version}'
    else:
        if not (args.manifest and args.artifact_name):
            raise ValueError('Publication requires the candidate --manifest and --artifact-name')
        manifest = json.loads(args.manifest.read_text(encoding='utf-8'))
        version, allocated, produced = publication(os.environ, args.expected_version, manifest,
                                                   args.artifact_name, ancestor)
        message = (f'Authorized immutable candidate {version}'
                   + (f' (allocated in attempt {allocated}, packed in attempt {produced}, '
                      f'publishing in attempt {os.environ["GITHUB_RUN_ATTEMPT"]})' if allocated else ''))
    audit(stable='-' not in version)
    if 'GITHUB_OUTPUT' in os.environ:
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
            output.write(f'version={version}\n')
    print(message)


if __name__ == '__main__':
    main()

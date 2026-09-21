# SPDX-License-Identifier: AGPL-3.0-only
"""Resolve independent compatibility axes and immutable, non-secret build identity."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

AXES = ('AppVersion', 'ContractSet', 'CapabilityVersion', 'NativeFormatVersion',
        'StorageSchemaVersion', 'NativeAbiVersion', 'PolicySchemaVersion',
        'ExtensionProtocolVersion', 'PackageVersion')
KINDS = dict(zip(AXES, ('release', 'contracts', 'declarations', 'declarations',
                      'migrations', 'native-abi', 'declarations', 'declarations', 'packages'), strict=True))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode('utf-8')


def git(root, *args):
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith('GIT_')}
    return subprocess.check_output(['git', *args], cwd=root, env=env, text=True, encoding='utf-8').strip()


def build_identity(root, environment=None):
    env = os.environ if environment is None else environment
    commit = git(root, 'rev-parse', 'HEAD')
    require(re.fullmatch('[a-f0-9]{40}', commit), 'Expected a full source commit.')
    identity = {'sourceCommit': commit, 'sourceDateEpoch': int(git(root, 'show', '-s', '--format=%ct', 'HEAD')),
                'dirty': bool(git(root, 'status', '--porcelain')), 'kind': 'local',
                'buildId': 'local.' + commit, 'pipelineRun': None, 'runId': None, 'runAttempt': None}
    if env.get('GITHUB_ACTIONS') == 'true':
        require(env.get('GITHUB_SHA') == commit, 'CI source differs from checked-out commit.')
        number, attempt, repository = (env.get(k, '') for k in
                                       ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_REPOSITORY'))
        require(re.fullmatch('[1-9][0-9]*', number) and re.fullmatch('[1-9][0-9]*', attempt)
                and re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository), 'Incomplete CI identity.')
        identity.update(kind='ci', buildId=number + '.' + attempt, runId=number, runAttempt=attempt,
                        pipelineRun=f'https://github.com/{repository}/actions/runs/{number}')
        require(not identity['dirty'], 'CI candidate source is dirty.')
    validate_identity(identity)
    return identity


def validate_identity(identity, commit=None, publish=False):
    require(set(identity) == {'sourceCommit', 'sourceDateEpoch', 'dirty', 'kind', 'buildId',
                              'pipelineRun', 'runId', 'runAttempt'}, 'Unknown/missing identity fields.')
    require(re.fullmatch('[a-f0-9]{40}', identity['sourceCommit']), 'Invalid source identity.')
    require(commit is None or identity['sourceCommit'] == commit, 'Build source mismatch.')
    require(type(identity['sourceDateEpoch']) is int and identity['sourceDateEpoch'] > 0
            and type(identity['dirty']) is bool, 'Invalid timestamp/dirty state.')
    require(identity['kind'] in {'ci', 'local'}, 'Invalid build kind.')
    if identity['kind'] == 'ci':
        number, attempt = identity['runId'], identity['runAttempt']
        require(isinstance(number, str) and re.fullmatch('[1-9][0-9]*', number)
                and isinstance(attempt, str) and re.fullmatch('[1-9][0-9]*', attempt), 'Invalid pipeline run/attempt.')
        require(identity['buildId'] == number + '.' + attempt and not identity['dirty'], 'Invalid CI build identity.')
        require(isinstance(identity['pipelineRun'], str) and re.fullmatch(
            r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/' + number,
            identity['pipelineRun']), 'Pipeline run mismatch.')
    else:
        require(identity['buildId'] == 'local.' + identity['sourceCommit']
                and all(identity[k] is None for k in ('pipelineRun', 'runId', 'runAttempt')), 'Invalid local identity.')
    require(not publish or identity['kind'] == 'ci', 'Only a clean CI identity is publishable.')


def source(root, relative):
    require(isinstance(relative, str) and relative and '\\' not in relative
            and not Path(relative).is_absolute() and '..' not in Path(relative).parts,
            'Unsafe version source path.')
    for part in [root / relative, *(root / relative).parents]:
        if part == root:
            break
        require(not part.is_symlink(), 'Linked version sources are forbidden.')
    path = (root / relative).resolve()
    require(path.is_relative_to(root.resolve()) and path.is_file() and not path.is_symlink(), 'Missing/escaping version source.')
    # Git text is LF-normalized so checkout newline conversion is not a version change.
    text = path.read_text(encoding='utf-8').replace('\r\n', '\n')
    return text, {'path': relative, 'sha256Lf': hashlib.sha256(text.encode('utf-8')).hexdigest()}


def resolve_axes(root, catalog, release=None, packages=()):
    require(set(catalog) == {'schemaVersion', 'owner', 'axes'} and catalog['schemaVersion'] == 1,
            'Invalid version source catalog.')
    require(set(catalog['axes']) == set(AXES), 'Exactly nine version axes are required.')
    result = {}
    for axis in AXES:
        config = catalog['axes'][axis]
        require(set(config) <= {'kind', 'sources', 'absence', 'reason', 'producer', 'subject'}
                and config.get('kind') == KINDS[axis], 'Invalid/cross-axis source resolver: ' + axis)
        values = []
        for relative in config.get('sources', []):
            text, evidence = source(root, relative)
            kind = config['kind']
            if kind == 'native-abi':
                major = re.search(r'#define ARC_NATIVE_ABI_MAJOR UINT32_C\((\d+)\)', text)
                minor = re.search(r'#define ARC_NATIVE_ABI_MINOR UINT32_C\((\d+)\)', text)
                require(major and minor, 'Missing actual ABI constants.')
                rows = [{'subject': 'arc-native', 'version': major[1] + '.' + minor[1]}]
            elif kind == 'contracts':
                namespaces = re.findall(r'^package ([a-z][a-z0-9_.]+)\.v([1-9][0-9]*);', text, re.MULTILINE)
                require(namespaces, 'Missing authored contract namespace version.')
                rows = [{'subject': name, 'version': version} for name, version in namespaces]
            elif kind == 'migrations':
                migrations = json.loads(text)
                require(isinstance(migrations, list) and migrations, 'Empty declared migration set.')
                require(all(set(m) == {'version', 'subject'} and type(m['version']) is int
                            and m['version'] > 0 for m in migrations), 'Invalid migration head source.')
                rows = [{'subject': name, 'version': str(max(m['version'] for m in migrations if m['subject'] == name))}
                        for name in sorted({m['subject'] for m in migrations})]
            elif kind == 'declarations':
                rows = json.loads(text)
                require(isinstance(rows, list) and rows, 'Empty version declaration file.')
            else:
                raise ValueError('Unexpected file source for ' + axis)
            for row in rows:
                require(set(row) == {'subject', 'version'}, 'Unknown declaration or cross-axis alias.')
                values.append({**row, 'source': evidence})
        if config['kind'] == 'release' and config.get('subject'):
            require(isinstance(release, str), 'Missing independent application release input.')
            values.append({'subject': config['subject'], 'version': release,
                           'source': {'input': 'allocated-application-release'}})
        if config['kind'] == 'packages':
            values.extend(copy.deepcopy(packages))
        if values:
            result[axis] = {'status': 'present', 'values': sorted(values, key=lambda row: row['subject'])}
        else:
            require(config.get('absence') in {'not-applicable', 'not-produced'} and config.get('reason'),
                    'Absent axis requires explicit applicability: ' + axis)
            require(config['absence'] != 'not-produced' or config.get('producer'), 'Missing future producer.')
            result[axis] = {'status': config['absence'], 'values': [], 'reason': config['reason']}
            if config.get('producer'):
                result[axis]['producer'] = config['producer']
    validate_axes(result)
    return result


def validate_axes(axes):
    require(set(axes) == set(AXES), 'Exactly nine version axes are required.')
    for name, axis in axes.items():
        require(axis.get('status') in {'present', 'not-applicable', 'not-produced'}, 'Invalid axis state.')
        require(set(axis) == ({'status', 'values'} if axis['status'] == 'present' else
                {'status', 'values', 'reason'} | ({'producer'} if 'producer' in axis else set())), 'Unknown axis fields.')
        values = axis['values']
        require(isinstance(values, list) and (bool(values) == (axis['status'] == 'present')), 'Invalid axis values.')
        require(len({v['subject'] for v in values}) == len(values), 'Duplicate version subject: ' + name)
        if not values:
            require(isinstance(axis['reason'], str) and axis['reason'].strip(), 'Empty absence reason.')
            require(axis['status'] != 'not-produced' or bool(axis.get('producer')), 'Missing later producer.')
        for row in values:
            require(set(row) == {'subject', 'version', 'source'} and isinstance(row['subject'], str)
                    and 0 < len(row['subject']) <= 256, 'Malformed version subject.')
            version = row['version']
            require(isinstance(version, str) and version not in AXES and re.fullmatch(
                r'[0-9][A-Za-z0-9.+:-]{0,127}', version), 'Invalid version or cross-axis alias.')
            evidence = row['source']
            require(isinstance(evidence, dict), 'Version source evidence is missing.')
            if set(evidence) == {'input'}:
                require(name == 'AppVersion' and evidence['input'] == 'allocated-application-release',
                        'Invalid application release evidence.')
            else:
                keys = set(evidence)
                require(keys in ({'path', 'sha256Lf'}, {'artifact', 'sha256'}), 'Unknown source evidence.')
                path_key, hash_key = ('path', 'sha256Lf') if 'path' in evidence else ('artifact', 'sha256')
                path = evidence[path_key]
                require(isinstance(path, str) and path and not Path(path).is_absolute()
                        and '..' not in Path(path).parts and '\\' not in path, 'Unsafe evidence path.')
                require(isinstance(evidence[hash_key], str) and re.fullmatch('[a-f0-9]{64}', evidence[hash_key]),
                        'Invalid source digest.')


def dependency_versions(root, native_directory=None, native_documents=()):
    result = {}
    for relative in git(root, 'ls-files').splitlines():
        if not relative.endswith('packages.lock.json'):
            continue
        text, evidence = source(root, relative)
        for target in json.loads(text)['dependencies'].values():
            for name, package in target.items():
                if package['type'] == 'Project':
                    continue
                version = package['resolved']
                subject = 'nuget:' + name + '@' + version
                result[subject] = {'subject': subject, 'version': version, 'source': evidence}
    documents = list(native_documents)
    if native_directory:
        documents.extend((path.parent.name + '/sbom.json', path.read_bytes())
                         for path in sorted(native_directory.glob('*/sbom.json')))
    for name, raw in sorted(documents):
        evidence = {'artifact': name, 'sha256': hashlib.sha256(raw).hexdigest()}
        for package in json.loads(raw)['buildDependencies']:
            version = package['version']
            subject = 'vcpkg:' + package['name'] + ':' + package['triplet'] + '@' + version
            result[subject] = {'subject': subject, 'version': version, 'source': evidence}
    return [result[key] for key in sorted(result)]


def report(root, artifact, version, native_directory=None):
    catalog = json.loads((root / 'eng/version-sources.json').read_text(encoding='utf-8'))
    return {'schema': 'arcforges.build-identity.v1', 'owner': catalog['owner'],
            'artifact': {'id': artifact, 'version': version}, 'build': build_identity(root),
            'axes': resolve_axes(root, catalog, packages=dependency_versions(root, native_directory))}


def verify_report(value, artifact, version, commit, publish=False):
    require(set(value) == {'schema', 'owner', 'artifact', 'build', 'axes'}
            and value['schema'] == 'arcforges.build-identity.v1' and value['owner'] == 'DesktopPlatform',
            'Unknown build report schema/owner.')
    require(value['artifact'] == {'id': artifact, 'version': version}, 'Build report artifact mismatch.')
    validate_identity(value['build'], commit, publish)
    validate_axes(value['axes'])


def verify_source_build(root, identity):
    validate_identity(identity)
    require(identity['sourceCommit'] == git(root, 'rev-parse', 'HEAD'), 'Verifier checkout source mismatch.')
    require(identity['sourceDateEpoch'] == int(git(root, 'show', '-s', '--format=%ct', 'HEAD')),
            'Source timestamp mismatch.')
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        validate_identity(identity, os.environ['GITHUB_SHA'], publish=True)
        require(identity['runId'] == os.environ['GITHUB_RUN_ID']
                and int(identity['runAttempt']) <= int(os.environ['GITHUB_RUN_ATTEMPT'])
                and identity['pipelineRun'] == 'https://github.com/' + os.environ['GITHUB_REPOSITORY']
                + '/actions/runs/' + os.environ['GITHUB_RUN_ID'], 'Unexpected producer pipeline identity.')


def native_suffix(identity):
    validate_identity(identity)
    return ''.join(';' + key + '=' + str(value) for key, value in (
        ('source', identity['sourceCommit']), ('build', identity['buildId']),
        ('run', identity['pipelineRun'] or 'local'), ('sourceDateEpoch', identity['sourceDateEpoch']),
        ('kind', identity['kind']), ('dirty', str(identity['dirty']).lower())))


def write_native_header(root, output):
    identity = build_identity(root)
    content = ('// SPDX-License-Identifier: AGPL-3.0-only\n#pragma once\n'
               'inline constexpr char arc_build_identity[] = ' + json.dumps(native_suffix(identity)) + ';\n').encode('utf-8')
    output.parent.mkdir(parents=True, exist_ok=True)
    if not output.exists() or output.read_bytes() != content:
        output.write_bytes(content)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-header', type=Path, required=True)
    args = parser.parse_args()
    write_native_header(Path(__file__).resolve().parents[1], args.native_header)

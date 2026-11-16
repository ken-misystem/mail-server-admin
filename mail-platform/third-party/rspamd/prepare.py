"""Prepare the pinned Debian Rspamd source backport. No install or service operations.

Copyright (c) 2026 MI-SYSTEM. This helper is MIT licensed.
The patch and upstream tests retain Apache-2.0; see NOTICE.md.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def checked(path, digest):
    if path.is_symlink() or not path.is_file():
        raise ValueError('regular_input_required:' + path.name)
    raw = path.read_bytes()
    if sha(raw) != digest:
        raise ValueError('input_hash_mismatch:' + path.name)
    return raw


def prepare(cache, output):
    lock = json.loads((HERE / 'source-lock.json').read_bytes())
    inputs = {name: checked(Path(cache) / name, row['sha256']) for name, row in lock['sources'].items()}
    materials = {name: checked(HERE / name, digest) for name, digest in lock['materials'].items()}
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError('new_output_required')
    output.mkdir(mode=0o700)
    operations = []

    def command(args, cwd):
        p = subprocess.run(args, cwd=cwd, capture_output=True, timeout=120)
        index = len(operations)
        for suffix, raw in [('stdout', p.stdout), ('stderr', p.stderr)]:
            (output / f'{index}.{suffix}').write_bytes(raw)
        operations.append({'args': args, 'exit': p.returncode,
                           'stdout_sha256': sha(p.stdout), 'stderr_sha256': sha(p.stderr)})
        if p.returncode:
            raise RuntimeError('source_preparation_command_failed:' + str(index))

    result = {'status': 'FAIL', 'operations': operations, 'host_changed': False,
              'package_built': False, 'package_installed': False}
    try:
        for name, raw in inputs.items():
            (output / name).write_bytes(raw)
        # Exact .dsc and both archives are authenticated by the reviewed lock above.
        command(['dpkg-source', '--no-check', '-x', 'rspamd_3.12.1-1.dsc', 'source'], output)
        source = output / 'source'
        target = source / lock['target']
        checked(target, lock['before_sha256'])
        patch = source / 'debian/patches/0004-symcache-persistence.patch'
        if patch.exists():
            raise ValueError('patch_already_exists')
        patch.write_bytes(materials['symcache-persistence.patch'])
        command(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)], source)
        checked(target, lock['after_sha256'])
        series = source / 'debian/patches/series'
        series.write_bytes(series.read_bytes().rstrip(b'\n') + b'\n0004-symcache-persistence.patch\n')
        test = source / 'test/rspamd_cxx_unit_symcache_persistence.hxx'
        if test.exists():
            raise ValueError('test_already_exists')
        test.write_bytes(materials['rspamd_cxx_unit_symcache_persistence.hxx'])
        runner = source / 'test/rspamd_cxx_unit.cxx'
        runner.write_bytes(runner.read_bytes() + b'\n#include "rspamd_cxx_unit_symcache_persistence.hxx"\n')
        changelog = source / 'debian/changelog'
        original = changelog.read_bytes()
        if not original.startswith(b'rspamd (3.12.1-1) '):
            raise ValueError('debian_version_mismatch')
        changelog.write_bytes(materials['changelog-entry.txt'] + original)
        result.update(status='PASS', version=lock['package_version'],
                      source_sha256=sha(target.read_bytes()),
                      patched_files={str(p.relative_to(source)): sha(p.read_bytes()) for p in
                                     (target, patch, series, test, runner, changelog)})
    except Exception as exc:
        result['failure'] = {'type': type(exc).__name__, 'detail': str(exc)}
        raise
    finally:
        raw = (json.dumps(result, indent=2) + '\n').encode()
        (output / 'result.json').write_bytes(raw)
        if (output / 'result.json').read_bytes() != raw:
            raise RuntimeError('result_readback_mismatch')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-cache', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.source_cache, args.output)))

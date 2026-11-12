"""Prepare, sign and verify local release assets from the registered repository sources."""
import argparse
import getpass
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE/'framework'))
from release import build, canonical, inspect, require, sha, sign, version
from build import prepare as prepare_sources
from distribution_inventory import inventory

ASSETS = ('mail-platform.tar.gz', 'release.json', 'release.sig')
REQUIRED_READINESS = frozenset((
    'empty_Debian13_install_validated', 'dynamic_UID_GID_portability_validated',
    'authenticated_update_UI_validated', 'production_update_hook_Linux_validated',
    'release_signing_key_provisioned', 'custom_Dovecot_distribution_validated',
    'third_party_distribution_review_completed'))


def write_new(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def readiness(path):
    raw = Path(path).read_bytes()
    values = json.loads(raw)
    require(type(values) is dict and values, 'readiness_shape')
    pending = sorted({name for name, value in values.items() if value is not True}
                     | (REQUIRED_READINESS - values.keys()))
    return {'sha256': sha(raw), 'pending': pending, 'install_ready': not pending}


def update_contract(value, release_version):
    fields = {'format', 'from_version', 'to_version', 'pause', 'stop', 'start', 'reload', 'health'}
    require(type(value) is dict and set(value) == fields and value['format'] == 1, 'update_contract_shape')
    require(value['to_version'] == release_version and version(value['from_version']) < version(release_version), 'update_contract_version')
    for action in ('pause', 'stop', 'start', 'reload', 'health'):
        names = value[action]
        require(type(names) is list and all(type(name) is str for name in names), 'update_contract_units')
        require(len(names) == len(set(names)), 'update_contract_duplicates')
    require(set(value['stop']) == set(value['start']), 'update_contract_stop_start')
    require(value['health'], 'update_contract_health')
    return value


def prepare(repository, release_version, contract_path, output, install_ready=False):
    version(release_version)
    gate = readiness(HERE/'readiness.json')
    require(not install_ready or gate['install_ready'], 'release_validation_pending')
    contract = update_contract(json.loads(Path(contract_path).read_bytes()), release_version)
    output = Path(output)
    require(not output.exists(), 'release_output_exists')
    sources, provenance = prepare_sources(repository)
    sources['payload/blueprint/update-contract.json'] = canonical(contract)
    payload = {name: raw for name, raw in sources.items() if name.startswith('payload/')}
    require('payload/installer.py' in payload, 'release_hook_missing')
    output.mkdir(mode=0o700, parents=True)
    # The staging tree contains public code only and is removed after building.
    with tempfile.TemporaryDirectory(prefix='mail-release-public-') as temporary:
        root = Path(temporary)
        entries = []
        for name, raw in sorted(payload.items()):
            path = root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            entries.append({'name': name, 'source': name, 'sha256': sha(raw), 'mode': 0o644})
        metadata = build(root, entries, release_version, output/ASSETS[0], ready=install_ready)
    write_new(output/ASSETS[1], canonical(metadata))
    distribution = inventory(payload)
    write_new(output/'distribution-inventory.json', canonical(distribution))
    record = {'format': 1, 'status': 'prepared_unsigned', 'version': release_version,
              'install_ready': install_ready, 'readiness': gate, 'metadata': metadata,
              'payload_files': len(payload), 'provenance': provenance,
              'distribution_inventory_sha256': sha((output/'distribution-inventory.json').read_bytes()),
              'metadata_sha256': sha((output/ASSETS[1]).read_bytes())}
    write_new(output/'prepare-result.json', canonical(record))
    return record


def prepared(directory):
    directory = Path(directory)
    require(directory.is_dir() and not directory.is_symlink(), 'release_directory')
    for name in (ASSETS[0], ASSETS[1], 'prepare-result.json'):
        path = directory/name
        require(path.is_file() and not path.is_symlink(), 'prepared_asset_type')
    record = json.loads((directory/'prepare-result.json').read_bytes())
    raw = (directory/ASSETS[1]).read_bytes()
    metadata = json.loads(raw)
    require(record['metadata'] == metadata and sha(raw) == record['metadata_sha256'], 'prepared_metadata_drift')
    require(sha((directory/ASSETS[0]).read_bytes()) == metadata['sha256'], 'prepared_archive_drift')
    with tarfile.open(directory/ASSETS[0], 'r:gz') as stream:
        manifests = [member for member in stream.getmembers() if member.name == 'bundle.json']
        require(len(manifests) == 1 and manifests[0].isfile(), 'prepared_manifest')
        manifest_raw = stream.extractfile(manifests[0]).read()
    require(sha(manifest_raw) == metadata['manifest_sha256'], 'prepared_manifest_drift')
    manifest = json.loads(manifest_raw)
    require(manifest['version'] == record['version'] == metadata['version'], 'prepared_version_drift')
    require(manifest['install_ready'] is record['install_ready'], 'prepared_readiness_drift')
    return record, metadata


def signing_readiness(record, candidate):
    if not candidate:
        current = readiness(HERE/'readiness.json')
        require(record['install_ready'] and current['install_ready'], 'release_validation_pending')
        require(record['readiness']['sha256'] == current['sha256'], 'readiness_changed_after_prepare')
    else:
        require(record['install_ready'] is False, 'candidate_signature_requires_noninstallable_bundle')


def sign_prepared(directory, key, public_key, passphrase, openssl='openssl', candidate=False):
    directory = Path(directory)
    record, metadata = prepared(directory)
    require(not (directory/ASSETS[2]).exists(), 'signature_exists')
    signing_readiness(record, candidate)
    with Path(key).open('rb') as stream:
        header = stream.readline(80)
    require(header.rstrip() == b'-----BEGIN ENCRYPTED PRIVATE KEY-----', 'encrypted_signing_key_required')
    signature = sign(metadata, key, openssl, passphrase=passphrase)
    manifest, files = inspect(directory/ASSETS[0], metadata, signature, public_key, openssl)
    require(manifest['install_ready'] is record['install_ready'], 'signed_readiness_mismatch')
    write_new(directory/ASSETS[2], (signature+'\n').encode())
    result = {'status': 'signed_candidate' if candidate else 'signed_release',
              'version': metadata['version'], 'install_ready': manifest['install_ready'],
              'verified_files': len(files), 'public_key_sha256': sha(Path(public_key).read_bytes()),
              'assets': {name: sha((directory/name).read_bytes()) for name in ASSETS}}
    write_new(directory/'sign-result.json', canonical(result))
    return result


def verify(directory, public_key, openssl='openssl'):
    directory = Path(directory)
    record, metadata = prepared(directory)
    signature = (directory/ASSETS[2]).read_text().strip()
    manifest, files = inspect(directory/ASSETS[0], metadata, signature, public_key, openssl)
    require(manifest['install_ready'] is record['install_ready'], 'verified_readiness_mismatch')
    return {'status': 'verified', 'version': manifest['version'],
            'install_ready': manifest['install_ready'], 'files': len(files)}


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest='action', required=True)
    commands.add_parser('plan')
    prepare_command = commands.add_parser('prepare')
    prepare_command.add_argument('--repository-root', type=Path, required=True)
    prepare_command.add_argument('--version', required=True)
    prepare_command.add_argument('--update-contract', type=Path, required=True)
    prepare_command.add_argument('--output', type=Path, required=True)
    prepare_command.add_argument('--install-ready', action='store_true')
    signing = commands.add_parser('sign')
    signing.add_argument('--directory', type=Path, required=True)
    signing.add_argument('--key', type=Path, required=True)
    signing.add_argument('--public-key', type=Path, required=True)
    signing.add_argument('--candidate', action='store_true')
    signing.add_argument('--openssl', default='openssl')
    checking = commands.add_parser('verify')
    checking.add_argument('--directory', type=Path, required=True)
    checking.add_argument('--public-key', type=Path, required=True)
    checking.add_argument('--openssl', default='openssl')
    arguments = parser.parse_args()
    if arguments.action == 'plan':
        result = readiness(HERE/'readiness.json')
    elif arguments.action == 'prepare':
        result = prepare(arguments.repository_root, arguments.version, arguments.update_contract,
                         arguments.output, arguments.install_ready)
    elif arguments.action == 'sign':
        record, _ = prepared(arguments.directory)
        signing_readiness(record, arguments.candidate)
        password = getpass.getpass('署名鍵のパスフレーズ: ').encode()
        result = sign_prepared(arguments.directory, arguments.key, arguments.public_key,
                               password, arguments.openssl, arguments.candidate)
    else:
        result = verify(arguments.directory, arguments.public_key, arguments.openssl)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()

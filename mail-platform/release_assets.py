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

ASSETS = ('mail-platform.tar.gz', 'release.json', 'release.sig')
REQUIRED_READINESS = frozenset((
    'empty_Debian13_install_validated', 'dynamic_UID_GID_portability_validated',
    'authenticated_update_UI_validated', 'production_update_hook_Linux_validated',
    'release_signing_key_provisioned', 'custom_Dovecot_distribution_validated',
    'third_party_distribution_review_completed', 'secure_initial_setup_validated',
    'ACME_DNS01_lifecycle_Linux_validated','TLS_pair_activation_recovery_Linux_validated',
    'CA_overlap_rotation_recovery_Linux_validated','certificate_runtime_upgrade_migration_validated'))


def write_new(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def readiness(path, contract_format=1):
    raw = Path(path).read_bytes()
    values = json.loads(raw)
    require(type(values) is dict and values, 'readiness_shape')
    require(type(contract_format) is int and contract_format in (1, 2), 'readiness_contract_format')
    generation_flag = 'delivery_preserving_updates_validated'
    required = REQUIRED_READINESS | ({generation_flag} if contract_format == 2 else set())
    pending = {name for name, value in values.items() if value is not True}
    if contract_format == 1:
        pending.discard(generation_flag)
    pending = sorted(pending | (required - values.keys()))
    return {'sha256': sha(raw), 'pending': pending, 'install_ready': not pending,
            'update_contract_format': contract_format,
            'generation_updates_validated': values.get(generation_flag) is True}


def update_contract(value, release_version):
    require(type(value) is dict and type(value.get('format')) is int, 'update_contract_shape')
    if value.get('format') == 2:
        fields = {'format', 'from_version', 'to_version', 'components', 'configuration_sha256'}
        require(set(value) == fields, 'availability_contract_shape')
        require(value['to_version'] == release_version and version(value['from_version']) < version(release_version), 'availability_contract_version')
        import re
        require(type(value['components']) is list and value['components'] and
                all(type(name) is str and re.fullmatch('[a-z][a-z0-9-]{0,30}', name) for name in value['components']) and
                len(value['components']) == len(set(value['components'])), 'availability_contract_components')
        require(type(value['configuration_sha256']) is str and re.fullmatch('[a-f0-9]{64}', value['configuration_sha256']), 'availability_contract_digest')
        return value
    fields = {'format', 'from_version', 'to_version', 'pause', 'stop', 'start', 'reload', 'health'}
    if 'optional_units' in value:
        from host_install import LEGACY_UNITS
        optional = value['optional_units']
        require(type(optional) is list and all(type(n) is str and n in LEGACY_UNITS for n in optional)
                and len(optional) == len(set(optional)), 'update_optional_units')
        fields.add('optional_units')
    require(type(value) is dict and set(value) == fields and type(value['format']) is int and value['format'] == 1, 'update_contract_shape')
    from update_sources import sources
    require(value['to_version'] == release_version, 'update_contract_version')
    sources(value['from_version'], release_version)
    for action in ('pause', 'stop', 'start', 'reload', 'health'):
        names = value[action]
        require(type(names) is list and all(type(name) is str for name in names), 'update_contract_units')
        require(len(names) == len(set(names)), 'update_contract_duplicates')
    require(set(value['stop']) == set(value['start']), 'update_contract_stop_start')
    require(value['health'], 'update_contract_health')
    return value


def prepare(repository, release_version, contract_path, output, install_ready=False, roundcube_settings='plugin',
            sieve_migration_kit=None, sieve_migration_from=None, native_requirements_path=None,
            monitor_environment_migration=False, code_only=False, native_migration=None):
    version(release_version)
    contract = update_contract(json.loads(Path(contract_path).read_bytes()), release_version)
    gate = readiness(HERE/'readiness.json', 2 if native_migration else contract['format'])
    require(not install_ready or gate['install_ready'], 'release_validation_pending')
    output = Path(output)
    require(not output.exists(), 'release_output_exists')
    sources, provenance = prepare_sources(repository, roundcube_settings)
    if code_only:
        require(not sieve_migration_kit and contract['format'] == 1, 'code_only_contract')
        # A fresh-install descriptor is not a request to repeat certificate adoption.
        sources.pop('payload/blueprint/migrations/certificates-v1/manifest.json', None)
        from native_requirements import PRESERVE_DESCRIPTOR, PRESERVE_CONTRACT
        sources[PRESERVE_DESCRIPTOR] = canonical(PRESERVE_CONTRACT)
    require(bool(sieve_migration_kit) == bool(sieve_migration_from), 'sieve_migration_asset_arguments')
    if sieve_migration_kit:
        require(contract['format'] == 1, 'sieve_migration_requires_initial_maintenance')
        from sieve_migration import add_assets
        add_assets(sources, sieve_migration_kit, sieve_migration_from)
    sources['payload/blueprint/update-contract.json'] = canonical(contract)
    if monitor_environment_migration:
        require(contract['format'] == 1 and not sieve_migration_kit, 'monitor_migration_contract_scope')
        from monitor_update import DESCRIPTOR, CONTRACT
        require('payload/'+DESCRIPTOR not in sources, 'duplicate_monitor_migration')
        sources['payload/'+DESCRIPTOR] = canonical(CONTRACT)
    if native_requirements_path:
        from native_requirements import DESCRIPTOR, validate as validate_native
        required = validate_native(json.loads(Path(native_requirements_path).read_bytes()))
        require(DESCRIPTOR not in sources, 'duplicate_native_requirements')
        sources[DESCRIPTOR] = canonical(required)
    if native_migration:
        require(code_only and monitor_environment_migration, 'adaptive_native_contract')
        from native_requirements import PRESERVE_DESCRIPTOR
        sources.pop(PRESERVE_DESCRIPTOR, None)
        from adaptive_update import DESCRIPTOR as ADAPTIVE, CONTRACT as ADAPTIVE_CONTRACT
        from native_package_update import add_assets
        # Every extra byte is included inside the signed archive. No network fetch occurs on update.
        add_assets(sources,native_migration)
        sources['payload/'+ADAPTIVE]=canonical(ADAPTIVE_CONTRACT)
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
    distribution_raw = sources['distribution-inventory.json']
    require(distribution_raw == payload['payload/usr/local/lib/mail-platform-update/licenses/distribution-inventory.json'],
            'distribution_inventory_binding')
    write_new(output/'distribution-inventory.json', distribution_raw)
    write_new(output/'distribution-plan.json', canonical({
        'format':1, 'default_distribution':'product-code-with-notices',
        'update_assets':list(ASSETS),
        'license_inventory':'distribution-inventory.json',
        'components':json.loads(sources['distribution-policy.json'])['components'],
        'third_party_binary_uploads':'signed-rspamd-with-corresponding-source' if native_migration else 'separate-reviewed-component-release'}))
    record = {'format': 1, 'status': 'prepared_unsigned', 'version': release_version,
              'update_contract_format': contract['format'],
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
        contract = json.loads(stream.extractfile('payload/blueprint/update-contract.json').read())
        actual_format = contract.get('format')
        require(type(actual_format) is int and actual_format in (1, 2), 'prepared_contract_format')
        require(record.get('update_contract_format', actual_format) == actual_format, 'prepared_contract_format_drift')
        record['update_contract_format'] = actual_format
    require(sha(manifest_raw) == metadata['manifest_sha256'], 'prepared_manifest_drift')
    manifest = json.loads(manifest_raw)
    require(manifest['version'] == record['version'] == metadata['version'], 'prepared_version_drift')
    require(manifest['install_ready'] is record['install_ready'], 'prepared_readiness_drift')
    return record, metadata


def signing_readiness(record, candidate):
    if not candidate:
        current = readiness(HERE/'readiness.json', record.get('update_contract_format', 1))
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
    prepare_command.add_argument('--roundcube-settings', choices=('legacy', 'plugin'), default='plugin')
    prepare_command.add_argument('--sieve-migration-kit', type=Path)
    prepare_command.add_argument('--sieve-migration-from', type=Path)
    prepare_command.add_argument('--native-requirements', type=Path)
    prepare_command.add_argument('--monitor-environment-migration', action='store_true')
    prepare_command.add_argument('--code-only', action='store_true')
    prepare_command.add_argument('--native-migration', type=Path)
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
                         arguments.output, arguments.install_ready, arguments.roundcube_settings,
                         arguments.sieve_migration_kit, arguments.sieve_migration_from, arguments.native_requirements,
                         arguments.monitor_environment_migration, arguments.code_only, arguments.native_migration)
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

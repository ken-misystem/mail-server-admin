"""Signed release hook. Installed as payload/installer.py in a release archive."""
import argparse
import json
import os
from pathlib import Path
import stat
import sys

PAYLOAD = Path(__file__).resolve().parent
sys.path.insert(0, str(PAYLOAD/'usr/local/lib/mail-platform-update'))
from code_update import CodeUpdate


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['plan', 'stage', 'activate', 'health', 'rollback', 'retire'])
    parser.add_argument('--transaction', type=Path, required=True)
    parser.add_argument('--native-migration-child', action='store_true')
    args = parser.parse_args()
    if os.name != 'posix' or os.geteuid() != 0:
        raise ValueError('root_required')
    directory = args.transaction.resolve(strict=True)
    if directory.parent != Path('/var/lib/mail-platform-update') or not directory.name.startswith('transaction-'):
        raise ValueError('update_transaction_scope')
    for path in [directory, *directory.parents]:
        metadata = path.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError('update_transaction_parent_trust')
    if stat.S_IMODE(directory.stat().st_mode) != 0o700:
        raise ValueError('update_transaction_permissions')
    contract = json.loads((PAYLOAD/'blueprint/update-contract.json').read_bytes())
    engine = CodeUpdate
    if (PAYLOAD/'blueprint/migrations/certificates-v1/manifest.json').is_file():
        from certificate_update import CertificateUpdate
        engine = CertificateUpdate
    elif contract.get('format') == 2:
        from generation_update import GenerationUpdate
        engine = GenerationUpdate
    elif (PAYLOAD/'blueprint/migrations/sieve-lock-v1/manifest.json').is_file():
        from sieve_migration import SieveMigration
        engine = SieveMigration
    elif args.action=='retire':
        raise ValueError('retirement_requires_generation_contract')
    certificate_native = engine.__name__ == 'CertificateUpdate'
    sieve_native = not certificate_native and contract.get('format') != 2 and (PAYLOAD/'blueprint/migrations/sieve-lock-v1/manifest.json').is_file()
    if certificate_native:
        from certificate_update import check_native_child, native_hook
    elif sieve_native:
        from sieve_migration import check_native_child, native_hook
    if certificate_native or sieve_native:
        if not args.native_migration_child:
            result = native_hook(PAYLOAD, directory, args.action)
            sys.stdout.buffer.write(result.stdout)
            sys.stderr.buffer.write(result.stderr)
            raise SystemExit(result.returncode)
        check_native_child(directory, args.action)
    if args.native_migration_child and not (certificate_native or sieve_native):
        raise ValueError('native_migration_requires_signed_descriptor')
    result = getattr(engine(PAYLOAD, directory), args.action)()
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status': 'failed', 'error': type(error).__name__, 'reason': str(error)}))
        raise SystemExit(1)

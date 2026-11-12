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
    parser.add_argument('action', choices=['plan', 'stage', 'activate', 'health', 'rollback'])
    parser.add_argument('--transaction', type=Path, required=True)
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
    result = getattr(CodeUpdate(PAYLOAD, directory), args.action)()
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status': 'failed', 'error': type(error).__name__, 'reason': str(error)}))
        raise SystemExit(1)

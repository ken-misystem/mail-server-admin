"""Report license metadata and notice bytes contained in a prepared public payload."""
import json
from pathlib import PurePosixPath

from framework.release import sha


def notice(name):
    leaf = PurePosixPath(name).name.upper()
    return leaf.startswith(('LICENSE', 'LICENCE', 'COPYING', 'COPYRIGHT', 'NOTICE'))


def inventory(files):
    documents = {name: {'sha256': sha(raw), 'bytes': len(raw)}
                 for name, raw in sorted(files.items()) if notice(name)}
    packages = []
    for name, raw in sorted(files.items()):
        if not name.endswith('/vendor/composer/installed.json'):
            continue
        value = json.loads(raw)
        rows = value if isinstance(value, list) else value['packages']
        vendor = name.removesuffix('composer/installed.json')
        for row in rows:
            package_name = row['name']
            parts = package_name.split('/')
            if len(parts) != 2 or any(part in ('', '.', '..') or '\\' in part for part in parts):
                raise ValueError('composer_package_name')
            root = vendor+package_name+'/'
            composer = files.get(root+'composer.json')
            metadata = json.loads(composer) if composer is not None else {}
            licenses = row.get('license', metadata.get('license', []))
            if isinstance(licenses, str):
                licenses = [licenses]
            if not isinstance(licenses, list) or not all(isinstance(item, str) for item in licenses):
                raise ValueError('composer_license_metadata')
            packages.append({'name': package_name, 'version': row.get('version'), 'root': root,
                             'declared_licenses': licenses,
                             'notices': sorted(path for path in documents if path.startswith(root)),
                             'source_reference': row.get('source', {}).get('reference')})
    return {'format': 1, 'scope': 'metadata_and_file_inventory_only',
            'packages': packages, 'notice_files': documents,
            'missing_license_metadata': sorted(row['root'] for row in packages if not row['declared_licenses']),
            'packages_without_notice_file': sorted(row['root'] for row in packages if not row['notices']),
            'external_private_kit_components': [
                {'name': 'custom Dovecot cnfix1 packages', 'source_in_this_payload': False,
                 'redistribution_review': 'pending'},
                {'name': 'ClamAV runtime and official definitions', 'runtime_in_this_payload': False,
                 'redistribution_review': 'pending'}],
            'legal_compliance_assessment': 'not_performed'}

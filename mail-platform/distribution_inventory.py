"""Report license metadata and notice bytes contained in a prepared public payload."""
import json
import hashlib
import io
import zipfile
from pathlib import PurePosixPath

def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def notice(name):
    leaf = PurePosixPath(name).name.upper()
    return leaf.startswith(('LICENSE', 'LICENCE', 'COPYING', 'COPYRIGHT', 'NOTICE'))


def inventory(files, policy=None):
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
    wheels = []
    for name, raw in sorted(files.items()):
        if not name.endswith('.whl'):
            continue
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            metadata_names = [item for item in archive.namelist() if item.endswith('.dist-info/METADATA')]
            if len(metadata_names) != 1:
                raise ValueError('wheel_license_metadata')
            metadata = archive.read(metadata_names[0]).decode()
            selected = {}
            for line in metadata.splitlines():
                key, separator, value = line.partition(': ')
                if separator and key in ('Name', 'Version', 'License-Expression', 'License'):
                    selected[key] = value
            notices = {}
            for item in archive.namelist():
                if notice(item):
                    content = archive.read(item)
                    notices[item] = {'bytes':len(content), 'sha256':sha(content)}
            wheels.append({'path':name, 'sha256':sha(raw), 'metadata':selected, 'notices':notices})
    result = {'format': 1, 'scope': 'metadata_and_file_inventory_only',
            'packages': packages, 'notice_files': documents,
            'missing_license_metadata': sorted(row['root'] for row in packages if not row['declared_licenses']),
            'packages_without_notice_file': sorted(row['root'] for row in packages if not row['notices']),
            'external_private_kit_components': [
                {'name': 'custom Dovecot cnfix1 packages', 'source_in_this_payload': False,
                 'redistribution_review': 'pending'},
                {'name': 'ClamAV runtime and official definitions', 'runtime_in_this_payload': False,
                 'redistribution_review': 'pending'}],
            'legal_compliance_assessment': 'not_performed', 'python_wheels':wheels,
            'wheels_without_license_metadata':[row['path'] for row in wheels
                if not (row['metadata'].get('License-Expression') or row['metadata'].get('License'))],
            'wheels_without_notice':[row['path'] for row in wheels if not row['notices']]}
    if policy is not None:
        if policy.get('format') != 1 or policy.get('original_code', {}).get('license') != 'MIT':
            raise ValueError('distribution_policy')
        result['original_code'] = policy['original_code']
        result['components'] = policy['components']
        result['default_distribution'] = policy['default_distribution']
        result['external_private_kit_components'] = [
            item for item in policy['components']
            if item['provision'] in ('target-build-from-corresponding-source','official-download-and-local-preparation')]
    return result


def include_materials(files, policy):
    """Embed identical inventory in installation and signed update payloads."""
    result = inventory(files, policy)
    if any(result[name] for name in ('missing_license_metadata','packages_without_notice_file',
                                    'wheels_without_license_metadata','wheels_without_notice')):
        raise ValueError('distribution_license_material_missing')
    rules = {item['name']:item for item in policy['components']}
    composer_licenses = rules['Composer dependencies']['licenses']
    wheel_licenses = rules['PyMySQL']['licenses']
    if any(not set(row['declared_licenses']) <= set(composer_licenses) for row in result['packages']):
        raise ValueError('distribution_dependency_license_change')
    if any((row['metadata'].get('License-Expression') or row['metadata'].get('License')) not in wheel_licenses
           for row in result['python_wheels']):
        raise ValueError('distribution_dependency_license_change')
    from native_assets import BINARIES
    external_binaries = {'payload/'+name for name in BINARIES}
    external_libraries = ('payload/usr/local/lib/libclam','payload/usr/local/lib/libfreshclam')
    if any(name.endswith(('.deb','.cvd','.cld')) or name in external_binaries
           or name.startswith(external_libraries) for name in files):
        raise ValueError('product_bundle_external_binary')
    raw = (json.dumps(result,sort_keys=True,indent=2)+'\n').encode()
    files['distribution-inventory.json'] = raw
    files['payload/usr/local/lib/mail-platform-update/licenses/distribution-inventory.json'] = raw
    return result

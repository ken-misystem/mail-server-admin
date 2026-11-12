"""Prepare pinned public native runtime and corresponding-source materials offline."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
import tomllib

HERE = Path(__file__).resolve().parent
MAX_SOURCE_EXPANDED = 512*1024*1024
BINARIES = frozenset('usr/local/'+name for name in (
    'bin/clamconf', 'bin/clamscan', 'bin/freshclam', 'bin/sigtool', 'sbin/clamd'))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)+'\n').encode()


def safe_name(name):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or '\\' in name or '\0' in name:
        raise ValueError('native_archive_path')
    return path.as_posix()


def pinned(path, expected):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 268435456:
        raise ValueError('native_input_type_or_size')
    raw = path.read_bytes()
    if sha(raw) != expected:
        raise ValueError('native_input_hash')
    return raw


def debian_data(raw):
    stream = io.BytesIO(raw)
    if stream.read(8) != b'!<arch>\n':
        raise ValueError('native_debian_magic')
    members = {}
    while header := stream.read(60):
        if len(header) != 60 or header[58:] != b'`\n':
            raise ValueError('native_debian_header')
        name = header[:16].decode('ascii').strip().rstrip('/')
        size = int(header[48:58])
        data = stream.read(size)
        if name in members or size < 0 or len(data) != size:
            raise ValueError('native_debian_member')
        members[name] = data
        if size % 2 and stream.read(1) != b'\n':
            raise ValueError('native_debian_padding')
    if set(members) != {'debian-binary', 'control.tar.gz', 'data.tar.gz'} or members['debian-binary'] != b'2.0\n':
        raise ValueError('native_debian_format')
    return members['data.tar.gz']


def resolve_runtime(files, links):
    result = dict(files)
    for name in links:
        target = name
        visited = set()
        while target in links:
            if target in visited:
                raise ValueError('native_runtime_link_cycle')
            visited.add(target)
            link = links[target]
            if PurePosixPath(link).name != link or link in ('.', '..'):
                raise ValueError('native_runtime_link_scope')
            target = str(PurePosixPath(target).parent/link)
        if target not in files:
            raise ValueError('native_runtime_link_missing')
        result[name] = files[target]
    return result


def runtime_files(package):
    files, links, seen = {}, {}, set()
    with tarfile.open(fileobj=io.BytesIO(debian_data(package)), mode='r:gz') as archive:
        for member in archive:
            name = safe_name(member.name)
            if name not in BINARIES and not (name.startswith('usr/local/lib/') and '.so' in PurePosixPath(name).name):
                continue
            if name in seen or member.size > 67108864:
                raise ValueError('native_runtime_duplicate_or_size')
            seen.add(name)
            if member.isfile():
                files[name] = archive.extractfile(member).read()
            elif member.issym():
                links[name] = member.linkname
            else:
                raise ValueError('native_runtime_type')
    if not BINARIES <= files.keys():
        raise ValueError('native_runtime_binary_missing')
    result = resolve_runtime(files, links)
    if len(result) > 120:
        raise ValueError('native_runtime_inventory_size')
    return result


def source_inventory(source):
    prefix = 'clamav-1.4.6/'
    vendor_prefix = prefix+'.cargo/vendor/'
    with tarfile.open(fileobj=io.BytesIO(source), mode='r|gz') as archive:
        files = {}
        expanded = 0
        for member in archive:
            name = safe_name(member.name)
            if member.isfile():
                if name in files or not name.startswith(prefix) or member.size > 67108864:
                    raise ValueError('native_source_member')
                expanded += member.size
                if expanded > MAX_SOURCE_EXPANDED:
                    raise ValueError('native_source_expanded_size')
                files[name] = archive.extractfile(member).read()
        lock = tomllib.loads(files[prefix+'Cargo.lock'].decode())
        crates = {}
        verified = 0
        notices = {}
        for name, raw in sorted(files.items()):
            if PurePosixPath(name).name.startswith(('COPYING', 'LICENSE', 'NOTICE', 'COPYRIGHT')):
                notices[name] = raw
            if not (name.startswith(vendor_prefix) and name.count('/') == 4 and name.endswith('/Cargo.toml')):
                continue
            root = name.rsplit('/', 1)[0]+'/'
            manifest = tomllib.loads(raw.decode())['package']
            checksums = json.loads(files[root+'.cargo-checksum.json'])
            for relative, expected in checksums['files'].items():
                relative = safe_name(relative)
                if sha(files[root+relative]) != expected:
                    raise ValueError('native_vendor_source_checksum')
                verified += 1
            key = (manifest['name'], manifest['version'])
            if key in crates or not (manifest.get('license') or manifest.get('license-file')):
                raise ValueError('native_crate_metadata')
            if manifest.get('license-file'):
                notice = root+safe_name(manifest['license-file'])
                notices[notice] = files[notice]
            crates[key] = {'name': key[0], 'version': key[1], 'license': manifest.get('license'),
                           'license_file': manifest.get('license-file'), 'package_checksum': checksums['package']}
        remote = [row for row in lock['package'] if 'source' in row]
        for dependency in remote:
            row = crates[(dependency['name'], dependency['version'])]
            if dependency.get('checksum') != row['package_checksum']:
                raise ValueError('native_locked_package_checksum')
        if len(remote) != len(crates) or not notices:
            raise ValueError('native_source_dependency_inventory')
        summary = {'locked_dependencies': len(remote), 'vendored_crates': len(crates),
                   'verified_source_files': verified, 'preserved_notices': len(notices),
                   'expanded_source_bytes': expanded, 'archive_read_mode': 'single_forward_stream',
                   'crates': sorted(crates.values(), key=lambda row: (row['name'], row['version']))}
        return summary, notices


def archive_new(path, files):
    with Path(path).open('xb') as stream:
        with gzip.GzipFile(fileobj=stream, mode='wb', filename='', mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode='w', format=tarfile.PAX_FORMAT) as archive:
                for name, raw in sorted(files.items()):
                    safe_name(name)
                    member = tarfile.TarInfo(name)
                    member.size, member.mode, member.mtime = len(raw), 0o644, 0
                    archive.addfile(member, io.BytesIO(raw))
    with tarfile.open(path, 'r:gz') as archive:
        readback = {member.name: archive.extractfile(member).read() for member in archive}
    if readback != files:
        raise ValueError('native_output_readback')
    return {'name': Path(path).name, 'sha256': sha(Path(path).read_bytes()), 'bytes': Path(path).stat().st_size,
            'files': len(files)}


def prepare(package, source, source_signature, public_key, dovecot_source, output):
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError('native_output_exists')
    lock = json.loads((HERE/'native-assets-lock.json').read_bytes())
    clamav = lock['clamav']
    package = pinned(package, clamav['package_sha256'])
    source = pinned(source, clamav['source_sha256'])
    signature = pinned(source_signature, clamav['source_signature_sha256'])
    public_key = pinned(public_key, clamav['keyring_sha256'])
    dovecot = pinned(dovecot_source, lock['dovecot']['source_candidate_sha256'])
    runtime = runtime_files(package)
    inventory, notices = source_inventory(source)
    copyrights = bytearray(b'ClamAV 1.4.6 upstream and vendored dependency notices\n')
    for name, raw in sorted(notices.items()):
        copyrights.extend(('\n\n===== '+name+' =====\n').encode()+raw+b'\n')
    sources = {'clamav/clamav-1.4.6.tar.gz': source,
               'clamav/clamav-1.4.6.tar.gz.sig': signature,
               'clamav/talos-public-key.gpg': public_key,
               'dovecot/dovecot-cnfix1-corresponding-source-candidate.tar.gz': dovecot,
               'native-assets-lock.json': encoded(lock), 'source-inventory.json': encoded(inventory),
               'README.md': (HERE/'NATIVE_ASSETS.md').read_bytes()}
    output.mkdir(parents=True)
    source_report = archive_new(output/'mail-platform-native-sources.tar.gz', sources)
    runtime['usr/local/share/doc/clamav/THIRD_PARTY_NOTICES.txt'] = bytes(copyrights)
    runtime['usr/local/share/doc/clamav/SOURCE-MATERIALS.json'] = encoded(source_report)
    blobs, by_hash, entries, mapping = {}, {}, {}, {}
    for name, raw in sorted(runtime.items()):
        digest = sha(raw)
        if digest not in by_hash:
            key = 'av_runtime_'+str(len(by_hash)).zfill(3)
            by_hash[digest] = key
            blob = 'runtime-files/'+key+'.input'
            blobs[blob] = raw
            entries[key] = {'path': blob, 'sha256': digest}
        mapping[name] = by_hash[digest]
    manifest = encoded({'files': mapping})
    blobs['clamav-runtime-manifest.json'] = manifest
    entries['clamav_runtime_manifest'] = {'path': 'clamav-runtime-manifest.json', 'sha256': sha(manifest)}
    blobs['kit-fragment.json'] = encoded({'files': entries})
    blobs['runtime-provenance.json'] = encoded({'package_sha256': clamav['package_sha256'],
        'source_sha256': clamav['source_sha256'], 'source_companion': source_report,
        'runtime_paths': len(mapping), 'unique_runtime_blobs': len(by_hash), 'artifacts_executed': False})
    runtime_report = archive_new(output/'mail-platform-clamav-runtime-candidate.tar.gz', blobs)
    result = {'status': 'public_materials_candidate', 'version': clamav['version'], 'source_companion': source_report,
              'runtime_candidate': runtime_report, 'source_inventory': inventory,
              'definition_database_included': False, 'private_resources_included': False,
              'dovecot_binary_packages_included': False, 'native_install_validated': False,
              'published': False, 'artifacts_executed': False}
    (output/'native-materials-result.json').write_bytes(encoded(result))
    if json.loads((output/'native-materials-result.json').read_bytes()) != result:
        raise ValueError('native_result_readback')
    return result


def main():
    parser = argparse.ArgumentParser()
    for name in ('package', 'source', 'source-signature', 'public-key', 'dovecot-source', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    result = prepare(args.package, args.source, args.source_signature, args.public_key, args.dovecot_source, args.output)
    print(json.dumps({key: value for key, value in result.items() if key != 'source_inventory'}))


if __name__ == '__main__':
    main()

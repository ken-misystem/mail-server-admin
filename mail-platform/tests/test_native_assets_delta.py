"""New public native-asset guards, with synthetic archives and no runtime execution."""
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import native_assets as assets


def tar_bytes(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz') as archive:
        for name, raw in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
    return stream.getvalue()


def source_fixture(tamper=False, missing=False):
    root = 'clamav-1.4.6/'
    crate = root+'.cargo/vendor/demo/'
    code = b'pub fn sample() {}\n'
    package = b'[package]\nname="demo"\nversion="1.0.0"\nlicense="MIT"\n'
    checksum = {'files': {'Cargo.toml': assets.sha(package), 'src/lib.rs': assets.sha(code)}, 'package': 'a'*64}
    files = {root+'Cargo.lock': b'[[package]]\nname="demo"\nversion="1.0.0"\nsource="registry+https://example.invalid"\nchecksum="'+b'a'*64+b'"\n',
             root+'COPYING.txt': b'Synthetic notice', crate+'Cargo.toml': package,
             crate+'.cargo-checksum.json': json.dumps(checksum).encode(),
             crate+'src/lib.rs': b'tampered' if tamper else code, crate+'LICENSE': b'Synthetic crate notice'}
    if missing:
        del files[crate+'Cargo.toml']
    return tar_bytes(files)


class NativeAssetsDelta(unittest.TestCase):
    def test_archive_scope_rejects_parent_absolute_and_windows_paths(self):
        for name in ('../escape', 'usr/../escape', '/etc/passwd', 'usr\\escape'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                assets.safe_name(name)

    def test_tar_dot_prefix_normalizes(self):
        self.assertEqual(assets.safe_name('./usr/local/bin/clamd'), 'usr/local/bin/clamd')

    def test_debian_magic_rejected(self):
        with self.assertRaisesRegex(ValueError, 'native_debian_magic'):
            assets.debian_data(b'bad')

    def test_truncated_ar_header_rejected(self):
        with self.assertRaisesRegex(ValueError, 'native_debian_header'):
            assets.debian_data(b'!<arch>\nshort')

    def test_unresolved_library_link_rejected(self):
        with self.assertRaisesRegex(ValueError, 'native_runtime_link_missing'):
            assets.resolve_runtime({}, {'usr/local/lib/liba.so': 'liba.so.1'})

    def test_library_link_cycle_rejected(self):
        with self.assertRaisesRegex(ValueError, 'native_runtime_link_cycle'):
            assets.resolve_runtime({}, {'usr/local/lib/a': 'b', 'usr/local/lib/b': 'a'})

    def test_library_link_escape_rejected(self):
        for link in ('../escape', '/etc/passwd', 'subdir/file'):
            with self.subTest(link=link), self.assertRaisesRegex(ValueError, 'native_runtime_link_scope'):
                assets.resolve_runtime({}, {'usr/local/lib/a': link})

    def test_link_chain_uses_same_regular_bytes(self):
        raw = b'synthetic shared library'
        result = assets.resolve_runtime({'usr/local/lib/a.1': raw},
            {'usr/local/lib/a': 'a.so', 'usr/local/lib/a.so': 'a.1'})
        self.assertEqual(set(result.values()), {raw})

    def test_source_dependency_closure_and_notice_preservation(self):
        record, notices = assets.source_inventory(source_fixture())
        self.assertEqual(record['locked_dependencies'], 1)
        self.assertEqual(record['verified_source_files'], 2)
        self.assertEqual(len(notices), 2)

    def test_tampered_vendor_file_rejected(self):
        with self.assertRaisesRegex(ValueError, 'native_vendor_source_checksum'):
            assets.source_inventory(source_fixture(tamper=True))

    def test_missing_locked_dependency_rejected(self):
        with self.assertRaises(KeyError):
            assets.source_inventory(source_fixture(missing=True))

    def test_wrong_input_pin_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            file = Path(temporary)/'public.source'
            file.write_bytes(b'synthetic')
            with self.assertRaisesRegex(ValueError, 'native_input_hash'):
                assets.pinned(file, '0'*64)

    def test_existing_output_rejected_before_reading_inputs(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(assets, 'pinned') as reader:
            with self.assertRaisesRegex(ValueError, 'native_output_exists'):
                assets.prepare(None, None, None, None, None, temporary)
            reader.assert_not_called()

    def test_deterministic_archive_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            first, second = Path(temporary)/'one.tar.gz', Path(temporary)/'two.tar.gz'
            files = {'source/public.txt': b'synthetic source'}
            a, b = assets.archive_new(first, files), assets.archive_new(second, files)
            self.assertEqual(a['sha256'], b['sha256'])
            with self.assertRaises(FileExistsError):
                assets.archive_new(first, files)


if __name__ == '__main__':
    unittest.main(verbosity=2)

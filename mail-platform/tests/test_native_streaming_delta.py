"""New checks for the bounded, single-forward-pass source inventory change."""
import io
import json
from pathlib import Path
import sys
import tarfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import native_assets as assets
from test_native_assets_delta import source_fixture, tar_bytes


class NativeStreamingDelta(unittest.TestCase):
    def test_stream_mode_used_once_with_expanded_byte_accounting(self):
        source = source_fixture()
        original = tarfile.open
        with patch.object(assets.tarfile, 'open', wraps=original) as opened:
            record, notices = assets.source_inventory(source)
        self.assertEqual(opened.call_count, 1)
        self.assertEqual(opened.call_args.kwargs['mode'], 'r|gz')
        self.assertEqual(record['archive_read_mode'], 'single_forward_stream')
        self.assertGreater(record['expanded_source_bytes'], 0)
        self.assertEqual(record['preserved_notices'], len(notices))

    def test_expanded_limit_rejected_before_metadata_parsing(self):
        with patch.object(assets, 'MAX_SOURCE_EXPANDED', 1):
            with self.assertRaisesRegex(ValueError, 'native_source_expanded_size'):
                assets.source_inventory(source_fixture())

    def test_locked_package_checksum_difference_rejected_after_file_checks(self):
        with tarfile.open(fileobj=io.BytesIO(source_fixture()), mode='r:gz') as archive:
            files = {row.name: archive.extractfile(row).read() for row in archive}
        name = 'clamav-1.4.6/.cargo/vendor/demo/.cargo-checksum.json'
        value = json.loads(files[name])
        value['package'] = 'b'*64
        files[name] = json.dumps(value).encode()
        with self.assertRaisesRegex(ValueError, 'native_locked_package_checksum'):
            assets.source_inventory(tar_bytes(files))

    def test_duplicate_source_member_rejected_in_forward_pass(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            for _ in range(2):
                row = tarfile.TarInfo('clamav-1.4.6/public.txt')
                row.size = 1
                archive.addfile(row, io.BytesIO(b'x'))
        with self.assertRaisesRegex(ValueError, 'native_source_member'):
            assets.source_inventory(stream.getvalue())


if __name__ == '__main__':
    unittest.main(verbosity=2)

"""New inventory checks, without making license compliance determinations."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from distribution_inventory import inventory


class InventoryCases(unittest.TestCase):
    def test_two_vendor_trees_keep_package_versions_and_notice_hashes(self):
        files = {}
        for tree, version in (('payload/opt/one', '1.0.0'), ('payload/opt/two', '2.0.0')):
            files[tree+'/vendor/composer/installed.json'] = json.dumps({'packages': [
                {'name': 'example/package', 'version': version, 'license': ['MIT']}]}).encode()
            files[tree+'/vendor/example/package/LICENSE'] = b'synthetic notice'
        result = inventory(files)
        self.assertEqual([row['version'] for row in result['packages']], ['1.0.0', '2.0.0'])
        self.assertEqual(len(result['notice_files']), 2)
        self.assertFalse(result['packages_without_notice_file'])

    def test_composer_license_fallback_and_missing_notices_are_reported(self):
        root = 'payload/opt/example/vendor/'
        result = inventory({root+'composer/installed.json': b'[{"name":"example/package","version":"1"}]',
                            root+'example/package/composer.json': b'{"license":"BSD-3-Clause"}'})
        self.assertEqual(result['packages'][0]['declared_licenses'], ['BSD-3-Clause'])
        self.assertEqual(result['packages_without_notice_file'], [root+'example/package/'])

    def test_absent_license_metadata_and_external_kit_are_explicit(self):
        result = inventory({'payload/x/vendor/composer/installed.json': b'[{"name":"a/b"}]'})
        self.assertEqual(result['missing_license_metadata'], ['payload/x/vendor/a/b/'])
        self.assertEqual(result['legal_compliance_assessment'], 'not_performed')
        self.assertEqual(len(result['external_private_kit_components']), 2)

    def test_unsafe_package_name_rejected(self):
        for name in ('../b', 'a/../b', 'a\\b/c'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                inventory({'payload/x/vendor/composer/installed.json': json.dumps([{'name': name}]).encode()})


if __name__ == '__main__':
    unittest.main(verbosity=2)

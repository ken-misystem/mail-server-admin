"""Adopt only the verified Roundcube recipe and component-owned file changes."""
import copy
import json
from pathlib import Path

from host_transaction import Files, durable_json, regular
from identity_bindings import bind as bind_identities
from install_preparation import baseline_identities, read_payload
from profile_bindings import bind as bind_profile
from release import sha
from roundcube_migration import CONFIG
from roundcube_settings import select
from site_bindings import bind as bind_site

RECEIPT = '/var/lib/mail-platform-update/installed-code.json'
RECIPE = 'blueprint/install-recipes.json'


def bound_payload(payload, receipt):
    files = read_payload(payload)
    bound = bind_site(files, receipt['site'])
    bound, _ = bind_identities(bound, receipt['identities'], baseline_identities(payload))
    return bind_profile(bound)


class ReceiptAdoption:
    def __init__(self, root, evidence):
        self.files = Files(root, evidence)
        self.evidence = Path(evidence)

    def prepare(self, payload, previous_recipe, migration):
        raw, attributes = regular(self.files.target(RECEIPT))
        if attributes['uid'] != 0 or attributes['mode'] != 0o600:
            raise ValueError('roundcube_receipt_permissions')
        receipt = json.loads(raw)
        if receipt.get('format') != 2:
            raise ValueError('roundcube_receipt_format')
        bound = bound_payload(payload, receipt)
        previous = bind_site({RECIPE: previous_recipe}, receipt['site'])[RECIPE]
        if sha(previous) != receipt['blueprints'].get(RECIPE):
            raise ValueError('roundcube_previous_recipe_pin')
        selected = {'payload/' + RECIPE: previous}
        select(selected, 'plugin')
        if json.loads(selected['payload/' + RECIPE]) != json.loads(bound[RECIPE]):
            raise ValueError('roundcube_recipe_scope')
        desired_blueprints = {name: sha(value) for name, value in bound.items()
                              if name.startswith('blueprint/')
                              and not name.startswith('blueprint/systemd/')
                              and name != 'blueprint/update-contract.json'}
        expected = dict(receipt['blueprints'])
        expected[RECIPE] = sha(bound[RECIPE])
        if expected != desired_blueprints:
            raise ValueError('roundcube_unrelated_blueprint_change')
        desired = copy.deepcopy(receipt)
        desired['blueprints'] = expected
        for target in migration['targets']:
            name = target['path']
            if name == CONFIG:
                continue
            if receipt['code'].get(name) != target['before']:
                raise ValueError('roundcube_owned_code_drift')
            desired['code'][name] = {key: target[key] for key in ('sha256', 'mode', 'uid', 'gid')}
        self.evidence.mkdir(mode=0o700)
        durable_json(self.evidence/'before.json', receipt)
        durable_json(self.evidence/'desired.json', desired)
        durable_json(self.evidence/'adoption.json', {
            'phase': 'prepared', 'before': attributes,
            'desired_sha256': sha((self.evidence/'desired.json').read_bytes())})
        return {'recipe_sha256': expected[RECIPE], 'version_preserved': receipt['version']}

    def activate(self):
        record = json.loads((self.evidence/'adoption.json').read_bytes())
        desired = (self.evidence/'desired.json').read_bytes()
        if (record['phase'] != 'prepared' or sha(desired) != record['desired_sha256']
                or regular(self.files.target(RECEIPT))[1] != record['before']):
            raise ValueError('roundcube_receipt_CAS_conflict')
        self.files.write(RECEIPT, desired, 0o600)
        record['phase'] = 'adopted'
        durable_json(self.evidence/'adoption.json', record)

    def check(self):
        record = json.loads((self.evidence/'adoption.json').read_bytes())
        if regular(self.files.target(RECEIPT))[1] != {
                'sha256': record['desired_sha256'], 'uid': 0, 'gid': 0, 'mode': 0o600}:
            raise ValueError('roundcube_adopted_receipt_drift')

    def restore(self):
        self.files.entries = [json.loads(path.read_bytes())
                              for path in sorted(self.evidence.glob('file-entry-*.json'))]
        return self.files.restore()

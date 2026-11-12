"""Invoke a fixed public pure renderer in its own isolated Python process."""
import base64
import importlib.util
import json
from pathlib import Path
import sys


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def run(payload, operation, arguments):
    root = Path(payload)
    certificate = root / 'usr/local/lib/mail-client-certificates-v1/client-certificates'
    if operation == 'certificate':
        directory = certificate / 'runtime-completion-v1'
        sys.path.insert(0, str(directory))
        return module(directory / 'configuration.py', 'fresh_certificate_config').render(**arguments)
    if operation == 'backend':
        api = module(certificate / 'final-integration-v1/backend.py', 'fresh_backend')
        configuration, disabled = api.dovecot(
            '/usr/local/lib/mail-client-certificates-v1', '/run/mail-client-certificates-v1/native',
            arguments['listeners'], config_version='2.4.1')
        return {'dovecot': configuration, 'postfix': api.postfix(
            '/run/mail-client-certificates-v1/native', '/run/mail-client-certificates-v1/postfix'),
            'master': api.master(), 'disabled': disabled}
    if operation == 'feature_state':
        directory = root / 'usr/local/lib/mail-feature-runtime-v1'
        sys.path.insert(0, str(directory))
        return module(directory / 'configuration_cycle.py', 'fresh_feature_cycle').initial_state()
    if operation == 'protection':
        directory = root / 'usr/local/lib/mail-protection-admin-v1'
        sys.path[:0] = [str(directory / 'runtime'), str(directory)]
        api = module(directory / 'runtime/runtime_render.py', 'fresh_protection_render')
        policy = module(directory / 'policy.py', 'fresh_protection_policy')
        adapter = module(directory / 'runtime/apply_adapter.py', 'fresh_protection_adapter')
        scanner = policy.defaults('scanner')
        return {'scanner': scanner, 'upstream': policy.defaults('upstream'),
                'antivirus': base64.b64encode(api.guard(False)).decode(),
                'attachments': base64.b64encode(api.attachments(scanner)).decode(),
                'loader': base64.b64encode(adapter.LOADER).decode(),
                'targets': adapter.TARGETS}
    if operation == 'AV_config':
        path = root / 'usr/local/lib/mail-protection-admin-v1/deployment_profile.py'
        return {name: raw.decode('utf-8') for name, raw in module(path, 'fresh_AV_config').configs().items()}
    raise ValueError('unknown_pure_recipe')


if __name__ == '__main__':
    # The installer fixes this path and operation. No network or live config is used.
    root, action = sys.argv[1:]
    print(json.dumps(run(root, action, json.load(sys.stdin)), sort_keys=True))

"""Select the original MI-SYSTEM plugin through normal package build inputs."""
import json


POLICY = 'integration/roundcube-settings.json'


def plugin_mode(files):
    if POLICY not in files:
        return False
    policy = json.loads(files[POLICY])
    if policy != {'format': 1, 'mode': 'plugin'}:
        raise ValueError('roundcube_settings_policy')
    return True


def select(files, mode):
    if mode not in ('legacy', 'plugin'):
        raise ValueError('roundcube_settings_mode')
    if mode == 'legacy':
        return
    name = 'payload/blueprint/install-recipes.json'
    recipes = json.loads(files[name])
    plugins = recipes['roundcube_plugins']
    if plugins.count('managesieve') != 1 or 'mail_settings' in plugins:
        raise ValueError('roundcube_settings_plugin_list')
    recipes['roundcube_plugins'] = ['mail_settings' if value == 'managesieve' else value for value in plugins]
    recipes['mail_settings_enabled'] = True
    files[name] = json.dumps(recipes, sort_keys=True, separators=(',', ':')).encode()
    files['payload/' + POLICY] = b'{"format":1,"mode":"plugin"}'

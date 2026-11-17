"""Add package updater units to the existing collector, UI and notification contract."""
from site_bindings import rebase

EXTRA = {
    'mail-platform-update.service': 'ソフトウェア更新確認',
    'mail-platform-update.timer': 'ソフトウェア更新タイマー',
    'mail-platform-update-ui.service': 'ソフトウェア更新管理',
    'mail-platform-update-ui.socket': 'ソフトウェア更新管理ソケット',
}


def once(raw, old, new):
    if raw.count(old) != 1:
        raise ValueError('monitor_profile_contract')
    return raw.replace(old, new)


def bind(files, *, supplemental_dns=False):
    output = dict(files)
    if not supplemental_dns:
        collector = 'usr/local/lib/mail-management-operations-v1/read_runtime.py'
        output[collector] = output[collector].replace(b"UNITS += ('mail-reputation-dns-v1.service',)\n", b'')
        snapshot = 'opt/mail-management/candidates/protection-relay-v1/src/OperationsSnapshot.php'
        output[snapshot] = output[snapshot].replace(b",'mail-reputation-dns-v1.service'", b'')
    name = 'usr/local/lib/mail-management-operations-v1/read_runtime.py'
    raw = output[name].decode()
    anchor = 'COMMANDS = {'
    raw = once(raw, anchor, 'UNITS += ' + repr(tuple(EXTRA)) + '\n'
               + "ONESHOTS += ('mail-platform-update.service',)\n" + anchor)
    output[name] = raw.encode()
    name = 'usr/local/lib/mail-management-alerts-v1/channel_delivery.py'
    raw = output[name].decode()
    output[name] = once(raw, 'UNIT_NAMES = {', 'UNIT_NAMES = {\n'
                        + ''.join('    ' + repr(key) + ': ' + repr(value) + ',\n'
                                  for key, value in EXTRA.items())).encode()
    name = 'usr/local/lib/mail-management-alerts-v1/worker.py'
    raw = output[name].decode()
    output[name] = once(raw, "'mail-protection-publish-v1.service'))",
                        "'mail-protection-publish-v1.service', 'mail-platform-update.service'))").encode()
    prefix = 'opt/mail-management/candidates/protection-relay-v1/src/'
    name = prefix + 'OperationsSnapshot.php'
    raw = output[name].decode()
    legacy = "'mail-protection-publish-v1.timer'];"
    dns = "'mail-protection-publish-v1.timer','mail-reputation-dns-v1.service'];"
    if sum(raw.count(anchor) for anchor in (legacy, dns)) != 1:
        raise ValueError('monitor_profile_contract')
    anchor = dns if dns in raw else legacy
    raw = once(raw, anchor, anchor[:-2] + ',' + ','.join(repr(key) for key in EXTRA) + '];')
    raw = once(raw, "'mail-protection-publish-v1.service'],true)",
               "'mail-protection-publish-v1.service','mail-platform-update.service'],true)")
    output[name] = raw.encode()
    name = prefix + 'OperationsStatusController.php'
    raw = output[name].decode()
    anchor = "'mail-protection-publish-v1.timer'=>'保護・上流設定の反映タイマー',"
    output[name] = once(raw, anchor, anchor + '\n'
                        + ''.join(repr(key) + '=>' + repr(value) + ',\n' for key, value in EXTRA.items())).encode()
    return rebase(output, files)

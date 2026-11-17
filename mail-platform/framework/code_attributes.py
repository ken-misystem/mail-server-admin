"""One code-attribute policy for fresh, ordinary and generation installs.

Existing receipt attributes are site state. Only the documented legacy POP
normalization (root:root/0644) may be repaired to its runtime reader contract.
Callers must first compare the live file with the complete ownership receipt.
"""
POP_REQUIRED = frozenset({
    '/usr/local/lib/mail-pop-compat-v1/compat.py',
    '/usr/local/lib/mail-pop-worker-v1/fetchmail_history.py',
    '/usr/local/lib/mail-pop-general-v1/fetchmail_history.py',
})
LEGACY = frozenset({'0.4.0', '0.4.1', '0.4.2'})
FIELDS = ('uid', 'gid', 'mode')


def attributes(path, identities, before=None, source_version=None):
    if before is not None:
        result = {k: before[k] for k in FIELDS}
        if any(type(v) is not int or v < 0 for v in result.values()) or result['mode'] > 0o7777:
            raise ValueError('code_attribute_receipt')
    elif path.startswith('/opt/mail-management/'):
        result = {'uid': 0, 'gid': identities['mailadmin.gid'], 'mode': 0o640}
    else:
        result = {'uid': 0, 'gid': 0, 'mode': 0o644}
    if path in POP_REQUIRED:
        expected = {'uid': 0, 'gid': identities['mailpop.gid'], 'mode': 0o640}
        if before is None or result == expected:
            return expected
        if source_version in LEGACY and result == {'uid': 0, 'gid': 0, 'mode': 0o644}:
            return expected
        raise ValueError('POP_code_attributes_require_review:' + path)
    return result

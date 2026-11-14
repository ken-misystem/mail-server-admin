"""Apply the two signed Sieve fixes to trusted OS sources entirely in memory."""
import re
import hashlib
from source_patches import apply
from roundcube_settings import plugin_mode

TARGETS={
    'usr/share/roundcube/plugins/managesieve/lib/Roundcube/rcube_sieve_engine.php':'rcube_sieve_engine.php',
    'usr/share/roundcube/plugins/managesieve/lib/Roundcube/rcube_sieve_forward.php':'rcube_sieve_forward.php',
}
NOTICE_INPUT = 'integration/roundcube-patches/NOTICE.md'
NOTICE_TARGET = 'usr/share/roundcube/plugins/managesieve/MI-SYSTEM-MODIFICATIONS.md'
NOTICE_MARKER = b'# MI-SYSTEM Roundcube modification notice\n'


def patch_header(name, body):
    if name not in TARGETS.values():
        raise ValueError('Roundcube_notice_target')
    return (NOTICE_MARKER.decode()
            + '# Component: Roundcube managesieve\n'
            + '# Modifier: MI-SYSTEM\n'
            + '# Modification date: 2026-11-11\n'
            + '# Notice supplemented: 2026-11-13\n'
            + '# License: GPL version 3 or later; upstream skins/plugins exception retained\n'
            + '# Details: NOTICE.md\n'
            + '# Patch body SHA256: ' + hashlib.sha256(body).hexdigest() + '\n\n').encode()


def patch_body(raw, name):
    if raw.startswith(NOTICE_MARKER):
        header, separator, body = raw.partition(b'\n\n')
        if not separator or header + separator != patch_header(name, body):
            raise ValueError('Roundcube_modification_notice')
        return body
    return raw


def annotate_patch(raw):
    body = raw
    if raw.startswith(NOTICE_MARKER):
        _, _, body = raw.partition(b'\n\n')
    first = body.splitlines()[0].decode()
    if not first.startswith('--- a/'):
        raise ValueError('Roundcube_patch_header')
    name = first.removeprefix('--- a/')
    body = patch_body(raw, name)
    return patch_header(name, body) + body

def hunks(raw,name):
    raw = patch_body(raw, name)
    lines=raw.decode('utf-8').replace('\r\n','\n').splitlines(keepends=True)
    if lines[:2]!=['--- a/'+name+'\n','+++ b/'+name+'\n']:
        raise ValueError('Roundcube_patch_header')
    result=[]
    before=[]
    after=[]
    expected=None
    for line in lines[2:]+['@@ end\n']:
        if line.startswith('@@'):
            if expected is not None:
                if (len(before),len(after))!=expected:
                    raise ValueError('Roundcube_patch_hunk_length')
                result.append({'before':''.join(before),'after':''.join(after)})
            if line=='@@ end\n':
                break
            match=re.fullmatch(r'@@ -[0-9]+,([0-9]+) \+[0-9]+,([0-9]+) @@\n',line)
            if match is None:
                raise ValueError('Roundcube_patch_hunk_header')
            expected=tuple(int(value) for value in match.groups())
            before=[]
            after=[]
        elif expected is None or line[:1] not in (' ','+','-'):
            raise ValueError('Roundcube_patch_line')
        else:
            if line[0] in (' ','-'):
                before.append(line[1:])
            if line[0] in (' ','+'):
                after.append(line[1:])
    if not result:
        raise ValueError('Roundcube_patch_empty')
    return result

def render(files,read_live):
    output={}
    restore_original = plugin_mode(files)
    for target,name in TARGETS.items():
        raw,metadata=read_live('/'+target)
        if metadata['uid']!=0 or metadata['mode']&0o022 or len(raw)>262144:
            raise ValueError('Roundcube_package_source_trust')
        patch=files['integration/roundcube-patches/'+name+'.patch']
        changes = hunks(patch, name)
        if restore_original:
            changes = [{'before': item['after'], 'after': item['before']} for item in changes]
        output[target]=apply(target,raw,{target:{'hunks':changes}})
    if NOTICE_INPUT in files:
        history = files[NOTICE_INPUT]
        if restore_original:
            output[NOTICE_TARGET] = (
                '# 現在の構成\n\n'
                '標準Roundcubeのmanagesieve PHP2ファイルを原版に保つ。'
                '個人設定は独自mail_settings pluginで提供する。'
                '旧修正は下記の履歴とGPL資料として保持する。\n\n'
                '## 旧修正の履歴\n\n'
            ).encode() + history
        else:
            output[NOTICE_TARGET] = history
    return output

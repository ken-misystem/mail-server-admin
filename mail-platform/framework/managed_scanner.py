"""Observe the installed managed protection runtime without inspecting mail."""
from pathlib import Path
import re
import stat

from observer_projection import scanner
from runtime_files import read


def managed_scanner(engine, runtime, unit_status):
    engine = Path(engine)
    runtime = Path(runtime)
    try:
        st = engine.lstat()
    except FileNotFoundError:
        present = False
    else:
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError('managed_scanner_engine_attributes')
        present = bool(st.st_mode & 0o111)
    pairs = [tuple(line.split('=',1)) for line in unit_status.decode('ascii').splitlines()]
    state = dict(pairs)
    if len(pairs)!=2 or set(state)!={'LoadState','ActiveState'}:
        raise ValueError('managed_scanner_unit_status')
    running = state=={'LoadState':'loaded','ActiveState':'active'}

    def first_match(name, expression):
        path = runtime/name
        mode = stat.S_IMODE(path.lstat().st_mode)
        if mode not in (0o640,0o644):
            raise ValueError('managed_scanner_runtime_mode')
        raw, _ = read(path,mode=mode,limit=32768)
        values = re.findall(expression,raw,re.M)
        if len(values)!=1:
            raise ValueError('managed_scanner_runtime_shape')
        return values[0]

    if not present and state['LoadState']=='not-found':
        return scanner({},engine_present=False,daemon_running=False)
    enabled = first_match('antivirus.lua',br'^local enabled = (true|false)$')==b'true'
    extensions, encrypted = first_match('attachments.lua',
        br'^local config = \{extensions=\{([^{}\r\n]*)\},attachment_action="(?:reject|tag)",encrypted_archives=(true|false)\}$')
    return scanner({'managed':True} if enabled else {},engine_present=present,daemon_running=running,
                   attachment_rules_configured=bool(extensions) or encrypted==b'true')

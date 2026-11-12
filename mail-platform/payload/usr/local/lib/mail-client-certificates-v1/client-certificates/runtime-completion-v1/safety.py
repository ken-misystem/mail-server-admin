"""Bounded public diagnostics and held root-owned configuration; no boot on import."""
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import threading
import traceback

def need(value,code):
    if value is not True:raise ValueError(code)

def unchanged(a,b):
    fields=('st_dev','st_ino','st_uid','st_gid','st_nlink','st_mode','st_size','st_mtime_ns','st_ctime_ns')
    return all(getattr(a,k)==getattr(b,k)for k in fields)

def held(path,maximum=131072,owner=0):
    need(type(path)is str and path.startswith('/')and '\x00'not in path and all(p not in ('','.','..')for p in path.split('/')[1:]),'protected_absolute_path')
    descriptors=[];fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);descriptors.append(fd)
    try:
        parts=path.split('/')[1:]
        for part in parts[:-1]:
            fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);descriptors.append(fd)
            info=os.fstat(fd);need(info.st_uid in(0,owner)and info.st_mode&0o022==0,'protected_parent_permissions')
        leaf=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=fd);descriptors.append(leaf)
        before=os.fstat(leaf);need(stat.S_ISREG(before.st_mode)and before.st_uid==owner and before.st_nlink==1 and before.st_mode&0o022==0 and 0<before.st_size<=maximum,'protected_file_permissions')
        raw=os.pread(leaf,before.st_size+1,0)
        need(len(raw)==before.st_size and unchanged(before,os.fstat(leaf))and unchanged(before,os.stat(parts[-1],dir_fd=fd,follow_symlinks=False)),'protected_file_drift')
        return raw
    finally:
        for item in reversed(descriptors):os.close(item)

def unique(pairs):
    result={}
    for key,value in pairs:need(key not in result,'duplicate_json_field');result[key]=value
    return result

"""Replacement declaration block for safety.py; public literals only, never values."""
_DIAGNOSTIC_INDEX = None


def diagnostic_index():
    global _DIAGNOSTIC_INDEX
    if _DIAGNOSTIC_INDEX is not None:
        return _DIAGNOSTIC_INDEX
    root = Path(__file__).resolve().parents[2]
    manifest = json.loads(held(str(root / 'runtime-manifest.json'), 1048576))
    records = {}; literals = set(); symbols = set()
    pins = manifest.get('pins')
    need(type(pins) is dict and len(pins) <= 180, 'diagnostic_manifest_inventory')
    for name, pin in pins.items():
        if not (type(name) is str and name.startswith('client-certificates/') and name.endswith('.py')):
            continue
        need(all(part not in ('', '.', '..') for part in name.split('/'))
             and '\\' not in name and type(pin) is str
             and re.fullmatch('[0-9a-f]{64}', pin) is not None, 'diagnostic_public_source_name')
        path = root / name
        raw = held(str(path), 2097152)
        need(sha256(raw).hexdigest() == pin, 'diagnostic_public_source_pin')
        tree = ast.parse(raw)
        functions = set(); classes = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and type(node.value) is str and re.fullmatch('[a-z][a-z0-9_]{1,95}', node.value):
                literals.add(node.value)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.add(node.name); symbols.add(node.name)
            if isinstance(node, ast.ClassDef):
                classes.add(node.name); symbols.add(node.name)
            if isinstance(node, ast.Name):
                symbols.add(node.id)
        records[str(path)] = {'functions':functions, 'classes':classes, 'sha256':pin}
    _DIAGNOSTIC_INDEX = {'records':records, 'literals':literals, 'symbols':symbols}
    return _DIAGNOSTIC_INDEX


def shape(error, phase):
    try:
        index = diagnostic_index(); index_failure = None
    except BaseException as lookup_error:
        # Never replace the primary failure with failure of its diagnostic lookup.
        index = {'records':{}, 'literals':set(), 'symbols':set()}
        index_failure = {'class':type(lookup_error).__name__, 'errno':getattr(lookup_error, 'errno', None)}
    literals = index['literals']; records = index['records']
    builtin_classes = {'Exception','ValueError','TypeError','RuntimeError','NameError','AttributeError',
        'ModuleNotFoundError','ImportError','OSError','PermissionError','FileNotFoundError',
        'TimeoutError','ConnectionError','ConnectionResetError','BrokenPipeError','SSLError','JSONDecodeError'}
    public_classes = set().union(*(row['classes'] for row in records.values())) if records else set()

    def token(value):
        return value if type(value) is str and value in literals else 'unclassified'

    def frame(row):
        trusted = records.get(row.filename)
        return {'source':Path(row.filename).name if trusted else 'unclassified',
            'function':row.name if trusted and row.name in trusted['functions'] else 'unclassified',
            'line':row.lineno if trusted else None, 'source_sha256':trusted['sha256'] if trusted else None}

    def safe_details(data):
        if type(data) is not dict:
            return None
        allowed = {'phase','reason','step','index','native_exit','native_code','errno','line','column',
            'actual_type','expected_type','field','row_count','table','rows','count','exit','timed_out'}
        out = {}; omitted = 0
        for key, value in list(data.items())[:32]:
            if type(key) is str and key in allowed and (type(value) in (int, bool) or value is None):
                out[key] = value
            elif type(key) is str and key in allowed and type(value) is str and value in literals:
                out[key] = value
            else:
                omitted += 1
        out['fields_omitted'] = omitted
        return out

    def item(e):
        code = getattr(e, 'code', None)
        if code is None and type(e) is ValueError and len(e.args) == 1:
            code = e.args[0]
        trace = traceback.extract_tb(e.__traceback__)
        frames = [frame(row) for row in trace[-8:]]
        trusted_frames = [row for row in frames if row['source'] != 'unclassified']
        last = trusted_frames[-1] if trusted_frames else {'source':'unclassified','function':'unclassified','line':None,'source_sha256':None}
        kind = type(e).__name__
        result = {'class':kind if kind in builtin_classes | public_classes else 'unclassified',
            'reason':token(code), 'reason_code_present':code is not None,
            'reason_classification':'trusted_public_literal' if type(code) is str and code in literals else 'not_trusted_literal',
            'origin_phase':token(getattr(e, 'phase', None)),
            **last, 'frames':frames, 'raw_error_saved':False}
        for name in ('errno','native_exit','native_code','verify_code'):
            value = getattr(e, name, None)
            if type(value) is int:
                result['tls_verify_code' if name == 'verify_code' else name] = value
        if e.args and type(e.args[0]) is int:
            result['native_code'] = e.args[0]
        for name, value in (('missing_symbol',getattr(e,'name',None)), ('missing_attribute',getattr(e,'name',None))):
            if isinstance(e, (NameError, AttributeError)) and type(value) is str:
                result[name] = value if value in index['symbols'] else 'unclassified'
        tls = getattr(e, 'reason', None)
        if type(tls) is str and tls in {'PEER_DID_NOT_RETURN_A_CERTIFICATE','CERTIFICATE_VERIFY_FAILED',
            'TLSV1_ALERT_UNKNOWN_CA','TLSV1_ALERT_BAD_CERTIFICATE','TLSV13_ALERT_CERTIFICATE_REQUIRED',
            'UNEXPECTED_EOF_WHILE_READING','WRONG_VERSION_NUMBER','NO_SHARED_CIPHER'}:
            result['tls_reason'] = tls
        detail = safe_details(getattr(e, 'details', None))
        if detail is not None:
            result['details'] = detail
        return result

    result = item(error); result['phase'] = token(phase); result['causes'] = []
    if index_failure is not None:
        result['diagnostic_index_failure'] = index_failure
    seen = {id(error)}; cause = error.__cause__ or error.__context__
    while cause is not None and id(cause) not in seen and len(result['causes']) < 5:
        seen.add(id(cause)); result['causes'].append(item(cause)); cause = cause.__cause__ or cause.__context__
    return result


class Audit:
    def __init__(self):
        self.lock = threading.Lock()

    def failure(self, error, phase='core'):
        if isinstance(error, BaseException):
            row = shape(error, phase)
        else:
            # Do not export arbitrary dictionaries or their embedded values.
            safe = ValueError('diagnostic_nonexception_input')
            row = shape(safe, phase)
        raw = json.dumps({'component':'mail_client_certificates','failure':row}, sort_keys=True)
        need(len(raw.encode()) <= 32768, 'safe_diagnostic_bound')
        with self.lock:
            print(raw, flush=True)

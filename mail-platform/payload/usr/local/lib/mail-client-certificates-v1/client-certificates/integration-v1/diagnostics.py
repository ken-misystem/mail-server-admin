"""Fixed safe reasons and public stack metadata; never str(error), locals or SQL."""
import ast
from hashlib import sha256
from pathlib import Path
import re
import traceback

HERE = Path(__file__).resolve().parent
ROOTS = (HERE, HERE.parent/'identity-security-v1', HERE.parent/'adapters-v1')
CLEANUP = {'rollback', 'cursor_close', 'connection_close'}
ERROR_CLASSES = {'AdapterError','AssertionError','RuntimeError','ValueError','TypeError','AttributeError',
                 'PermissionError','OSError','TimeoutError','SyntaxError','KeyError','ImportError',
                 'ModuleNotFoundError','OperationalError','InternalError','ProgrammingError','IntegrityError',
                 'DataError','InterfaceError','NotSupportedError','JSONDecodeError'}


def record(error, phase):
    literals = set()
    for root in ROOTS:
        for path in root.glob('*.py'):
            if path.name.startswith('test_'): continue
            literals.update(n.value for n in ast.walk(ast.parse(path.read_bytes()))
                            if isinstance(n, ast.Constant) and type(n.value) is str
                            and re.fullmatch('[a-z][a-z0-9_]{2,63}', n.value))
    def frames(exc):
        found = [f for f in traceback.extract_tb(exc.__traceback__) if Path(f.filename).parent in ROOTS]
        f = found[-1] if found else None
        return {'component': Path(f.filename).name if f else None, 'function': f.name if f else None,
                'line': f.lineno if f else None,
                'source_sha256': sha256(Path(f.filename).read_bytes()).hexdigest() if f else None}
    def item(exc):
        code = getattr(exc, 'code', None)
        if code is None and type(exc) is ValueError and len(exc.args) == 1 and type(exc.args[0]) is str and exc.args[0] in literals:
            code = exc.args[0]  # Fixed validator reason only, never an arbitrary native message.
        native = getattr(exc, 'native_code', None)
        if type(native) is not int and exc.args and type(exc.args[0]) is int: native = exc.args[0]
        return {**frames(exc), 'error_class': type(exc).__name__ if type(exc).__name__ in ERROR_CLASSES else 'unclassified',
                'reason': code if type(code) is str and code in literals else 'assertion_mismatch' if isinstance(exc, AssertionError) else 'unexpected_exception',
                'native_code': native if type(native) is int and 0 <= native <= 65535 else None}
    result = item(error)
    p = getattr(error, 'phase', phase); result['phase'] = p if p in literals else 'unknown_phase'
    result['causes'] = []; seen = {id(error)}; cause = error.__cause__ or error.__context__
    while cause is not None and id(cause) not in seen and len(result['causes']) < 4:
        seen.add(id(cause)); result['causes'].append(item(cause)); cause = cause.__cause__ or cause.__context__
    details = getattr(error, 'details', None)
    cleanup = details.get('cleanup_failures', []) if type(details) is dict else []
    result['cleanup_failures'] = [k for k in cleanup if k in CLEANUP]
    result['raw_message_saved'] = False
    return result


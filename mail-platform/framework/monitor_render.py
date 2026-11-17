"""Generate the collector from upstream code and the shared environment module."""
import ast
from pathlib import Path


def render(raw):
    text = raw.decode().replace('\r\n', '\n')
    tree = ast.parse(text)
    guard = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'certificate_guard')
    lines = text.splitlines(keepends=True)
    shared = Path(__file__).with_name('monitor_environment.py').read_text(encoding='utf-8')
    text = ''.join(lines[:guard.lineno-1]) + shared + '\n' + ''.join(lines[guard.end_lineno:])
    tree = ast.parse(text)
    commands = next(n for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t,ast.Name) and t.id=='COMMANDS' for t in n.targets))
    # The units tuple is generated upstream. Only the two site-specific commands change.
    for key, node in reversed(list(zip(commands.value.keys, commands.value.values))):
        if isinstance(key, ast.Constant) and key.value in ('queue','certificate'):
            lines = text.splitlines(keepends=True)
            start = sum(map(len, lines[:node.lineno-1])) + node.col_offset
            end = sum(map(len, lines[:node.end_lineno-1])) + node.end_col_offset
            text = text[:start] + '()' + text[end:]
    replacements = {
        'def collect(native=capture, filesystem=filesystem_summary, now=None, certificate=certificate_guard):':
        'def collect(native=capture, filesystem=filesystem_summary, now=None, certificate=None, environment=None):',
        '    checks = {}\n    for name in':
        '    checks = {}\n    for name in',
        "                before = certificate() if name == 'certificate' else None\n                raw, meta = native(COMMANDS[name], LIMITS[name])\n                if name == 'certificate': need(certificate() == before)":
        "                guard = None\n                command = COMMANDS[name]\n                if name in ('queue', 'certificate'):\n                    settings = monitor_load() if environment is None else monitor_validate(environment)\n                    command = monitor_commands(settings)[name]\n                    guard = (certificate or (lambda: monitor_certificate_guard(settings))) if name == 'certificate' else (lambda: monitor_queue_guard(settings))\n                before = guard() if guard else None\n                raw, meta = native(command, LIMITS[name])\n                if guard: need(guard() == before)",
    }
    for before, after in replacements.items():
        if text.count(before) != 1: raise ValueError('monitor_render_anchor')
        text = text.replace(before, after, 1)
    compile(text, 'monitor-collector', 'exec')
    return text.encode()

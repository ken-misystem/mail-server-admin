"""Isolated-Python bootstrap for the installed availability services."""
from pathlib import Path
import os
import runpy
import sys

root = Path(__file__).resolve().parent
for item in (root, Path(__file__).resolve()):
    attributes = item.stat()
    if attributes.st_uid != 0 or attributes.st_mode & 0o022:
        raise ValueError('availability_bootstrap_trust')
if len(sys.argv) < 2 or sys.argv[1] not in ('front', 'secondary'):
    raise ValueError('availability_entry_mode')
mode = sys.argv.pop(1)
sys.path.insert(0, str(root))
runpy.run_module('generation_front' if mode == 'front' else 'secondary_policy', run_name='__main__')

"""Explicit bootstrap for isolated pure recipe execution."""
from pathlib import Path
import runpy
import sys

root = Path(__file__).resolve().parent
sys.path.insert(0, str(root))
runpy.run_path(str(root / 'recipe_worker.py'), run_name='__main__')

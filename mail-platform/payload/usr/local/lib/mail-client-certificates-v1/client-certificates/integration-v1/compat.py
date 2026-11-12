"""Reuse frozen candidate APIs, never import a test or an application bootstrap."""
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parent.parent
for folder in ('adapters-v1', 'identity-security-v1'):
    path = str(PROJECT / folder)
    if path not in sys.path:
        sys.path.insert(0, path)
import identity as old_identity
import privileges as old_privileges
import repository as old_repository
import registry as old_registry
from core import AdapterError, Owner, require


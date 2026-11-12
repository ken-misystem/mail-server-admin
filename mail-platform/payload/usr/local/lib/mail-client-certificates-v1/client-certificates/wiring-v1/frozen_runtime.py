"""Frozen imports only. Reject module collisions; never import old test modules."""
from pathlib import Path
import sys
import importlib.util

BASE = Path(__file__).resolve().parent.parent
for folder in ('adapters-v1', 'identity-security-v1', 'integration-v1'):
    value = str(BASE/folder)
    if value not in sys.path: sys.path.insert(0, value)
from core import AdapterError, Owner, Receipt, require, domain
from connector import RoleConnector, Endpoint
from database import IdentitySnapshot, BoundRepository, LiveRegistry
from identity import SessionContext, OwnerIdentity

# actions.py uses the short domain name; it must see the SAME Owner/Service types.
require('domain' not in sys.modules or sys.modules['domain'] is domain,
        'domain_module_collision', 'wiring_import')
sys.modules['domain'] = domain
spec = importlib.util.spec_from_file_location('certificate_frozen_actions_v1', BASE/'candidate-v1/actions.py')
actions = sys.modules.get(spec.name)
if actions is None:
    actions = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = actions
    spec.loader.exec_module(actions)


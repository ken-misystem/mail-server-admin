"""Import saved production candidates only, never old tests or launchers."""
from pathlib import Path
import sys

BASE = Path(__file__).resolve().parent.parent
for name in ('runtime-boundaries-v1', 'wiring-v1'):
    path = str(BASE / name)
    if path not in sys.path:
        sys.path.insert(0, path)
from frozen_runtime import require, AdapterError, Owner, Receipt, SessionContext, OwnerIdentity, domain
from role_startup import authenticated_application, broker, RoleFDs
from identity import canonical


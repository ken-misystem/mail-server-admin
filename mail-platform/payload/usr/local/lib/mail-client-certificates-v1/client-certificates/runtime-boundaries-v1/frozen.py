"""Only frozen production candidates; distinct name avoids integration compat collision."""
from pathlib import Path
import sys

BASE = Path(__file__).resolve().parent.parent
for name in ('adapters-v1', 'identity-security-v1'):
    path = str(BASE / name)
    if path not in sys.path:
        sys.path.insert(0, path)
from core import AdapterError, require, Owner
from identity import OwnerIdentity, SessionContext
from tls_gate import TLSGate, SessionBook
from gateway_policy import decide


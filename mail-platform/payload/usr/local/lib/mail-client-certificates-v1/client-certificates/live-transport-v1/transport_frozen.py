"""Frozen implementation imports only; distinct name avoids legacy frozen module."""
from pathlib import Path
import sys

BASE = Path(__file__).resolve().parent.parent
for folder in ('runtime-boundaries-v1','wiring-v1','session-broker-v1'):
    value=str(BASE/folder)
    if value not in sys.path: sys.path.insert(0,value)
from frozen_seams import require, AdapterError, SessionContext, domain
from sessions import SessionRecord, EpochBoundSession
from attestation import unique
from ipc import receive, kernel_peer
from native import LinuxRuntime
from database import session


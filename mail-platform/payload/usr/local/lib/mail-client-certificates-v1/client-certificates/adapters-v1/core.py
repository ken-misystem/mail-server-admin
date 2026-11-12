"""Load the unchanged, pinned V1 core; no application/test/bootstrap execution."""
import importlib.util
from pathlib import Path
import sys

V1 = Path(__file__).resolve().parent.parent / "candidate-v1"
spec = importlib.util.spec_from_file_location("client_certificates_domain_v1", V1 / "domain.py")
domain = sys.modules.get(spec.name)
if domain is None:
    domain = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = domain
    spec.loader.exec_module(domain)
Device, Download, Receipt, Owner = domain.Device, domain.Download, domain.Receipt, domain.Owner


class AdapterError(Exception):
    """No raw native/DB/credential text in exception messages or records."""
    def __init__(self, code, *, phase, native_exit=None, native_code=None, details=None):
        self.code, self.phase = code, phase
        self.native_exit, self.native_code = native_exit, native_code
        self.details = details
        super().__init__(code)


def require(value, code, phase):
    if value is not True:
        raise AdapterError(code, phase=phase)

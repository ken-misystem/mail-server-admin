"""-I deliberately excludes script-directory imports; add ONLY this protected release."""
from pathlib import Path
import os
import stat
import sys

root=Path(__file__).resolve().parent
s=root.stat()
if s.st_uid!=0 or s.st_mode&0o022:
    raise RuntimeError('unsafe_release')
sys.path.insert(0,str(root))
from socketmap import main
main()

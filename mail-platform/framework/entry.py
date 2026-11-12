"""Path bootstrap is local root-owned installed code only."""
from pathlib import Path
import runpy,sys
root=Path(__file__).resolve().parent
sys.path.insert(0,str(root))
runpy.run_path(str(root/'mailctl.py'),run_name='__main__')

from pathlib import Path
import runpy,sys
root=Path(__file__).resolve().parent
sys.path.insert(0,str(root))
runpy.run_path(str(root/'broker.py'),run_name='__main__')

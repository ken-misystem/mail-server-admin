"""Fixed installed module loader. Python -I deliberately ignores the script path."""
import importlib.util
from pathlib import Path
import sys
BASE=Path('/usr/local/lib/mail-management-log-viewer-v1')
for name in ('events','collector'):
    spec=importlib.util.spec_from_file_location(name,BASE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
if __name__=='__main__':raise SystemExit(sys.modules['collector'].main())

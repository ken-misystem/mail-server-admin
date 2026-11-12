"""Fixed installed imports, using the pinned bundled DB driver."""
from pathlib import Path
import sys

BASE=Path(__file__).resolve().parent
sys.path[:0]=[str(BASE),str(BASE/'pymysql-1.2.3-py3-none-any.whl')]
from runtime import main

if __name__=='__main__':
    main()

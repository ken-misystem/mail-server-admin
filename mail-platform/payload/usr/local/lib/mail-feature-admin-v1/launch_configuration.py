"""Exact installed source and verified wheel; no ambient PYTHONPATH."""
import sys
from pathlib import Path
root=Path(__file__).resolve().parent
sys.path[:0]=[str(root),str(root/'pymysql-1.2.3-py3-none-any.whl')]
from configuration_service import main
if __name__=='__main__':
    import pymysql
    main(pymysql)

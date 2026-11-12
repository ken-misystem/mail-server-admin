import sys
from pathlib import Path
root=Path(__file__).resolve().parent
sys.path[:0]=[str(root),str(root/"pymysql-1.2.3-py3-none-any.whl")]
from feature_service import main
import pymysql
main(pymysql)

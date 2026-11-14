"""Explicit generation backend. Accept the trusted frontend's per-connection nonce."""
from pathlib import Path
import json
import sys

BASE=Path(__file__).resolve().parent
sys.path[:0]=[str(BASE),str(BASE/'pymysql-1.2.3-py3-none-any.whl')]

def main():
    if len(sys.argv)!=2:
        raise ValueError('generation_limits_config_argument')
    import pymysql
    from runtime import run
    run(json.loads(Path(sys.argv[1]).read_bytes()),pymysql,generation_front=True)

if __name__=='__main__':
    main()

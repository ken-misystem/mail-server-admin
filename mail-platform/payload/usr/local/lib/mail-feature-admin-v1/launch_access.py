"""Isolated Python entrypoint, only the installed immutable runtime directory."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from access_service import main
if __name__=='__main__':main()

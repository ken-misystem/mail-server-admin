"""Root observer entrypoint with no ambient Python search path."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from observer_service import main
if __name__=='__main__':main()

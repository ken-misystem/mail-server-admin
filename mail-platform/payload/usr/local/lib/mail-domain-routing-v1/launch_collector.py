"""Guard resolver view BEFORE the existing collector reads DB or performs DNS."""
from pathlib import Path
import json
import stat
import sys

def start(check, load, on_error):
    try:
        check()
    except Exception as exc:
        print(json.dumps({'status': 'fail', 'failure': on_error(exc)}))
        return 1

    return load()


def main():
    root = Path(__file__).resolve().parent
    info = root.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError('unsafe_release')
    sys.path.insert(0, str(root))
    from public_dns_guard import verify, safe_error
    def load():
        from collector import main
        return main()
    return start(verify, load, safe_error)


if __name__ == '__main__':
    raise SystemExit(main())

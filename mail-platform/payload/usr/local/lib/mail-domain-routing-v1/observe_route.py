"""Deployment-only public DNS observation in the already-tested resolver namespace."""
import json
from pathlib import Path
import sys
import time

MODULE = Path('/usr/local/lib/mail-domain-routing-v1')
sys.path.insert(0, str(MODULE))
from public_dns_guard import verify, safe_error
from collector import child
from routing import decide


def main():
    try:
        verify()
        cfg = json.loads(Path('/etc/mail-domain-routing-v1/runtime.json').read_bytes())
        data = child(['/usr/bin/php','-n',str(MODULE/'dns_probe.php')], b'{"domain":"yukido.co.jp"}',seconds=5)
        now=int(time.time());decision=decide(True,data,cfg['self_addresses'],now)
        # Only the already-approved old static hostname may be considered for rollback.
        legacy=[row for row in data.get('mx',[]) if row.get('host')=='mx.yukido.co.jp']
        compatible=decision.state=='external' and bool(legacy)
        out={'status':'ok','compatible':compatible,'checked_at':now,'expires_at':min(decision.expires_at,now+30),'decision':decision.json()}
        print(json.dumps(out));return 0
    except Exception as exc:
        failure=safe_error(exc)
        if hasattr(exc,'detail'):failure['native_details']=exc.detail
        print(json.dumps({'status':'fail','failure':failure,'compatible':False}));return 1


if __name__=='__main__':raise SystemExit(main())

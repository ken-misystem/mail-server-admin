"""Append-only, fsynced release intents. Torn records stop further mutations."""
import json
import os
import stat

from broker import require

LIMIT = 4 * 1024 * 1024


class Audit:
    def __init__(self, path):
        self.path = path
        self.records = {}
        self.events = []
        self.healthy = True
        self.fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        info = os.fstat(self.fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_nlink == 1 and info.st_size <= LIMIT, 'audit_file_unsafe')
        import fcntl
        fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        raw = os.pread(self.fd, LIMIT + 1, 0)
        require(not raw or raw.endswith(b'\n'), 'audit_torn_tail')
        for line in raw.splitlines():
            self.accept(json.loads(line))
        # Persist a newly created directory entry before accepting an intent.
        parent = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(parent)
            require(info.st_uid == 0 and not info.st_mode & 0o022, 'audit_parent_unsafe')
            os.fsync(parent)
        finally:
            os.close(parent)

    def accept(self, event):
        require(type(event) is dict and type(event.get('id')) is str, 'audit_record_shape')
        if 'request' in event:
            require(set(event) == {'id', 'request', 'at'} and event['id'] not in self.records, 'audit_duplicate_intent')
            self.records[event['id']] = event.copy()
        else:
            require(set(event) == {'id', 'result', 'at'} and event['id'] in self.records
                    and 'result' not in self.records[event['id']], 'audit_completion_shape')
            self.records[event['id']]['result'] = event['result']
        self.events.append(event)

    def lookup(self, identifier):
        return self.records.get(identifier)

    def append(self, event):
        require(self.healthy, 'audit_unavailable')
        raw = (json.dumps(event, sort_keys=True, separators=(',', ':')) + '\n').encode()
        require(os.fstat(self.fd).st_size + len(raw) <= LIMIT, 'audit_capacity')
        # A partial write is never retried as an action. The next startup rejects
        # its torn tail and preserves the evidence for manual reconciliation.
        try:
            require(os.write(self.fd, raw) == len(raw), 'audit_short_write')
            os.fsync(self.fd)
            self.accept(event)
        except Exception:
            self.healthy = False
            raise

    def recent(self, limit):
        records = list(self.records.values())[-limit:]
        return [{'at': row['at'], 'actor': row['request']['actor'], 'jail': row['request']['jail'],
                 'ip': row['request']['ip'], 'reason': row['request']['reason'],
                 'state': row.get('result', {}).get('state', 'unknown')} for row in reversed(records)]

    def close(self):
        os.close(self.fd)

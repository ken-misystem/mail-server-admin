"""FIFO-order decisions with per-item savepoints and one durable batch commit."""
import re
from policy import Limit, need
from rollup import QUERY, validate

class BatchLedger:

    def __init__(self, connection):
        self.db = connection
        need(not connection.in_transaction, 'caller_transaction')
        validate(connection)
        connection.execute('PRAGMA busy_timeout=250')
        connection.execute('PRAGMA synchronous=FULL')
        need(connection.execute('PRAGMA synchronous').fetchone() == (2,), 'FULL_required')

    def apply(self, admission, now, limits):
        need(type(now) is int and now >= 0 and limits and all((type(value) is Limit for value in limits)), 'clock_or_limits')
        need(all((type(value) is str and re.fullmatch('[0-9a-f]{64}', value) for value in (admission.principal, admission.request_key, admission.payload_hash))), 'admission_hash')
        need(type(admission.recipients) is int and 1 <= admission.recipients <= 1000, 'admission_recipients')
        state = self.db.execute('SELECT last_time FROM ledger_state WHERE id=1').fetchone()
        need(state is not None and type(state[0]) is int and (now >= state[0] - 5), 'clock_rollback')
        now = max(now, state[0])
        if now != state[0]:
            self.db.execute('UPDATE ledger_state SET last_time=? WHERE id=1', (now,))
        previous = self.db.execute('SELECT principal,payload_hash FROM admissions WHERE request_key=?', (admission.request_key,)).fetchone()
        if previous:
            need(previous == (admission.principal, admission.payload_hash), 'replay_conflict')
            return 'duplicate'
        for limit in limits:
            count, recipients = self.db.execute(QUERY, (admission.principal, now - limit.seconds)).fetchone()
            if count + 1 > limit.messages or recipients + admission.recipients > limit.recipients:
                return 'exceeded'
        self.db.execute('INSERT INTO admissions(request_key,principal,payload_hash,admitted_at,recipients) VALUES(?,?,?,?,?)', (admission.request_key, admission.principal, admission.payload_hash, now, admission.recipients))
        self.db.execute('DELETE FROM admissions WHERE rowid IN (SELECT rowid FROM admissions WHERE admitted_at<? ORDER BY admitted_at LIMIT 256)', (now - 86400,))
        return 'admitted'

    def admit_many(self, requests):
        need(1 <= len(requests) <= 16 and (not self.db.in_transaction), 'batch_bounds')
        results = []
        try:
            self.db.execute('BEGIN IMMEDIATE')
            for request in requests:
                self.db.execute('SAVEPOINT admission_one')
                try:
                    outcome = self.apply(*request)
                except ValueError as error:
                    self.db.execute('ROLLBACK TO admission_one')
                    outcome = error
                self.db.execute('RELEASE admission_one')
                results.append(outcome)
            self.db.commit()
            need(not self.db.in_transaction, 'batch_commit_incomplete')
            return results
        except BaseException:
            if self.db.in_transaction:
                self.db.rollback()
            raise

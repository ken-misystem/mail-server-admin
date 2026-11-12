"""Metadata-only DB-API adapter. Explicit connector; no credential discovery/DDL."""
from contextlib import contextmanager
import json
import uuid
from .unreceived import Claim, COMPONENTS, DownloadObservation, GuardError, eligible, need
from . import lifecycle_sql as sql


class Repository:
    def __init__(self, connector, activation_cutoff):
        need(callable(connector) and type(activation_cutoff) is int and activation_cutoff > 0, 'cleanup_connector_cutoff')
        self.connector, self.cutoff = connector, activation_cutoff

    @contextmanager
    def transaction(self, readonly=False):
        connection = cursor = None
        try:
            connection = self.connector(); connection.autocommit(False); cursor = connection.cursor()
            cursor.execute("SET SESSION time_zone='+00:00'")
            cursor.execute('SET SESSION max_statement_time=2'); cursor.execute('SET SESSION innodb_lock_wait_timeout=2')
            if readonly: cursor.execute('START TRANSACTION READ ONLY')
            else: connection.begin()
            yield cursor
            if readonly: connection.rollback()
            else: connection.commit()  # Real PyMySQL success returns None, not truthy.
        except Exception:
            if connection is not None: connection.rollback()
            raise
        finally:
            try:
                if cursor is not None: cursor.close()
            finally:
                if connection is not None: connection.close()

    @staticmethod
    def identifier(value):
        need(type(value) is bytes and len(value) == 16 and uuid.UUID(bytes=value).version == 4, 'cleanup_device_id_shape')
        return str(uuid.UUID(bytes=value))

    def candidates(self, now, cutoff, bound):
        need(type(now) is int and cutoff == self.cutoff and bound == 32, 'cleanup_fixed_query_bound')
        with self.transaction(True) as cur:
            cur.execute(sql.CANDIDATES, (cutoff, now - 30, cutoff) * sql.CANDIDATE_PARAMS); rows = cur.fetchmany(33)
            need(type(rows) in (tuple, list) and len(rows) <= 32, 'cleanup_candidate_rows')
            for row in rows:
                need(type(row) is tuple and len(row) == 2 and type(row[1]) is int and row[1] > 0, 'cleanup_owner_shape')
                self.identifier(row[0])
            return list(rows)

    def locked_row(self, cur, candidate):
        device, owner = candidate
        need(type(owner) is int and owner > 0, 'cleanup_owner_identity'); self.identifier(device)
        cur.execute(sql.OWNER_LOCK, (owner,)); need(cur.fetchmany(2) in ([(owner,)], ((owner,),)), 'cleanup_owner_lock')
        cur.execute(sql.LOCKED_ROW, (device, owner)); rows = cur.fetchmany(2)
        need(type(rows) in (tuple, list) and len(rows) <= 1, 'cleanup_unique_row')
        if not rows: return None
        row = rows[0]
        ok = (type(row) is tuple and len(row) == 10 and row[0] == device and row[1] == owner and row[9] == owner
              and all(type(row[k]) is int for k in (1, 2, 3, 4, 6, 8)))
        if not ok:
            error = GuardError('cleanup_metadata_types')
            known = {'int','str','bytes','bool','float','Decimal','NoneType','tuple','list','memoryview'}
            error.metadata_types = [{'position':k,'actual_type':type(v).__name__ if type(v).__name__ in known else 'other'}
                                    for k,v in enumerate(row[:10])] if type(row) in (tuple,list) else []
            raise error
        return row

    def claim(self, candidate, now, cutoff):
        need(cutoff == self.cutoff, 'cleanup_rollout_policy_changed')
        with self.transaction() as cur:
            row = self.locked_row(cur, candidate)
            if row is None: return None
            observation = DownloadObservation(row[6], row[8], row[7], row[5], row[1] == row[9])
            if not eligible(observation, now, cutoff): return None
            generation = row[4]
            if row[5] == 'active':
                generation += 1
                cur.execute(sql.DENY, (generation, json.dumps(sorted(COMPONENTS)), row[0], row[1], row[4]))
                need(cur.rowcount == 1, 'cleanup_deny_rowcount')
                cur.execute(sql.EXPIRE_DOWNLOAD, (row[0], row[1])); need(cur.rowcount == 1, 'cleanup_download_rowcount')
            else:
                need(row[5] == 'revoke_pending' and row[7] == 'expired' and generation > 0, 'cleanup_resumption_scope')
            return Claim(self.identifier(row[0]), row[1], row[2], row[3], generation)

    def complete(self, claim, acknowledgements):
        need(type(claim) is Claim and type(acknowledgements) is frozenset and acknowledgements <= COMPONENTS, 'cleanup_ack_receipt')
        with self.transaction() as cur:
            row = self.locked_row(cur, (uuid.UUID(claim.id).bytes, claim.owner_id))
            need(row is not None and row[2:5] == (claim.epoch, claim.identity_version, claim.generation)
                 and row[5] == 'revoke_pending' and row[7] == 'expired' and row[6] >= self.cutoff, 'cleanup_committed_generation_changed')
            missing = COMPONENTS - acknowledgements; complete = not missing
            cur.execute(sql.FINISH, ('revoked' if complete else 'revoke_pending', json.dumps(sorted(missing)), row[0], row[1], claim.generation))
            need(cur.rowcount in (0, 1), 'cleanup_completion_rowcount')
            return complete

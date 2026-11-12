#!/usr/bin/python3
"""Fixed ken pilot. Installing this source does not initialize or send anything."""

from contextlib import contextmanager
from datetime import datetime, timezone
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import format_datetime
import hashlib
import json
import os
from pathlib import Path
import smtplib
import sqlite3
import stat
import sys
import types


BUNDLE = Path('/root/ken-junk-digest-v2')
STATE = Path('/var/lib/ken-junk-digest-v1')
ACCOUNT = 'ken@mi-sys.jp'
SENDER = 'spam-report@mi-sys.jp'
DEPENDENCIES = {
    'junk_previous_day_probe': (6752, '045de66a4abd5b41c319a867dc71b0dbd88e2c8db1eeef7e1d636d282699175d'),
    'pilot_message': (2689, 'f42d9312a42f1e294a33520e5b66f5226b444623abfb1aa05b76be7e544bd8eb'),
    'ken_digest_runtime_preflight': (7388, 'e7016b039c6e23590b8edd44b8cac8197cefa29faa8f47177afa3c1d612b5887'),
}
META = 'CREATE TABLE metadata (id INTEGER PRIMARY KEY CHECK(id=1), format INTEGER NOT NULL CHECK(format=1), account TEXT NOT NULL) STRICT'
JOBS = "CREATE TABLE jobs (account TEXT NOT NULL, day TEXT NOT NULL, content_sha256 TEXT NOT NULL, phase TEXT NOT NULL CHECK(phase IN ('in_flight','accepted','unknown')), attempted_at INTEGER NOT NULL, PRIMARY KEY(account,day)) STRICT"


class PilotError(ValueError):
    """Literal codes only; do not include rows, paths, mail or exceptions."""


def secure_info(info, *, directory=False):
    return ((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and info.st_uid == 0 and info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600)
            and (directory or info.st_nlink == 1))


def pinned_read(path, size, pin):
    info = os.lstat(path)
    if not secure_info(info) or info.st_size != size:
        raise PilotError('source_binding')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        if (not secure_info(opened) or (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino)):
            raise PilotError('source_binding')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(size + 1)
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != pin:
            raise PilotError('source_binding')
        return raw
    finally:
        os.close(fd)


def load_dependencies():
    if not secure_info(os.lstat(BUNDLE), directory=True):
        raise PilotError('source_binding')
    result = {}
    for name, (size, pin) in DEPENDENCIES.items():
        raw = pinned_read(BUNDLE / (name + '.py'), size, pin)
        module = types.ModuleType(name)
        exec(compile(raw, '<pinned-' + name + '>', 'exec'), module.__dict__)
        result[name] = module
    return result


def configure_db(db):
    db.execute('PRAGMA temp_store=MEMORY')
    db.execute('PRAGMA trusted_schema=OFF')
    db.execute('PRAGMA synchronous=EXTRA')
    if db.execute('PRAGMA journal_mode').fetchone() != ('delete',):
        raise PilotError('ledger_mode')


def initialize_db(db):
    db.execute('BEGIN IMMEDIATE')
    db.execute(META)
    db.execute(JOBS)
    db.execute('INSERT INTO metadata VALUES (1,1,?)', (ACCOUNT,))
    db.execute('COMMIT')


def validate_db(db):
    if (db.execute('PRAGMA quick_check').fetchall() != [('ok',)]
            or db.execute("SELECT name,type,sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY name").fetchall()
            != [('jobs', 'table', JOBS), ('metadata', 'table', META)]
            or db.execute('SELECT id,format,account FROM metadata').fetchall() != [(1, 1, ACCOUNT)]
            or db.execute('SELECT count(*) FROM jobs').fetchone()[0] > 10000):
        raise PilotError('ledger_invalid')


def state_guard():
    for parent in ('/var', '/var/lib'):
        info = os.lstat(parent)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or info.st_mode & 0o022):
            raise PilotError('ledger_parent')
    if not secure_info(os.lstat(STATE), directory=True):
        raise PilotError('ledger_directory')
    names = {path.name for path in STATE.iterdir()}
    if not {'ledger.sqlite', 'run.lock'} <= names or names - {'ledger.sqlite', 'run.lock', 'ledger.sqlite-journal'}:
        raise PilotError('ledger_inventory')
    for name in names:
        info = os.lstat(STATE / name)
        if not secure_info(info) or info.st_size > 4000000:
            raise PilotError('ledger_file')


def initialize_state():
    """Explicit exclusive initialization only. Never called from run_once."""
    for parent in ('/var', '/var/lib'):
        info = os.lstat(parent)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or info.st_mode & 0o022):
            raise PilotError('ledger_parent')
    os.mkdir(STATE, 0o700)  # Existing/partial state is a stop; never repair/overwrite.
    os.umask(0o077)
    for name in ('run.lock', 'ledger.sqlite'):
        fd = os.open(STATE / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.fsync(fd)
        os.close(fd)
    db = sqlite3.connect((STATE / 'ledger.sqlite').as_uri() + '?mode=rw', uri=True, isolation_level=None, timeout=1)
    try:
        configure_db(db)
        initialize_db(db)
        validate_db(db)
    finally:
        db.close()
    fd = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    state_guard()


@contextmanager
def ledger():
    import fcntl
    state_guard()  # No automatic creation on missing or corrupt state.
    fd = os.open(STATE / 'run.lock', os.O_RDWR | os.O_NOFOLLOW)
    db = None
    try:
        if not secure_info(os.fstat(fd)):
            raise PilotError('ledger_lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state_guard()
        db = sqlite3.connect((STATE / 'ledger.sqlite').as_uri() + '?mode=rw', uri=True, isolation_level=None, timeout=1)
        configure_db(db)
        validate_db(db)
        yield db
    finally:
        if db is not None:
            db.close()
        os.close(fd)


def already_reserved(db, day):
    return db.execute('SELECT 1 FROM jobs WHERE account=? AND day=?', (ACCOUNT, day)).fetchone() is not None


def reserve(db, day, fingerprint, now):
    db.execute('BEGIN IMMEDIATE')
    try:
        db.execute('INSERT INTO jobs VALUES (?,?,?,?,?)', (ACCOUNT, day, fingerprint, 'in_flight', now))
        db.execute('COMMIT')  # The SMTP call is forbidden until commit returns.
    except BaseException:
        if db.in_transaction:
            db.execute('ROLLBACK')
        raise


def record_outcome(db, day, outcome):
    if outcome not in ('accepted', 'unknown'):
        raise PilotError('invalid_outcome')
    db.execute('BEGIN IMMEDIATE')
    try:
        result = db.execute("UPDATE jobs SET phase=? WHERE account=? AND day=? AND phase='in_flight'", (outcome, ACCOUNT, day))
        if result.rowcount != 1:
            raise PilotError('ledger_transition')
        db.execute('COMMIT')
    except BaseException:
        if db.in_transaction:
            db.execute('ROLLBACK')
        raise


def message_bytes(snapshot, rendered, now):
    message = EmailMessage(policy=SMTP)
    message['From'] = SENDER
    message['To'] = ACCOUNT
    message['Subject'] = rendered['subject']
    message['Date'] = format_datetime(now.astimezone(timezone.utc))
    message['Message-ID'] = '<ken-junk-digest-' + snapshot['day'].replace('-', '') + '-v1@mi-sys.jp>'
    message.set_content(rendered['body'] + 'この日報は非原子的な取得時点の件数です。\n', charset='utf-8')
    return message.as_bytes()


def send_once(raw):
    connection = None
    try:
        connection = smtplib.SMTP('127.0.0.1', 25, timeout=12)
        return 'unknown' if connection.sendmail(SENDER, [ACCOUNT], raw) else 'accepted'
    except Exception:
        return 'unknown'  # Never retry; no raw SMTP exception/response is exposed.
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass


def execute(db, *, eligibility, collect, render, window, clock, transport):
    """Injected seams support local tests; production CLI supplies fixed functions."""
    day = window(clock())[0]
    if already_reserved(db, day):
        return {'status': 'skipped', 'reason': 'already_reserved', 'mail_submission': False}
    snapshot = collect()
    if type(snapshot) is not dict or snapshot.get('status') != 'ok':
        reason = snapshot.get('reason') if type(snapshot) is dict else None
        if reason not in ('mailbox_unverified', 'status_unverified', 'search_unverified',
                          'snapshot_unstable', 'collection_failed'):
            reason = 'collection_failed'
        raise PilotError('collect_' + reason)
    rendered = render(snapshot)
    collected = datetime.fromisoformat(snapshot['collected_at'])
    now = clock()
    if window(now)[0] != day or snapshot['day'] != day or now < collected:
        raise PilotError('snapshot_window')
    if not eligibility():  # Recheck after collection, immediately before reservation.
        return {'status': 'skipped', 'reason': 'opted_out', 'mail_submission': False}
    now = clock()
    if window(now)[0] != day or now < collected:
        raise PilotError('send_window')
    raw = message_bytes(snapshot, rendered, now)
    reserve(db, day, hashlib.sha256(raw).hexdigest(), int(now.timestamp()))
    try:
        outcome = transport(raw)
        if outcome not in ('accepted', 'unknown'):
            outcome = 'unknown'
    except Exception:
        outcome = 'unknown'
    # Process death/BaseException leaves durable in_flight; it still blocks resend.
    record_outcome(db, day, outcome)
    return {'status': 'ok' if outcome == 'accepted' else 'fail', 'day': day,
            'smtp_queue_acceptance': outcome == 'accepted', 'mail_submission': True,
            'delivery_receipt': 'user_verification_required', 'automatic_retry': False}


def run_once():
    dependencies = load_dependencies()
    preference = dependencies['ken_digest_runtime_preflight']
    counter = dependencies['junk_previous_day_probe']
    renderer = dependencies['pilot_message']
    clock = lambda: datetime.now(counter.JST)
    counter.window(clock())  # No DB/mailbox work outside the reviewed daily window.
    preference.verify_sources()
    eligible = lambda: preference.parse_preference(preference.read_preference())
    if not eligible():
        return {'status': 'skipped', 'reason': 'opted_out', 'mail_submission': False}
    os.umask(0o077)
    with ledger() as db:
        return execute(db, eligibility=eligible, collect=counter.collect,
                       render=renderer.render_pilot_message, window=counter.window,
                       clock=clock, transport=send_once)


def main():
    if (len(sys.argv) != 2 or sys.argv[1] not in ('--init-state', '--run-once')
            or sys.platform != 'linux' or not sys.flags.isolated
            or not sys.dont_write_bytecode or os.geteuid() != 0):
        print('{"status":"denied"}')
        return 77
    stage = 'initialize_state' if sys.argv[1] == '--init-state' else 'run_once'
    try:
        if sys.argv[1] == '--init-state':
            initialize_state()
            result = {'status': 'ok', 'disk_ledger_created': True, 'mail_submission': False}
        else:
            result = run_once()
    except Exception as error:
        allowed = {'collect_mailbox_unverified', 'collect_status_unverified',
                   'collect_search_unverified', 'collect_snapshot_unstable',
                   'collect_collection_failed', 'source_binding', 'ledger_mode',
                   'ledger_invalid', 'ledger_parent', 'ledger_directory',
                   'ledger_inventory', 'ledger_file', 'ledger_lock',
                   'ledger_transition', 'snapshot_window', 'send_window', 'invalid_outcome'}
        reason = str(error) if isinstance(error, PilotError) and str(error) in allowed else 'runtime_failed'
        result = {'status': 'fail', 'stage': stage, 'reason': reason,
                  'mail_submission': 'not_verified' if stage == 'run_once' else False,
                  'automatic_retry': False}
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0 if result['status'] in ('ok', 'skipped') else 1


if __name__ == '__main__':
    raise SystemExit(main())

"""Exact per-second aggregates maintained in the admission transaction."""
TABLE = '''CREATE TABLE admission_totals (
 principal TEXT NOT NULL CHECK(length(principal)=64),
 admitted_at INTEGER NOT NULL CHECK(typeof(admitted_at)='integer' AND admitted_at>=0),
 messages INTEGER NOT NULL CHECK(typeof(messages)='integer' AND messages>=0),
 recipients INTEGER NOT NULL CHECK(typeof(recipients)='integer' AND recipients>=0),
 CHECK(recipients>=messages AND recipients<=messages*1000),
 PRIMARY KEY(principal,admitted_at)
) WITHOUT ROWID'''
INSERT_TRIGGER = '''CREATE TRIGGER admissions_totals_insert AFTER INSERT ON admissions BEGIN
 INSERT INTO admission_totals(principal,admitted_at,messages,recipients)
 VALUES(NEW.principal,NEW.admitted_at,1,NEW.recipients)
 ON CONFLICT(principal,admitted_at) DO UPDATE SET
 messages=messages+1, recipients=recipients+excluded.recipients;
END'''
DELETE_TRIGGER = '''CREATE TRIGGER admissions_totals_delete AFTER DELETE ON admissions BEGIN
 UPDATE admission_totals SET messages=messages-1,recipients=recipients-OLD.recipients
 WHERE principal=OLD.principal AND admitted_at=OLD.admitted_at AND messages>0 AND recipients>=OLD.recipients;
 SELECT RAISE(ABORT,'rollup_missing') WHERE changes()<>1;
 DELETE FROM admission_totals WHERE principal=OLD.principal AND admitted_at=OLD.admitted_at AND messages=0;
END'''
QUERY = ('SELECT COALESCE(SUM(messages),0),COALESCE(SUM(recipients),0) '
         'FROM admission_totals WHERE principal=? AND admitted_at>?')


def normalize(sql):
    return ' '.join(sql.strip().rstrip(';').split())


def validate(database):
    if database.execute('PRAGMA user_version').fetchone() != (2,):
        raise ValueError('rollup_version')
    expected = {'admission_totals': TABLE, 'admissions_totals_insert': INSERT_TRIGGER,
                'admissions_totals_delete': DELETE_TRIGGER}
    actual = dict(database.execute("SELECT name,sql FROM sqlite_master WHERE name IN ('admission_totals','admissions_totals_insert','admissions_totals_delete')").fetchall())
    if set(actual) != set(expected) or any(normalize(actual[name]) != normalize(sql) for name,sql in expected.items()):
        raise ValueError('rollup_definition')


def migrate(database):
    if database.in_transaction:
        raise ValueError('migration_transaction')
    version = database.execute('PRAGMA user_version').fetchone()
    if version == (2,):
        validate(database)
        return 'already_current'
    if version != (1,):
        raise ValueError('migration_version')
    try:
        database.execute('BEGIN IMMEDIATE')
        if database.execute('PRAGMA user_version').fetchone() != (1,):
            raise ValueError('migration_changed')
        database.execute(TABLE)
        database.execute('INSERT INTO admission_totals SELECT principal,admitted_at,COUNT(*),SUM(recipients) FROM admissions GROUP BY principal,admitted_at')
        database.execute(INSERT_TRIGGER)
        database.execute(DELETE_TRIGGER)
        database.execute('PRAGMA user_version=2')
        validate(database)
        database.commit()
        return 'migrated'
    except Exception:
        if database.in_transaction:
            database.rollback()
        raise


def facts(database):
    validate(database)
    rows,messages,recipients = database.execute('SELECT COUNT(*),COALESCE(SUM(messages),0),COALESCE(SUM(recipients),0) FROM admission_totals').fetchone()
    return {'bucket_rows':rows,'messages':messages,'recipients':recipients,
            'plan':[row[3] for row in database.execute('EXPLAIN QUERY PLAN '+QUERY,('a'*64,0))],
            'synchronous':database.execute('PRAGMA synchronous').fetchone()[0]}

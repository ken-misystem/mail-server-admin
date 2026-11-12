-- Candidate only. A new dedicated quota ledger, never an existing mail database.
PRAGMA user_version = 1;
CREATE TABLE ledger_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    last_time INTEGER NOT NULL CHECK (last_time >= 0)
);
INSERT INTO ledger_state VALUES (1, 0);
CREATE TABLE admissions (
    request_key TEXT PRIMARY KEY CHECK (length(request_key) = 64),
    principal TEXT NOT NULL CHECK (length(principal) = 64),
    payload_hash TEXT NOT NULL CHECK (length(payload_hash) = 64),
    admitted_at INTEGER NOT NULL CHECK (admitted_at >= 0),
    recipients INTEGER NOT NULL CHECK (recipients BETWEEN 1 AND 1000)
);
CREATE INDEX admissions_owner_time ON admissions(principal, admitted_at);
CREATE INDEX admissions_time ON admissions(admitted_at);

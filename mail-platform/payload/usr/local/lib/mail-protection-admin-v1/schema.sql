-- Deployment creates these tables in the root-private broker database.
CREATE TABLE protection_settings (
 kind TEXT PRIMARY KEY CHECK(kind IN ('scanner','upstream')),
 revision INTEGER NOT NULL CHECK(revision>0),
 payload TEXT NOT NULL,
 private_credential TEXT,
 applied_revision INTEGER NOT NULL CHECK(applied_revision>=0 AND applied_revision<=revision),
 phase TEXT NOT NULL CHECK(phase IN ('applied','pending','applying','failed','unknown')),
 failure_code TEXT,
 CHECK(kind='upstream' OR private_credential IS NULL)
);
CREATE TABLE protection_requests (
 request_id TEXT PRIMARY KEY,
 actor_id TEXT NOT NULL,
 kind TEXT NOT NULL,
 revision INTEGER NOT NULL,
 public_before TEXT NOT NULL,
 public_after TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 FOREIGN KEY(kind) REFERENCES protection_settings(kind)
);

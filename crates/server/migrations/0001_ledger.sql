-- One ledger per database (SPEC §4). The log is append-only; a checkpoint
-- commits its entries, its note and the removal of their pending rows in
-- one transaction.
CREATE TABLE isoloir_log (
    seq BIGINT PRIMARY KEY,
    kind TEXT NOT NULL,
    body BYTEA NOT NULL,
    hash TEXT NOT NULL,
    checkpoint BIGINT NOT NULL
);
CREATE INDEX isoloir_log_hash ON isoloir_log (hash);

CREATE TABLE isoloir_checkpoints (
    idx BIGINT PRIMARY KEY,
    note TEXT NOT NULL,
    time BIGINT NOT NULL,
    size BIGINT NOT NULL
);

-- Judged messages waiting for their checkpoint: accepted ones become
-- entries, refused ones reject entries. Written before the ack is posted.
CREATE TABLE isoloir_pending (
    event_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    body BYTEA NOT NULL,
    hash TEXT NOT NULL,
    relay TEXT NOT NULL,
    received BIGINT NOT NULL,
    outcome TEXT NOT NULL,
    reason TEXT
);

-- Every message judged, for idempotent acknowledgements.
CREATE TABLE isoloir_seen (
    event_id TEXT PRIMARY KEY,
    relay TEXT NOT NULL,
    ack JSONB NOT NULL,
    posted BOOLEAN NOT NULL DEFAULT false
);

-- Entries from the operator (setups) and from local authorities.
CREATE TABLE isoloir_submissions (
    id BIGSERIAL PRIMARY KEY,
    kind TEXT NOT NULL,
    body BYTEA NOT NULL,
    submitted BIGINT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    error TEXT
);

-- The newest event time read from each relay.
CREATE TABLE isoloir_cursors (
    relay TEXT PRIMARY KEY,
    since BIGINT NOT NULL
);

-- OpenTimestamps proofs of the checkpoint notes.
CREATE TABLE isoloir_stamps (
    idx BIGINT PRIMARY KEY,
    ots BYTEA NOT NULL,
    complete BOOLEAN NOT NULL DEFAULT false,
    updated BIGINT NOT NULL
);

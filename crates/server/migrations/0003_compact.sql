-- Compact storage, in the store only: the log's bytes and hashes do not
-- change. New rows hold their body in the packed form of
-- crates/server/src/packed.rs (`packed` true: hex and base64 as bytes,
-- unpacked to the exact bytes); the rows already there keep their bytes
-- and are read as they are.
ALTER TABLE isoloir_log ADD COLUMN packed BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE isoloir_refused ADD COLUMN packed BOOLEAN NOT NULL DEFAULT false;

-- Acks: new ones packed in ack_bin; earlier rows keep their JSONB ack.
ALTER TABLE isoloir_seen ALTER COLUMN ack DROP NOT NULL;
ALTER TABLE isoloir_seen ADD COLUMN ack_bin BYTEA;

-- Each body once: a logged submission's body is its log entry's, and a
-- refusal logged on its own has its reject body in the log.
ALTER TABLE isoloir_submissions ALTER COLUMN body DROP NOT NULL;
UPDATE isoloir_submissions SET body = NULL WHERE status = 'logged';
ALTER TABLE isoloir_refused ALTER COLUMN entry DROP NOT NULL;
UPDATE isoloir_refused SET entry = NULL WHERE listed;

-- Refusals are not logged (SPEC §11.4): a refused message is recorded
-- here when it is judged, with its ack in isoloir_seen, kept 30 days for
-- debugging, then purged (by `received`). Rows from 0002 keep their
-- checkpoint and take its time as `received`; refused messages still
-- pending (judged by an earlier ingest, waiting to become reject
-- entries) move here.
ALTER TABLE isoloir_refused ALTER COLUMN checkpoint DROP NOT NULL;
ALTER TABLE isoloir_refused ALTER COLUMN listed DROP NOT NULL;
ALTER TABLE isoloir_refused ADD COLUMN received BIGINT;
ALTER TABLE isoloir_refused ADD COLUMN kind TEXT;
ALTER TABLE isoloir_refused ADD COLUMN reason TEXT;
ALTER TABLE isoloir_refused ADD COLUMN author TEXT;
ALTER TABLE isoloir_refused ADD COLUMN relay TEXT;
UPDATE isoloir_refused r SET received = c.time FROM isoloir_checkpoints c WHERE c.idx = r.checkpoint;
INSERT INTO isoloir_refused (event_id, body, packed, received, kind, reason, author, relay)
    SELECT event_id, body, false, received, kind, reason, author, relay FROM isoloir_pending WHERE outcome <> 'accepted'
    ON CONFLICT (event_id) DO NOTHING;
DELETE FROM isoloir_pending WHERE outcome <> 'accepted';
CREATE INDEX isoloir_refused_received ON isoloir_refused (received);

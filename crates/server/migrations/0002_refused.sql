-- Refusals keep no body in the log (SPEC §11.4): the log names the event,
-- its author, size and body hash; the body stays here, so that an auditor
-- can ask for it (GET /v1/refused/<event id>).
ALTER TABLE isoloir_pending ADD COLUMN author TEXT;

-- Every refusal logged since this migration, written in the checkpoint's
-- transaction. `entry` is its `reject` body: an entry of the log when
-- `listed`, else a leaf of the checkpoint's `rejects` entry (the list
-- GET /v1/rejects/<checkpoint> serves). `body` is the refused message, NULL
-- when it was over the size limit.
CREATE TABLE isoloir_refused (
    event_id TEXT PRIMARY KEY,
    checkpoint BIGINT NOT NULL,
    entry BYTEA NOT NULL,
    listed BOOLEAN NOT NULL,
    body BYTEA
);
CREATE INDEX isoloir_refused_summed ON isoloir_refused (checkpoint) WHERE NOT listed;

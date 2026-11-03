# Running a ledger

The order of operations to put a ledger in production. Three roles, three
places: the **ingest** (a server with Postgres; it holds the log key and
the Nostr key), the **authority** (a machine with no inbound access; it
holds a decryption key), the **operator** (submits setups; any machine
with access to the ingest's database).

## 1. Keys

```sh
isoloir keygen log --origin vote.example/isoloir   # ingest: ISOLOIR_LOG_SEED; the log_key goes in the ledger
isoloir keygen nostr                               # ingest: ISOLOIR_NOSTR_KEY; the public key goes in the ledger
isoloir keygen authority --out /secure/dec.json    # authority: back it up offline; pk and sign_key go in polls
```

The log seed never changes for the life of the ledger (every reader pins
the log key). An authority's key may serve many polls.

## 2. Circuits

On a machine with nargo and bb, build the variants the polls will use
and install them into the mirror (their verification keys and the
artifacts browsers prove with):

```sh
isoloir circuits choice4_single_linked_d20 ranked12_single_linked_d20 --mirror mirror
```

Each line printed is `name vk_hash`: the poll names both.

## 3. Genesis and setups

```sh
isoloir check ledger ledger.json                       # offline: spelling, rules
isoloir check poll poll.json --registry registry.json  # prints the circuit to build
isoloir genesis ledger.json            # once per database
isoloir submit registry registry.json  # waits until the ingest logs it
isoloir submit poll poll.json
```

A setup file is canonical JSON with optional fields at their default
left out (`isoloir check` says what the one spelling is).

The ingest judges every setup (SPEC §5, §7, §8, §13) and refuses a poll
outside the matrix. Later versions of a setup (`version + 1`) change only
what SPEC §13 allows.

## 4. The mirror and the ingest

The mirror is a git repository the ingest commits to and pushes, and
browsers read through a CDN by commit. Create an empty repository, give
the ingest a deploy key with write access, and point it there: an empty
mirror directory is cloned at start (so an ephemeral disk is fine, the
circuits and the stamps come back with the clone, a partial one:
`--filter=blob:none`), a new one is initialised. A checkpoint waits
until the remote holds the previous checkpoints' commits (retried every
30 s): a lasting push failure, such as a revoked deploy key, pauses the
log, with an error in the logs, rather than sign notes naming commits
that could be lost.

```sh
isoloir ingest --mirror-dir /app/mirror --mirror-git git@github.com:org/ledger-data.git \
  --zkverifier /app/zkverifier/verify.mjs
```

With a `direct` channel in the ledger, add `--listen 0.0.0.0:8080` and
put the endpoint behind TLS at the URL the ledger names.

Environment: `DATABASE_URL`, `ISOLOIR_LOG_SEED` (32 bytes of hex, or a
C2SP `PRIVATE+KEY+<origin>+…` string such as Go's note package writes),
`ISOLOIR_NOSTR_KEY`, `ISOLOIR_MIRROR_GIT` (or `--mirror-git`),
`ISOLOIR_MIRROR_SSH_KEY` (the private half of a write deploy key of the
mirror's repository), `ISOLOIR_BB`, `ISOLOIR_ETH_RPC`
(optional, for passport certificate roots), `PORT` (serves `/v1/health`, the refusals for auditors,
`/v1/rejects/<index>` and `/v1/refused/<event id>`, and the direct
channel when the ledger lists one). The ingest refuses to
start when its keys are not the ledger's. One instance per database: a
second one waits up to 10 minutes for the first to stop (a deploy starts
the new process before the old one is gone), then refuses to start. The container image (`Dockerfile`) runs it
by default. At start it replays the log, brings the mirror up to date,
and reads the relays from its saved cursors. It checkpoints when the
log grew, and at least every 10 minutes.

## 5. The authority

```sh
isoloir authority --mirror https://cdn.example/ledger --circuits ./circuits-vk \
  --zkverifier ./zkverifier/verify.mjs --log-key "<log_key>" \
  --keys /secure/dec.json --nostr-key <a Nostr key>
```

It verifies the whole log (every proof, every passport) before
decrypting anything, then publishes each tally when the poll's rule
says it is due; it retries a transient failure and stops for good on a
log that does not verify. `--circuits` points at verification keys you
built yourself (`isoloir circuits … --mirror ./circuits-vk`), so that a
mirror cannot hand you a different circuit. For tlock polls no key is
needed: any authority (or anyone) opens them at the round with
`--drand https://api.drand.sh`.

## 6. Checks

```sh
isoloir audit --mirror https://… --circuits ./circuits-vk --zkverifier ./zkverifier/verify.mjs \
  --log-key "<log_key>" --relays --bitcoin --ledger https://<the ingest's HTTP service>
```

Exit 0 and no `PROBLEM` line. Run it from machines the operator does not
control, with circuits you built. A proof the audit could not check is a
problem, never a pass; `--skip-passports` reports every registration as
unchecked. The log keeps the hash of a refused body, not the body:
`--relays` judges again the refusals the relays still hold, `--ledger`
asks the ingest for the others and for the lists of the refusals a
checkpoint sums up (all checked against the log); what it could get from
neither is a warning. `--bitcoin` checks the checkpoints' stamps against block
headers (stamps take hours to be attested).

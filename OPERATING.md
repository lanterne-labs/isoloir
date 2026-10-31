# Running a ledger

The order of operations to put a ledger in production. Three roles, three
places: the **ingest** (a server with Postgres; it holds the log key and
the Nostr key), the **decrypter** (a machine with no inbound access; it
holds a decryption key), the **operator** (submits setups; any machine
with access to the ingest's database).

## 1. Keys

```sh
isoloir keygen log --origin vote.example/isoloir   # ingest: ISOLOIR_LOG_SEED; the log_key goes in the ledger
isoloir keygen nostr                               # ingest: ISOLOIR_NOSTR_KEY; the public key goes in the ledger
isoloir keygen decrypter --out /secure/dec.json    # decrypter: back it up offline; pk and sign_key go in polls
```

The log seed never changes for the life of the ledger (every reader pins
the log key). A decrypter's key may serve many polls.

## 2. Circuits

On a machine with nargo and bb, build the variants the polls will use
and install them into the mirror (their verification keys and the
artifacts browsers prove with):

```sh
isoloir circuits choice4_elgamal_linked_d20 ranked12_elgamal_linked_d20 --mirror mirror
```

Each line printed is `name vk_hash`: the poll names both.

## 3. Genesis and setups

```sh
isoloir genesis ledger.json            # once per database
isoloir submit registry registry.json  # waits until the ingest logs it
isoloir submit poll poll.json
```

The ingest judges every setup (SPEC §5, §7, §8, §13) and refuses a poll
outside the matrix. Later versions of a setup (`version + 1`) change only
what SPEC §13 allows.

## 4. The ingest

```sh
isoloir ingest --mirror-dir /app/mirror --mirror-git git@github.com:org/ledger-data.git \
  --zkverifier /app/zkverifier/verify.mjs
```

Environment: `DATABASE_URL`, `ISOLOIR_LOG_SEED`, `ISOLOIR_NOSTR_KEY`,
`ISOLOIR_BB`, `ISOLOIR_ETH_RPC` (optional, for passport certificate
roots). One instance per database: a second one refuses to start. The
container image (`Dockerfile`) runs it by default. At start it replays
the log, brings the mirror up to date, and reads the relays from its
saved cursors.

## 5. The trustee

```sh
isoloir trustee --mirror /path/to/mirror-clone --log-key "<log_key>" \
  --keys /secure/dec.json --nostr-key <a Nostr key>
```

It verifies the whole log (every proof) before decrypting anything, then
publishes each tally when the poll's rule says it is due. For tlock polls
no key is needed: any trustee (or anyone) opens them at the round with
`--drand https://api.drand.sh`.

## 6. Checks

```sh
isoloir audit --mirror https://… --log-key "<log_key>" --relays
```

Exit 0 and no `PROBLEM` line. Run it from machines the operator does not
control.

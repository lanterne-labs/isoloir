# pollkit: anonymous polls with passport eligibility, in Rust

A library and a set of binaries for polls where eligibility is proven once
with a passport (ZKPassport), ballots are anonymous and encrypted, every
step is on a public log anyone can recount, and nothing runs on a chain or
a network of ours. The first instance is the presidential pre-poll of
tartuffe.me (today in Go, `mirror/docs/vote/SPEC.md`, "v2"); the second is
whatever comes next. The Go system is not changed by this work.

The name is a placeholder.

## 1. Goals

- One library, several polls. A poll is a `PollKind` (what a ballot says,
  how it is encrypted, how a tally is decoded and shown) plus a `Setup`
  (who may vote, which committee, which policy, when it closes).
- Two publication modes. **Open**: results published while the poll runs
  (the K_REAL rule and the random delay of v2). **Closed**: one result, at
  the close, nothing before.
- Decryption behind one trait, three implementations: a **single
  decrypter** (now), **drand** time-lock for closed polls (now, see §5 for
  what it does and does not enforce), **threshold** committee (later: the
  trait and the log entries are shaped for it from day one).
- A committee key that does not depend on the poll: one key, reused across
  polls and ballot types (§4).
- The browser core in the same Rust, compiled to WebAssembly: one
  implementation of the field math, the hashes, the encodings and the
  signature checks for the server and the browser.

## 2. Non-goals

- Byte compatibility with the v2 log. The ballot encryption changes (§4),
  so this is a v3 protocol. The presidential pre-poll stays on Go until an
  event that starts on v3.
- A chain, a sequencer network, a token, a key ceremony we host.
- Replacing ZKPassport's verifier: it is a TypeScript SDK and stays a Node
  sidecar, as in Go.
- Proving in Rust: proofs are UltraHonk from Noir, made by `bb.js` in the
  browser and verified by the `bb` binary on the server, as today.

## 3. What is kept from v2 as is

The Noir circuits (`circuits/ballot`, `circuits/keygen`), copied into this
repo and adapted for §4. The spec as the design document, forked as
`SPEC.md` v3 with the deltas below. The relay transport (Nostr kinds
7020–7026), the signed acknowledgements, the checkpoints (C2SP note,
Ed25519), the RFC 6962 log, the OpenTimestamps stamps, the git mirror read
through jsDelivr by commit, the receipts and complaints, the device link,
the key in a passkey or 12 words, the registration key the passport proof
binds (`custom_data = H(T_REG, event, key_lo, key_hi)`, BIP340 signature
over the body). None of these know what a ballot says.

## 4. Protocol deltas (v3)

1. **One encryption key.** Exponential ElGamal on Grumpkin under one key
   `PK` per committee. Each chunk of a ballot has its own randomness:
   `(r_j·G, m_j·G + r_j·PK)`. v2 shared one randomness across ten
   independent keys; that saved ten scalar multiplications and ten points
   per ballot, and tied the keys to the circuit of one poll. Cost of v3 for
   the ranked ballot type: ten more fixed-base multiplications in the
   proof, ten more compressed points per ballot (about 330 bytes). For a
   one-question poll, nothing.
2. **The key is a public input of the circuit**, not a constant. One
   compiled circuit per ballot type, reused by every poll of that type and
   every committee. A new poll is a setup entry, not a toolchain run.
3. **`PollKind` in the setup.** The setup names the ballot type (`ranked`,
   `yesno`, …), its parameters (slots, options, the blank), the committee
   (`decrypt: single | tlock | threshold`, with the public key or the
   drand chain and round), the policy (`publish: open{k_real, min_gap} |
   closed`), the verification key hash of the circuit, the relays, the
   close.
4. **Decryption entries.** A `partial` entry: a decryption share of an
   aggregate with a DLEQ proof whose challenge includes the poll
   identifier and the checkpoint it is computed at. A `tally` entry is the
   combination of `t` partials (the identity for a single decrypter). The
   browser and the auditor verify partials and combination alike. For
   tlock polls the entries differ (§5).
5. **Decrypt only what the log justifies.** A trustee computes the
   aggregate itself from the poll's logged ballots at a checkpoint; it is
   never handed a ciphertext. The committee key is reusable because of
   this rule and of the domain-separated DLEQ.
6. **Deterministic policy.** When to decrypt is a function of the log, so
   several trustees agree without talking: at the first checkpoint after
   the close (closed polls); for open polls, the K_REAL rule with the
   delay drawn from the checkpoint hash instead of a private coin.

## 5. Decryption modes

| Mode | Who can read before the close | Who is needed at the close | Status |
|---|---|---|---|
| `single` | the key holder | the key holder | M2 |
| `tlock` | nobody (drand) | nobody: anyone with the drand round finishes the tally | M4 |
| `threshold` | any `t` of `n` trustees | any `t` of `n` | later |

**`tlock`, honestly.** Time-lock encryption is identity-based encryption on
BLS12-381 against a future drand round. Our proofs are on BN254; doing
BLS12-381 arithmetic inside the circuit is non-native and heavy (the
`g_id^r` exponentiation in the pairing target group and one scalar
multiplication in G1, likely millions of constraints: not for a phone
today). So the tlock mode does not encrypt the ElGamal chunks to drand.
It works like this:

- In the circuit, the ballot is proven valid as today, and the circuit
  outputs a binding commitment `c = H(T_CT, plaintext, salt)` as a public
  input instead of ElGamal ciphertexts.
- Outside the circuit, the browser time-locks `(plaintext, salt)` to the
  poll's close round with `tlock` (the drand team's Rust crate, via wasm)
  and posts the proof, `c` and the time-locked blob together.
- The ingest checks the proof and logs the three; it cannot read the
  ballot. At the close round, anyone decrypts every blob, checks it opens
  to the committed `c`, drops the ballots that do not (their voter's own
  fault, nobody else's) and counts the plaintexts in clear.

What this gives: nobody, including us, can read any ballot before the
close, and nobody is needed to finish the tally. What it changes: after
the close, the plaintext of every ballot is public **per pseudonym**, and
so is a pseudonym's voting history (every re-vote opens). The pseudonym is
still unlinkable to the person. For a yes/no question this is usually
acceptable; for a ranked ballot it exposes the ranking pattern, which the
v2 design chose to hide. The setup says which it is, and the library
refuses `tlock` for a ballot type whose `PollKind` declares that
individual plaintexts must stay hidden. In-circuit tlock stays a research
item (a spike in M4 measures the constraint count with bb's bignum
library); if it becomes affordable, it slots in as a fourth mode with
aggregate-only disclosure.

**`single`** is the v2 tallier: one process with the key, partial = full
decryption, DLEQ proof, Ed25519 signature on the entry.

**`threshold`** reuses everything above with `n > 1`: a Pedersen DKG run
over the log (shares encrypted to each trustee's key, complaints as
entries, the auditor replays it) or a trusted dealer, and Lagrange
combination of partials. Not built now; the `Decryptor` trait, the
`partial` entry and the setup fields are shaped so that it adds code
without changing formats.

## 6. Workspace

```
pollkit/
  Cargo.toml                 workspace
  SPEC.md                    v3 (forked from mirror/docs/vote/SPEC.md)
  circuits/                  Noir: ballot-ranked, ballot-yesno, keygen (nargo)
  crates/
    core/        field math (ark-bn254, ark-grumpkin), Poseidon2 with
                 Barretenberg's parameters, domain tags, the tree, leaf
                 and nullifier, canonical JSON (Go-compatible escaping),
                 bodies, BIP340 and Ed25519 checks, the checkpoint note,
                 the RFC 6962 log in memory. no_std-friendly, wasm-ready.
    kinds/       the PollKind trait; `ranked` (the presidential ballot:
                 10 slots, top 3, 66 values, first/ranked/margin decoding),
                 `yesno` (one value). Each: public-input layout, ballot
                 encoder, tally decoder, disclosure declaration.
    decrypt/     the Decryptor trait; single; tlock (tlock crate); the
                 partial entry and the combiner; threshold stub.
    policy/      open (K_REAL, delay from the checkpoint hash, blackouts)
                 and closed; deterministic over the log.
    store/       Postgres with sqlx: log, checkpoints, pending acks,
                 cursors, leases (advisory locks), stamps.
    relays/      nostr-sdk: read with cursors, post with ack, the server
                 key, the archive.
    ingest/      the server: verify (bb subprocess, ZKPassport sidecar),
                 ack, checkpoint in one transaction, mirror (git2), stamps
                 (rust-opentimestamps), close snapshot.
    trustee/     watches the log, applies the policy, posts partials
                 (single now; threshold later). Read access and a relay
                 only: no inbound port, no database credentials.
    audit/       the verifier: everything in SPEC §12 against the API,
                 the relays, the mirror by commit, Bitcoin headers.
    wasm/        `core` + `kinds` encoders + signature checks for the
                 browser (wasm-bindgen).
  zkverifier/    the Node sidecar for ZKPassport proofs (copied from Go)
  js/            `@pollkit/web`: the session (registration, mailbox,
                 checkpoints, receipts, link, key) in TypeScript over the
                 wasm core, framework-free. Pages stay in each project.
  cmd/pollkit    one binary: setup, keygen, ingest, trustee, audit,
                 archive, nostr-key, relays probe.
```

Everything in `core` is checked against vectors exported from the Go
implementation (hashes, leaves, nullifiers, tree roots, canonical bodies,
registration signatures, a full checkpoint note): the first thing to do
in `mirror` before this repo starts, as a test-only command that writes
`vectors/v2.json`. Where v3 diverges (the encryption), the vectors come
from the Noir circuit's own test outputs.

## 7. Milestones

Each milestone ends with its tests green, a tag, and a line in CHANGES.md.

- **M0 — vectors and skeleton** (days). Export the Go vectors. Workspace,
  CI (cargo test, clippy, nargo test), `core` with Poseidon2, tags, tree,
  canonical JSON, bodies, signatures: all vectors pass. Exit: a Rust
  checkpoint note verifies under the production log key.
- **M1 — circuits v3 and `kinds`** (1–2 weeks). The ranked circuit with
  `PK` as a public input and per-chunk randomness; the yesno circuit;
  `kinds` encoders and decoders; vectors from `nargo test`. Exit: a ballot
  made in the browser (`bb.js`) verifies with `bb` through `ingest`'s
  verifier for both kinds.
- **M2 — the server path, single decrypter** (2–3 weeks). `store`,
  `relays`, `ingest`, `trustee` (single), `policy` open and closed,
  `audit`, the CLI. Exit: the v2 local trial replayed on v3 end to end
  with a yesno poll and a ranked poll: register, vote, re-vote, receipt,
  complaint, tally, close snapshot, audit exit 0; the two-instance,
  one-lease and durable-ack tests ported from Go.
- **M3 — the browser package** (2 weeks). `wasm`, `@pollkit/web`, and a
  minimal demo page for yesno. Exit: the Playwright flows of v2 (one
  voter, two devices with the code, complaint page) pass on the demo.
- **M4 — tlock for closed polls** (1–2 weeks). The commitment variant of
  §5, the drand client, the close-time opening in `audit` and `trustee`,
  the disclosure refusal. The in-circuit spike, time-boxed to two days,
  with its number in the spec. Exit: a closed yesno poll whose result
  nobody could compute before the round and anyone can after.
- **M5 — the presidential instance** (1 week). The `ranked` kind wired to
  tartuffe's event and candidate data through a thin adapter crate in
  this repo (no change in `mirror`), the results decoding identical to Go
  (compared on the v2 local log). Exit: a v3 trial of the presidential
  ballot with the same UX flows.
- **M6 — threshold** (later). DKG over the log, `n > 1` trustees, the
  combiner, the audit of the ceremony.

Rough total for M0–M5: eight to ten weeks of focused work, half in `core`
and the circuits. Nothing here is needed for the launch of the pre-poll,
which stays on the Go implementation; M0 is the only step that touches
`mirror`, and only adds a test command.

## 8. Decisions taken in this plan (change them here, not in code)

- v3 is not byte-compatible with v2; the presidential pre-poll migrates at
  a new event, or never.
- One committee key, per-chunk randomness, key as a public input.
- tlock = commitment in circuit + time-locked plaintext outside; per
  pseudonym plaintexts public at the close; refused for kinds that
  declare hidden plaintexts.
- Policy deterministic over the log; no private coin.
- The ZKPassport verifier stays a Node sidecar.
- Threshold designed in, built later.

## 9. Open questions for the owner

1. The repo's name and where it lives (private under `tartuffeme`?).
2. Licence of the library (the Go code is private; this one is meant to be
   reused, so a licence is needed from the first commit).
3. For closed ranked polls: accept per-pseudonym plaintexts at the close
   (tlock mode allowed), or keep them hidden (single or threshold only)?

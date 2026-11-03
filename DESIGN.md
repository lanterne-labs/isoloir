# isoloir: what protects what

The map of the design: the mechanisms in place and the threat each one
answers, the limits of the current version, and the extensions decided
or considered. [SPEC.md](SPEC.md) is normative; this document says why
the pieces are there and where they stop. Section numbers (§) refer to
the spec.

## 1. Mechanisms in place

### 1.1 Eligibility: one passport, one voter

- A voter proves with the ZKPassport app that their passport satisfies
  the registry's rule (age, nationality, document type, expiry) and
  gets a `uid`, unique per passport for the registry's domain and
  scope (§5, §6), salted by ZKPassport's threshold OPRF under a key the
  registry pins, so the state that issued the passport cannot compute it
  alone. The ingest verifies the proof itself (the open
  verifier of the ZKPassport SDK in a Node sidecar) and refuses a `uid`
  already registered (`uid_used`): one registration per passport, ever.
- The registration binds a leaf `ID = H(T_id, registry, s)` of the
  voter's secret `s`, in a Merkle tree of fixed depth (§5). The proof is
  signed by a throwaway key so that a relay that saw it cannot replay
  it under a leaf of its own.
- The tree's root at each checkpoint is in the checkpoint note; a
  ballot proves against a recent root (`anchor_age`), so a registration
  the log does not hold cannot vote.

### 1.2 Anonymity: the ballot names no one

- A ballot proves in zero knowledge (Noir, UltraHonk, no trusted setup
  of ours) that its leaf is in the registry tree and names a
  per-poll pseudonym `H(T_null, poll, s)` (§9). Nothing links the
  pseudonym to the passport, to the leaf, or to the voter's pseudonyms
  in other polls.
- The secret `s` comes from a passkey's PRF output or from 12 words,
  and lives only on the voter's devices (§14). A device link carries it
  to another device end to end encrypted, confirmed by a code.
- With Nostr channels the browser never talks to the operator: the
  ingest reads the relays (§11.1). A voter sends registrations and
  ballots to different relays, chosen by a hash of `s`, so no single
  relay sees both.

### 1.3 Ballot secrecy: sums, not ballots

- Ballots are ElGamal ciphertexts on Grumpkin under the authority's key,
  with the proof that they encrypt a well-formed ballot (§9). The
  authority decrypts aggregates and publishes Chaum–Pedersen proofs of
  correct decryption (§10): anyone checks the decryption without the
  key.
- An open poll publishes a tally only after `k_real` changed ballots
  and `min_gap` seconds, outside blackouts (§10.1); both may only rise
  (§13).
- A closed poll with drand time-lock has no key holder at all: ballots
  open at the beacon round, after the close (§7, §8).
- Packing follows the decryption mode (§7.2): a single authority opens
  each ballot, so seven values per chunk; a threshold committee only
  sums, so two. The circuits are named after the mode.

### 1.4 The count: deterministic and recomputable

- The ballot's statement (§9.1) fixes what a ballot can be: a choice,
  a ranking, its pairwise margins, a blank. No malformed ballot enters
  a sum.
- When a tally is due is a function of the log alone (§10.1), so the
  authority cannot choose a convenient moment; the auditor recomputes
  every tally, aggregate, share and signature (§16).
- Re-votes: `linked` keeps one pseudonym per voter and counts the last
  ballot; `delta` posts unlinkable corrections (§7.4). The matrix (§8)
  refuses the combinations that are unsound, such as corrections under
  time-lock.

### 1.5 The log: one history, signed, mirrored, timestamped

- One append-only log per ledger: an RFC 6962 Merkle tree, with signed
  checkpoints (C2SP `signed-note`, Ed25519) at most every
  `checkpoint_period` seconds and at least every 10 minutes (§4).
  Entries within a checkpoint are ordered by body hash, so the log does
  not reveal arrival order.
- Every refusal is logged by event id, author, size and body hash
  (§11.4); the body is kept by the ingest and the relays, and the
  auditor judges every refusal again from a copy that matches the hash.
- The mirror is static files served from a git repository by commit,
  the commit named in the checkpoint (§15). Setups and tallies carry
  inclusion proofs: the mirror cannot serve a key, a channel or a result
  the log does not hold.
- Every checkpoint note is timestamped with OpenTimestamps and the
  stamp upgraded until it carries a Bitcoin attestation (§4). The audit
  checks the stamps against block headers: the operator cannot claim
  later that the log looked different at a given time.
- Setups are versioned and say what may change (§13); a poll's keys,
  kind, encryption and re-vote rule never change: a different poll is
  a new poll.

### 1.6 Receipts: a dropped ballot is provable

- The ingest answers every message with a signed ack naming the
  checkpoint that will hold it (§11.2); a message is stored before it
  is acknowledged, and logged in the same transaction as the
  checkpoint.
- The browser checks the named checkpoint on the mirror; a missing
  body becomes a complaint, posted with the ack: anyone judges it, and
  only the ingest can sign an ack (§11.3).
- The relays keep copies of what they carried, so the auditor finds a
  message the ingest never judged (withholding, §16) even if the voter
  never complained.

### 1.7 The audit: everything, or a failure

- From the log, the relays and the mirror, the audit recomputes every
  signature, proof, tree, tally, refusal and stamp (§16). A check that
  cannot run is a failure, not a pass.
- The same audit runs in a browser (`audit` of `@isoloir/web`): the
  wasm core replays the log with the same judge, the page checks the
  ballot proofs with bb.js against the mirror's verification keys and
  the passport proofs with the ZKPassport SDK (the registry roots read
  on Ethereum through a public endpoint), then compares the relays'
  copies with the log. The judge's verifiers are synchronous, so the
  log is read twice: the first pass collects the proofs, the second
  replays with the verdicts. Not in the browser yet: the Bitcoin
  stamps, and tlock tallies (reported as not checked).
- §17 tabulates what each party learns: the public, the ingest, the
  authority, a relay, the mirror host, a network observer.

## 2. Limits of the current version

- **One authority can read ballots.** A single key holder may decrypt
  any ballot of any poll under its key. "Closed" means the public cannot
  read before the close; the authority can (§8). Threshold decryption
  is designed in and not built (§3.3).
- **A fork of the log is detectable, not prevented.** The operator
  could keep two signed histories, show a voter the one that holds
  their ballot and tally the other. Catching it requires comparing
  views: the mirror is one public repository and the relays hold every
  checkpoint note, so the two histories must survive side by side, and
  any two conflicting notes prove the fork. But nothing pins one
  history as the only one: OpenTimestamps proves a note existed by a
  time, not that no other did, and the browser does not yet keep the
  last checkpoint it saw to demand that the next one extends it. For a
  closed poll a fork at the end is the cheapest attack, since nobody
  reads the log after the tally. §3.1 and §3.2 close this.
- **Network metadata.** A relay sees the address and the time of each
  post; a direct channel shows them to the operator. Acks are rounded
  to the minute so the public record dates nothing to the second, but
  only Tor or a VPN hides the voter from the relay (§17).
- **Two chains are read or written.** Bitcoin carries the stamps (on
  by default, `--no-stamps` off), and the ZKPassport certificate
  registry root is read from Ethereum. A deployment that wants no chain
  must give up the stamps and pin the root by hand (§3.4).
- **Time-lock is narrow.** Only closed, single-choice polls with one
  ballot per voter (§8): every time-locked ballot opens in clear at the
  round, so a rare ranking would be a receipt, and corrections are
  unsound.
- **Open polls can reveal single ballots.** The difference between two
  tallies is the sum of the ballots in between; with a small `k_real`
  or low traffic that is one ballot, in clear (§10.1). The operator
  sets `k_real`; the library does not forbid a small one.
- **Coercion.** Re-votes let a coerced voter vote again, but under
  `linked` the history of a pseudonym is public, and a rich ballot (a
  ranking with margins) is a pattern a buyer can ask to see in an open
  tally. There is no coercion resistance beyond that.
- **The device is the secret.** A seized or compromised device reveals
  the voter's pseudonyms and ballots; the passkey and the words recover
  the key, they do not revoke it.
- **Passports only.** Eligibility is what ZKPassport proves; identity
  cards would need the provider's support and would leak enumerable
  participation.
- **Scale.** The ingest holds the log in memory (about 100k ballots);
  the browser rebuilds the registry tree (about 100k voters); a tree of
  depth 20 holds a million leaves.
- **Spam grows the log, boundedly.** Anyone can post junk with the
  ledger's tag for free, under a fresh key each time, so a cap per
  author bounds nothing. The log keeps no refused body, and a checkpoint
  logs at most 16 refusals of its own and sums up the rest in one
  `rejects` entry (§11.4): a flood adds at most about 7 KB per
  checkpoint to the mirror, about 30 MB a day at a 20 s period. The
  bodies stay in the ingest's database (up to 256 KiB each), which a
  flood fills instead; that is the operator's disk, not the public
  record. The cost is in the audit: a refusal is judged again only from
  a copy of its body, which the relays may drop and the ingest may stop
  serving; the audit then says it could not judge it.
- **Liveness.** The ingest is one process and the only writer; a
  second refuses to start. It can refuse service, and a deploy pauses
  the log; nothing is lost, since messages wait on the relays. A
  checkpoint waits until the mirror's remote holds the previous ones
  (§15): an outage of the git host pauses the log too.

## 3. Extensions

### 3.1 Next: fork detection without third parties

Decided (2026-11-01). Two changes, no new party:

- The browser keeps the last checkpoint it verified and accepts a new
  one only with the RFC 6962 consistency proof that the new tree
  extends it. A voter shown a different history later sees it fail.
- The audit collects every checkpoint note the relays hold and the
  mirror serves, and fails on two notes of the same index with
  different roots, or on a note that does not extend an earlier one.

With these, a fork must be kept from every reader forever; a reader who
saw both sides proves it.

### 3.2 Later: one history, pinned on a chain (Catena)

Decided in principle (2026-11-01), not scheduled. Timestamping cannot
pin one history: a calendar aggregates many digests and never checks
that two of them conflict, so both sides of a fork get a valid stamp.
What pins a history is a resource the chain refuses to spend twice.
Catena (Tomescu and Devadas, IEEE S&P 2017) keeps one unspent output
per log; each anchor spends it, writes the checkpoint root in an
OP_RETURN, and creates the next output. Every statement has at most one
successor: a fork is a double spend.

- **Schedule.** A ledger setting, not per ballot: an anchor at every
  poll setup, one at the close of every closed poll, and a period (a
  week is enough) for ledgers with open polls. The setup anchor pins
  the rules before any ballot; the close anchor pins the outcome.
- **The authority waits for the anchor.** For a closed poll the
  authority tallies only the anchored close, once the anchoring
  transaction is confirmed (six Bitcoin blocks, about an hour; a few
  minutes on Zcash). Otherwise the operator could fork around the
  tally, and a separate authority asked to decrypt both sides would
  reveal the dropped ballots as the difference of two sums.
- **Verification.** The ledger setup names the genesis transaction; the
  audit walks the chain of spends from it, against block headers or a
  node, and checks that every anchored root is a checkpoint of the log.
  The browser keeps checking signatures and inclusion on the mirror; it
  does not follow the chain.
- **Chains.** Bitcoin (about 150 vbytes per anchor; 1 to 3 sat/vB in
  calm periods, spikes of 50 and more) or Zcash's transparent pool
  (OP_RETURN of 83 bytes; fee fixed by ZIP 317, 0.0001 ZEC). At the
  prices of 2026-10-31, one anchor costs 12 to 35 cents on Bitcoin and
  13 cents on Zcash; weekly anchors about $6 a year, a closed poll two
  anchors. A shielded variant (a chain of spends of one note, the
  account's full viewing key published, a note being spendable once) is
  an idea, not a design.
- **What stays.** OpenTimestamps remains the free proof of time on every
  checkpoint; a deployment may drop it. Witness cosigning (§3.3) covers
  the same threat without a chain and may come first or instead.

### 3.3 Threshold authority

Designed, not built: the share format and the combination are in the
spec (§7.2, §10.3); the DKG, the `dkg` and `partial` entries and more than
one authority are not. Circuits for it exist in name (`threshold`): two
values per chunk, aggregates only. It spreads the trust of §2's first
limit; time-lock removes it for the polls that can use it.

### 3.4 Considered

- **Witness cosigning** (C2SP `tlog-witness`): independent witnesses
  cosign each checkpoint only if it extends the last they saw; readers
  require a quorum. No chain, but third parties to find and run.
- **Tor or a mixnet** in front of any channel, for the voter's address;
  an onion service as a channel (Arti). Nym's mixnet is free today and
  plans credentials bought on its chain.
- **Other channels.** A gossip network (iroh) as an extra delivery
  path, not a replacement: it keeps no copies, so withholding would not
  be provable from it. Zcash memos (512 bytes; memo bundles of 10 KB
  proposed) are too small for a ballot with its proof (about 15 KB).
  Waku's public network needs a membership on an Ethereum rollup.
- **A pinned certificate root**, updated by the operator in the
  registry setup, so that a deployment reads no chain at all.
- **Other registries.** Coin-weighted eligibility on Zcash (shielded
  notes at a snapshot, nullified once); other passport providers. The
  registry is a provider and a rule; a new provider is a new verifier.
- **Scale.** Sharded trees and a streamed log for ledgers beyond 100k
  voters.

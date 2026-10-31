# isoloir — protocol specification

Version 1 of the protocol (`isoloir/1`). This document is normative: the
code follows it, and a change to the protocol is a change here first.

## 1. What it is

A voter proves once, with a passport, that they belong to a **registry**
(for example "French adults"). Their device then holds a secret key that
votes in any **poll** of that registry, anonymously: a ballot proves
membership in zero knowledge and names a per-poll pseudonym that nobody
can link to the passport, nor to the voter's pseudonyms in other polls.
Ballots are encrypted. Everything — registrations, ballots, decryptions,
results — is appended to one public **log** per deployment (a
**ledger**), signed and timestamped, mirrored as static files; anyone can
recount.

Nothing runs on a blockchain. Messages travel through public Nostr
relays; the browser never talks to the operator's server. Bitcoin is used
only to timestamp checkpoints (OpenTimestamps), Ethereum only to read the
passport certificate registry, drand only as a time-lock beacon.

## 2. Parties

| Party | Holds | Does |
|---|---|---|
| Voter (browser) | the voter secret `s` | registers, votes, checks receipts |
| Ingest (server) | the ledger's log key, its Nostr key | verifies and logs, acknowledges, checkpoints, mirrors |
| Decrypter (`trustee`) | a poll's decryption key, or nothing (tlock) | publishes decryptions when the poll's rule says so |
| Relays | nothing | carry messages; see who posts what, from which address |
| Auditor | nothing | recomputes everything from the log, the relays, the mirror |

The ingest cannot vote for anyone, cannot change a ballot, cannot read a
ballot, and cannot drop one without the voter's receipt check failing in
public. It can refuse service, and it sees relay traffic timing as any
relay does.

## 3. Primitives and encodings

- **F**: the BN254 scalar field, `r = 21888242871839275222246405745257275088548364400416034343698204186575808495617`.
- **H**: Poseidon2 over F with Barretenberg's parameters (t = 4, d = 5,
  8 full and 56 partial rounds) and the sponge of `noir-lang/poseidon`
  (rate 3, IV = `len · 2^64` in the capacity element). `H(a, b, …)` is
  that sponge over the inputs in order.
- **Tags**: `T_name` is the field element of the ASCII string
  `isoloir/<name>` read big-endian. Every H in this document starts with
  a tag. Names: `id`, `null`, `node`, `reg`, `prf`, `relay`, `bnull`,
  `bleaf`, `salt`, `cmt`.
- **Grumpkin**: `y² = x³ − 17` over F, generator `G = (1, √−16)` (the
  embedded curve of Noir and Barretenberg). Its order is the BN254 base
  field prime `q`; scalars used in circuits are elements of F (< r < q).
- **Exponential ElGamal** under a public key `PK = sk·G`: a plaintext
  `m ∈ F` with randomness `ρ` is `(ρ·G, m·G + ρ·PK)`. Additively
  homomorphic per component.
- **SHA-256** for bodies, the log and Fiat–Shamir challenges outside
  circuits; **Ed25519** for the log key and decrypter signatures;
  **BIP340 Schnorr on secp256k1** for registration keys and Nostr events.
- **Encodings** (all lower-case hex, `0x`-prefixed where a field or point):
  - a field element: `0x` + 64 hex digits, value < r;
  - a Grumpkin point: `0x` + 64 hex digits: the x coordinate big-endian,
    with bit 255 set when y is odd (as an integer); the point at infinity
    has no encoding and is refused;
  - a Grumpkin scalar: `0x` + 64 hex digits, value < q;
  - bytes (proofs, blobs): standard base64 with padding;
  - times: integer Unix seconds (UTC); durations: integer seconds.
- **Canonical JSON**: UTF-8, object keys sorted bytewise (keys are ASCII),
  no insignificant whitespace, integers only (no floats), strings escaped
  as `serde_json` does (`\"`, `\\`, `\b \f \n \r \t`, other controls as
  `\u00xx`). A body that does not re-serialize to its own bytes is
  refused as `malformed`. Bodies are logged and hashed exactly as posted.
- **Body version**: every body has `"v"`; this document defines `v: 1`
  for every kind. A body of an unknown version is refused as `version`
  (§12).

## 4. The ledger and its log

A ledger is one append-only log, identified by its **origin** (an ASCII
name, e.g. `tartuffe.me/isoloir`). Entries are numbered from 0 (`seq`).

- **Leaf**: `"isoloir/1\n" ‖ seq ‖ "\n" ‖ kind ‖ "\n" ‖ body`, seq in
  decimal. The log is an RFC 6962 Merkle tree over the leaves (SHA-256,
  `0x00` leaf prefix, `0x01` node prefix).
- **Kinds**: `ledger`, `registry`, `register`, `poll`, `ballot`, `reject`,
  `tally`, `close`. Later versions add `partial` and `dkg` (threshold
  decryption, §9.4).
- **Checkpoint**: a signed note (C2SP `signed-note`) by the ledger's log
  key (Ed25519), text:

  ```
  <origin>
  <log size>
  <log root, base64>
  time <unix seconds>
  registry <id> <tree size> <tree root>      one line per registry
  ballots <poll> <tree size> <tree root>     one line per delta poll
  mirror <token>                             when the mirror has one
  ```

  The note's key name is the origin; its key id is the first 4 bytes of
  `SHA-256(origin ‖ "\n" ‖ 0x01 ‖ pubkey)`. Checkpoints are numbered
  from 1 (`index`) and taken at most every `checkpoint_period` seconds
  when the log grew. A checkpoint's entries are the entries since the
  previous one, ordered by body hash (so the order within a checkpoint
  reveals nothing about arrival order); registrations take their tree
  positions in that order.
- **Stamps**: every checkpoint note's SHA-256 is timestamped with
  OpenTimestamps; the stamps are upgraded until they carry a Bitcoin
  attestation and are published with the mirror.

### 4.1 The `ledger` entry

The first entry of a log. Later `ledger` entries with `version + 1`
change what may change (§13).

```json
{"v":1,"version":1,"origin":"tartuffe.me/isoloir",
 "log_key":"<C2SP verifier key>","ingest":"<Nostr pubkey, x-only hex>",
 "relays":[{"url":"wss://…","state":"active"}],
 "checkpoint_period":20,"anchor_age":86400}
```

`relays`: at least three; `state` is `active` or `retired` (read, not
written). `anchor_age`: how old a tree root a ballot may prove against.

## 5. Registries

A registry is a set of eligible voters, reusable by any number of polls.

```json
{"v":1,"id":1,"version":1,"name":"Adultes français",
 "eligibility":{"provider":"zkpassport","domain":"vote.example",
   "scope":"isoloir/registry/1","min_age":18,"nationality":["FRA"],
   "document_type":"passport","require_expiry":true},
 "validity":3600,"depth":20}
```

- The voter's **leaf** is `ID = H(T_id, registry, s)`; positions follow
  the log order (§4). The tree has fixed depth `depth` (≤ 32); empty
  leaves are 0; a node is `H(T_node, left, right)`.
- **Registration** (§6) is the only way into the tree. Rules: one
  registration per passport (`uid`) per registry, ever (`uid_used`); one
  per leaf (`id_used`).
- `provider: "dev"` accepts any registration whose proof bundle names a
  `uid`; it exists for tests and is refused by the ingest unless started
  with `--dev`.

## 6. Registration

1. **The scan comes first.** The browser draws a registration key `R`
   (secp256k1) and opens the passport request with
   `custom_data = H(T_reg, registry, R_lo, R_hi)` (R's x-only public key
   in two 16-byte big-endian limbs), the registry's domain and scope, its
   rules, a non-salted unique identifier, on-device proving, validity
   `validity`.
2. **Then the key.** The browser obtains `s` (§14) and computes `ID`. The
   proof waits with `R` in the browser's storage until then.
3. **Post** `register` to the ledger's relays:

   ```json
   {"v":1,"registry":1,"id":"<ID>","uid":"<passport identifier>",
    "proof":{…the provider's bundle…},"proof_date":1761900000,
    "key":"<R, x-only hex>","sig":"<BIP340 signature, hex>"}
   ```

   `sig` signs `SHA-256("isoloir/1/register\n" ‖ canonical body without
   sig)`. The proof binds R, R signs the leaf: nobody who saw the
   registration can reuse the proof for a leaf of their own.
4. **Checks**, in order: canonical, version, registry known; `key`, `sig`
   (`bad_sig`); `|proof_date − now| ≤ validity + 300` (`stale_date`);
   `uid` and `ID` unused (`uid_used`, `id_used`); the provider verifies
   the proof against the rules, the binding and `proof_date` and returns
   the same `uid` (`bad_proof`). An infrastructure failure (the provider
   unreachable) is not a refusal: the message waits (§11).

What becomes public: that passport `uid` registered in this registry, at
which checkpoint, with which leaf. The state that issued the passport can
compute `uid`; participation is public to it. Votes are not.

## 7. Polls

```json
{"v":1,"id":7,"version":1,"registry":1,"title":"…",
 "kind":{…},"encryption":{…},"publish":{…},"revote":"linked",
 "opens":1761900000,"closes":1777000000,"blackouts":[{"from":…,"to":…}],
 "circuit":{"name":"choice4_elgamal_linked","vk_hash":"0x…"}}
```

### 7.1 Kinds

A kind says what a ballot is, its **values** (the integer vector the
tally sums), its **class** (single choice or multiple choices, §8) and
the circuit family that proves it.

- **`choice`** (single choice): `{"type":"choice","options":["Oui","Non"],
  "blank":true}`. Slots: the options, then the blank if any. A ballot
  picks one slot, or none (a withdrawal, when re-votes are on). Values:
  one per slot, 1 for the slot picked. Yes/no is `choice` with two
  options.
- **`ranked`** (multiple choices): `{"type":"ranked","options":[…],
  "blank":true,"depth":3,"margins":true}`. A ballot ranks up to `depth`
  distinct slots; the blank, if picked, is last. Values: `first[m]` (1 for
  the slot ranked first), `ranked[m]` (1 for every ranked slot), and with
  `margins` the pairwise `margin[i<j]` (+1 when i is ranked before j, −1
  when after, 0 otherwise; a ranked slot is before every unranked one).

The circuit of a kind has a compiled maximum of slots `M`: `choice4`,
`choice16`, `ranked12`. A poll's `mask` (derived from the options and
the blank: bit k set for an active slot) is a public input; inactive
slots must be empty.

**Packing.** A ballot's values are small signed integers, `|v| ≤ 2` (a
correction of a margin goes from −1 to +1). Each is written as the digit
`v + 2`, and digits go two per **chunk**: `chunk = d0 + d1·2^32`.
Plaintexts are thus non-negative integers far below both r and q: a
"negative" element of F would not be negative in Grumpkin's group, whose
order is q, and sums of ciphertexts would stop being sums of values. A
sum over N ballots has digits `Σv + 2N`, in `[0, 4N]`, below 2^32 for
N < 2^30 (so `depth ≤ 30`). Decrypting a chunk sum is a discrete
logarithm with both digits in `[2N − B, 2N + B]`, B the bound the kind
gives for a value sum (N for counts): a baby-step table over one digit,
reused for each candidate of the other.

### 7.2 Encryption

- **`elgamal`**: `{"mode":"elgamal","pk":"<point>","decrypter":
  {"type":"single","sign_key":"<Ed25519 public key hex>"}}`. Each chunk
  is encrypted under `pk` with its own randomness:
  `(ρ_j·G, chunk_j·G + ρ_j·PK)`. One key per committee, independent of
  the poll: the same `pk` may serve many polls (§9.3).
- **`tlock`**: `{"mode":"tlock","chain":"<drand chain hash>",
  "public_key":"<drand group public key hex>","period":3,"genesis":…,
  "round":<round at or after closes>}`. The ballot carries a commitment
  `vcmt = H(T_cmt, salt, H(v_0, …, v_{n−1}))` and a blob: a 16-byte key
  time-locked to `round` (drand IBE, the `tlock` format) followed by
  `{"salt":"0x…","values":[…]}` sealed under that key
  (ChaCha20-Poly1305, key `SHA-256("isoloir/1/tlock" ‖ key)`, zero nonce:
  the key is used once). Nobody can open a blob before the round; anyone
  can after. The circuit checks the values against the kind, so an
  invalid choice is refused at once, not discovered at the close.

### 7.3 Publication

- **`open`**: `{"mode":"open","k_real":1,"min_gap":0,"coin":true}`:
  results while the poll runs (§10.1).
- **`closed`**: `{"mode":"closed"}`: one result, after the close.

### 7.4 Re-votes

- **`none`**: one ballot per voter; the pseudonym is
  `nullifier = H(T_null, poll, s)`; a second ballot is `revote_off`.
- **`linked`**: the pseudonym `nullifier` and a sequence number `seq`;
  a ballot counts if it has the highest `seq` of its nullifier. The log
  shows when and how often a pseudonym changed its mind.
- **`delta`**: every ballot has a fresh identifier
  `ident_i = H(T_bnull, poll, s, i)` (i = 0, 1, … private), carries the
  **correction** `new − old` (old = 0 for i = 0), and appends to the
  poll's **ballot tree** the leaf `H(T_bleaf, ident_i, cmt_i)` with
  `cmt_i = H(T_cmt, salt_i, new…)`, `salt_i = H(T_salt, poll, s, i)`. For
  i > 0 the proof shows that the leaf of ballot i − 1 is in the ballot
  tree (a root from a checkpoint) and opens to `old`. The tally is the
  sum of every ballot. Nothing links a correction to the ballot it
  corrects, and a first ballot looks like a correction. `ident` must be
  unused (`duplicate`), so each voter has one chain.

## 8. The matrix

| Encryption, publication | Ballot class | none | linked | delta |
|---|---|---|---|---|
| elgamal, open | single choice | ✓ | ✓ | ✓ |
| elgamal, open | multiple choices | ✓ | ✓ | ✓ |
| elgamal, closed | single choice | ✓ | ✓ | ✓ |
| elgamal, closed | multiple choices | ✓ | ✓ | ✓ |
| tlock, open | any | ✗ | ✗ | ✗ |
| tlock, closed | single choice | ✓ | ✗ | ✗ |
| tlock, closed | multiple choices | ✗ | ✗ | ✗ |

- tlock, open: nothing opens before the round.
- tlock, multiple choices: every ballot opens in clear at the round; a
  rare ranking is a receipt for a coercer or a buyer. A correction is a
  pattern too, so delta does not help.
- tlock, single choice, linked: ballots are alike but histories are not
  ("yes, no, yes, no") under one pseudonym.
- tlock, delta: a correction is only sound if the ballot it corrects is
  counted. Under tlock nobody can tell before the round whether a blob
  opens, and a voter could post a first ballot whose blob is garbage
  (void at the round) and then a valid correction "no − yes": unlinkable
  to the void ballot, it would remove someone else's "yes". The circuit
  cannot check a drand ciphertext at phone cost, so tlock polls take one
  ballot per voter.

A `poll` entry outside the matrix is refused by the ingest and reported
by the auditor. With a single decrypter, "closed" means the public cannot
read before the close: the key holder can. Threshold spreads that trust;
tlock removes it.

## 9. Ballots

### 9.1 The statement

One UltraHonk proof (Noir, `bb`, verifier target `noir-recursive`,
zero-knowledge). Public inputs, in this order:

1. `registry`, `poll`, `setup` (the seq of the `poll` entry proven
   against), `mask`, for ranked kinds `blank` (the blank's slot, or the
   circuit's slot count when there is none), `root` (a registry tree
   root);
2. none/linked: `nullifier`, `seq`; delta: `ident`, `broot` (a ballot tree
   root), `cmt` (the new leaf's commitment);
3. elgamal: `pk.x`, `pk.y`, then the ciphertexts as return values
   (`c0.x, c0.y, c1.x, c1.y` per chunk); tlock: `vcmt`, the commitment
   to the values the blob holds, and `bhash`, SHA-256 of the blob read
   as a big-endian integer modulo r: the proof binds the blob, so a relay
   cannot swap it, and only the voter can make their own ballot void.

The circuit proves: the leaf `H(T_id, registry, s)` is in the tree of
`root`; the pseudonym is computed from `s` as §7.4 says; the choice is
valid for the kind and the mask; the values are those of the choice
(delta: of the correction, with the chain of §7.4); the ciphertexts
encrypt the packed values under `pk` (elgamal) or `vcmt` commits to them
with `salt` (tlock).

### 9.2 The body

```json
{"v":1,"poll":7,"setup":12,"root":"0x…",
 "nullifier":"0x…","seq":3,                        none/linked
 "ident":"0x…","broot":"0x…","cmt":"0x…",          delta
 "ct":[["<c0>","<c1>"],…],                         elgamal
 "vcmt":"0x…","blob":"<base64>",                   tlock
 "proof":"<base64>"}
```

### 9.3 Checks (the ingest, in order)

canonical, version, poll known and its `setup` in force (§13: the
current one, or the previous one for 24 h after its successor);
`opens ≤ now < closes` (`not_open`, `closed`); `root` is a checkpoint
root of the registry at most `anchor_age` old (`old_root`), same for
`broot`; points decode and are not at infinity (`malformed`); the
re-vote rule (`revote_off`, `stale_seq` when `seq` is not above the
pseudonym's last, `duplicate`); `blob` ≤ 4 KiB (tlock); the proof against
the circuit of the setup with the public inputs rebuilt from the body,
the setup and the poll (`bad_proof`).

The committee key is reusable across polls because a decrypter only ever
decrypts aggregates it recomputed from one poll's logged ballots, never
a ciphertext it is handed, and because its proofs carry the poll and the
log position in their challenge.

## 10. Results

### 10.1 When

Deterministic over the log, so any decrypter and any auditor agree:

- `open`: at a checkpoint at time t, with `changed` the number of
  pseudonyms whose counted ballot changed since the last tally (delta:
  the number of ballots since), a tally is due when `changed ≥ k_real`,
  `t − last ≥ min_gap`, t is outside every blackout, and, with `coin`,
  the low bit of `SHA-256("isoloir/1/coin" ‖ checkpoint root)` is 1.
  The tally covers the log up to that checkpoint (`upto`, its last seq).
- `closed`: one tally, covering up to the `close` entry.
- At the close of an open poll, a final tally covering up to `close`,
  even during a blackout.

### 10.2 The counted ballots

Up to `upto`: none/linked, the ballot of each nullifier with the highest
seq; delta, every ballot. The **aggregate** of chunk j is the
component-wise sum of the counted ciphertexts' chunk j.

### 10.3 The `tally` entry (elgamal)

```json
{"v":1,"poll":7,"upto":4810,"checkpoint":233,"final":false,
 "values":[…counts…],
 "shares":[{"trustee":1,"d":["<point>",…],"proofs":[["<c>","<z>"],…]}],
 "sig":"<Ed25519, hex>"}
```

For each chunk j with aggregate `(A0_j, A1_j)`: each share gives
`d_ij = sk_i·A0_j` and a Chaum–Pedersen proof that
`log_G(PK_i) = log_{A0_j}(d_ij)`, with challenge
`SHA-256("isoloir/1/dleq" ‖ poll ‖ upto ‖ j ‖ G ‖ PK_i ‖ A0_j ‖ d_ij ‖ a ‖ b) mod q`
(points in their 32-byte encodings, integers as 8-byte big-endian). The
decryption is `D_j = Σ λ_i·d_ij` (Lagrange at 0 over the trustees
present; one trustee: `D_j = d_1j`), and the values must satisfy
`A1_j − D_j = pack(values)_j·G`. `sig` signs `SHA-256("isoloir/1/tally\n"
‖ canonical body without sig)` under the decrypter's `sign_key`.

### 10.4 The `tally` entry (tlock)

```json
{"v":1,"poll":7,"upto":4810,"final":true,
 "beacon":{"round":…,"signature":"<hex>"},
 "values":[…],"counted":…,"void":[…seqs…]}
```

The beacon signature verifies under the chain's public key. Every
counted ballot's blob is decrypted with it and must open to its `vcmt`;
a blob that does not (garbled or swapped in transit) makes its ballot
**void**: listed in `void`, not counted. Whoever posts it, the ingest
checks it in full before logging it.

### 10.5 The `close` entry

At the first checkpoint whose time is ≥ `closes`, the ingest appends
`{"v":1,"poll":7,"at":<closes>,"last":<seq of the last ballot>}`.
Ballots after are `closed`. Relays may still deliver ballots posted
before `closes` (§11): they are logged before `close` if they arrive
before it, else refused, and the complaint process (§11.3) covers a
ballot acknowledged and never logged.

## 11. Transport

### 11.1 Relays

Nostr events, tag `["t","isoloir/1/<origin>"]`, content the body:

| Kind | Content | Signed by |
|---|---|---|
| 7100 | register | a throwaway key |
| 7101 | ballot | a throwaway key |
| 7102 | ack | the ingest |
| 7103 | checkpoint note | the ingest |
| 7104 | device link | a throwaway key |
| 7105 | tally | a throwaway key (the body carries its own signature) |
| 7106 | complaint | a throwaway key |

A voter posts to one relay chosen by `H(T_relay, s, …)` among the active
ones, and moves to the next when no ack comes within 60 s.

### 11.2 Acknowledgements

The ingest answers every message it has judged with an ack on the relay
it came from, tag `["e", <event id>]`:

```json
{"v":1,"of":"<event id>","hash":"<SHA-256 of the body>",
 "outcome":"accepted","checkpoint":234}
```

or `"outcome":"rejected","reason":"…"`. An accepted message is first
written to durable storage (pending), then acknowledged, then logged at
the named checkpoint in the same transaction as the checkpoint itself.
A message whose check failed for an infrastructure reason is neither
acknowledged nor refused; it is retried.

### 11.3 Receipts and complaints

The browser keeps the ack and checks the entries of the named
checkpoint on the mirror for its body hash. A missing body is a
**complaint**: `{"v":1,"ack":<the ack event>,"body":<the body>}` posted
to the relays; anyone can judge it from the log and the ack's
signature.

### 11.4 Every refusal is logged

Refusals are `reject` entries `{"v":1,"of":"<event id>","hash":"…",
"reason":"…"}`, so the log accounts for every message the ingest judged.

## 12. Reasons

`malformed`, `version`, `unknown`, `not_open`, `closed`, `bad_sig`,
`stale_date`, `uid_used`, `id_used`, `bad_proof`, `old_root`,
`revote_off`, `stale_seq`, `duplicate`, `not_due`, `bad_tally`.

## 13. Upgrades

- **Bodies**: `"v"`; readers dispatch on (kind, v) and refuse unknown
  versions. A new body version is added alongside the old one.
- **Setups** (`ledger`, `registry`, `poll`): a later entry with the same
  id and `version + 1` supersedes the previous. What may change:
  - `ledger`: `relays` (append, retire), `checkpoint_period`,
    `anchor_age`; never `origin`, `log_key`.
  - `registry`: `name`, `validity`; never `id`, `eligibility`, `depth`.
  - `poll`: `title`, `closes` (later only, before the close), `blackouts`
    (future ones only), `publish.k_real` and `publish.min_gap` (open
    polls), `circuit` (a fixed circuit with the same public inputs);
    never `registry`, `kind`, `encryption`, `revote`, `publish.mode`,
    `opens`.
  A ballot names the setup it proves against (`setup`); the previous
  setup is accepted for 24 h after its successor is logged.
- **Protocol**: the leaf prefix, the checkpoint origin line and the
  Nostr tag carry `isoloir/1`. A ledger never changes protocol version;
  `isoloir/2` would be a new ledger.
- **Storage**: numbered migrations; the server refuses to start on a
  schema newer than it knows.
- **Circuits**: a circuit is named and its verification key hashed in
  the poll; a new circuit is a new name, so a setup change says exactly
  which one ballots prove against.

## 14. The voter secret

As in tartuffe-vote/2 §4.1–4.2: where the platform offers the WebAuthn
PRF extension, `s = H(T_prf, prf_lo, prf_hi)` from a passkey's PRF output
on input `isoloir/1/<origin>/<registry>`; otherwise `s` comes from 12
words (BIP39, 128 bits) or is carried by a device link (ECDH secp256k1 +
XChaCha20-Poly1305 over a relay, confirmed by a six-digit code). No
ballot is cast before a backup is confirmed.

## 15. The mirror

Static files, served from a git repository by commit (the checkpoint's
`mirror` token) so that a reader can prove which files it was served:

```
checkpoint.txt                       the latest note
checkpoints/<index>.txt              every note
entries/<index>.json                 [{seq, kind, body}] of a checkpoint
stamps/<index>.ots                   the OpenTimestamps proof
setup/ledger.json, registries/<id>.json, polls/<id>.json
circuits/<name>/{artifact.json,vk}
registries/<id>/leaves/<k>.json      leaves 1024·k … 1024·k+1023
registries/<id>/positions/<pp>.json  leaf → position, by leaf prefix
polls/<id>/pseudonyms/<pp>.json      nullifier → last seq (linked)
polls/<id>/ballots/<k>.json          ballot tree leaves (delta)
polls/<id>/tallies/latest.json, polls/<id>/tallies/<seq>.json
```

## 16. The audit

From the log alone: every checkpoint signature and the log's consistency
between checkpoints; the stamps against Bitcoin block headers; every
setup against its predecessor (§13) and the matrix (§8); every
registration (signature, freshness, provider proof, uniqueness, tree
positions and roots); every ballot (roots in age, re-vote rule, proof);
every reject's reason, recomputed; every tally (due by §10.1, aggregate,
shares, combination, values, signature; tlock: beacon, openings, void
list); every close. With the relays: every message the relays hold was
judged (else withholding). With the mirror: its files at each
checkpoint's commit are the log's.

## 17. What each party learns

| | Passport ↔ leaf | Leaf ↔ ballot | Ballot content | Re-vote history |
|---|---|---|---|---|
| Public | yes (uid is public) | no | aggregates only (elgamal); every ballot at the round (tlock) | linked: per pseudonym; delta: nothing |
| Ingest | yes | no (timing only, as a relay) | as public | as public |
| Decrypter (elgamal) | yes | no | could decrypt any ballot | as public |
| Relay | yes | address and time of the post | as public | as public |

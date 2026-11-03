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

Nothing runs on a blockchain. Messages travel by the **channels** the
ledger declares (§11.1): public Nostr relays, so that the browser never
talks to the operator's server, or the ingest's own HTTP endpoint, or
both; the library picks them from the ledger. Channels are transport
only: nothing relies on them keeping a copy of anything. Bitcoin is used
only to timestamp checkpoints (OpenTimestamps), Ethereum only to read the
passport certificate registry, drand only as a time-lock beacon.

## 2. Parties

| Party | Holds | Does |
|---|---|---|
| Voter (browser) | the voter secret `s` | registers, votes, checks receipts |
| Ingest (server) | the ledger's log key, its Nostr key | verifies and logs, acknowledges, checkpoints, mirrors |
| Authority (`authority`) | a poll's decryption key, or nothing (tlock) | publishes decryptions when the poll's rule says so |
| Channels | nothing | carry messages; a relay sees who posts what, from which address (a direct channel: the operator does) |
| Auditor | nothing | recomputes everything from the log and the mirror |

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
  circuits; **Ed25519** for the log key and authority signatures;
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
name, e.g. `vote.example/isoloir`). Entries are numbered from 0 (`seq`).

- **Leaf**: `"isoloir/1\n" ‖ seq ‖ "\n" ‖ kind ‖ "\n" ‖ body`, seq in
  decimal. The log is an RFC 6962 Merkle tree over the leaves (SHA-256,
  `0x00` leaf prefix, `0x01` node prefix).
- **Kinds**: `ledger`, `registry`, `register`, `poll`, `ballot`, `tally`,
  `close`. Logs written before this version of the document also hold
  `reject` and `rejects` entries (§11.4), which readers still accept and
  no ingest writes. Later versions add `partial` and `dkg` (threshold
  decryption, §9.4).
- **Checkpoint**: a signed note (C2SP `signed-note`) by the ledger's log
  key (Ed25519), text:

  ```
  <origin>
  <log size>
  <log root, base64>
  index <checkpoint index>
  time <unix seconds>
  registry <id> <tree size> <tree root>      one line per registry
  ballots <poll> <tree size> <tree root>     one line per delta poll
  mirror <commit>:<index>                    when the mirror has one
  ```

  The note's key name is the origin; its key id is the first 4 bytes of
  `SHA-256(origin ‖ "\n" ‖ 0x01 ‖ pubkey)`. Checkpoints are numbered
  from 1 (`index`) and taken at most every `checkpoint_period` seconds
  when the log grew, and at least every 10 minutes whatever happened (a
  **heartbeat**, so that readers can refuse a stale checkpoint, §9.3). A
  checkpoint's entries are the entries since the previous one, ordered by
  body hash (so the order within a checkpoint
  reveals nothing about arrival order), except `close` entries, which end
  their checkpoint (in poll order) so that the ballots accepted before
  the close and logged with it come first; registrations take their tree
  positions in that order.
- **The `mirror` line** names the newest commit of the mirror's
  repository that the ingest knows its remote holds, and the newest
  checkpoint whose files that commit holds (§15): a checkpoint is never
  delayed by the mirror, so its own files are named by a later note.
  One token, `<commit>:<index>`, so that readers of earlier versions
  (which take the line's one field as a commit) still parse the note,
  then fall back to the latest files. Notes written before this version
  name one commit, the one holding that checkpoint's own data files
  (`mirror <commit>`).
- **Stamps**: every checkpoint note's SHA-256 is timestamped with
  OpenTimestamps; the stamps are upgraded until they carry a Bitcoin
  attestation and are published with the mirror.

### 4.1 The `ledger` entry

The first entry of a log. Later `ledger` entries with `version + 1`
change what may change (§13).

```json
{"v":1,"version":1,"origin":"vote.example/isoloir",
 "log_key":"<C2SP verifier key>","ingest":"<Nostr pubkey, x-only hex>",
 "channels":[{"type":"nostr","url":"wss://…","state":"active"},
             {"type":"direct","url":"https://vote.example/ingest","state":"active"}],
 "checkpoint_period":20,"anchor_age":86400,
 "revote_gap":3600,"pow":16}
```

`channels`: at least one active (three relays for a ledger that wants
voters never to reach the operator); `state` is `active` or `retired` (read, not
written). `anchor_age`: how old a tree root a ballot may prove against
(at least `checkpoint_period`). Channel URLs are `wss://` (nostr) or
`https://` (direct), `ws://` and `http://` on the local machine only, no
trailing slash, no duplicate. `revote_gap` (seconds, absent: 0): the
least time between two counted ballots of one pseudonym (§7.4). `pow`
(bits, absent: 0): the proof of work every envelope carries (§11.1).
Both are left out at 0, so a ledger written without them reads the same.

## 5. Registries

A registry is a set of eligible voters, reusable by any number of polls.

```json
{"v":1,"id":1,"version":1,"name":"French adults",
 "eligibility":{"provider":"zkpassport","domain":"vote.example",
   "scope":"isoloir/registry/1","min_age":18,"nationality":["FRA"],
   "document_type":"passport","require_expiry":true,
   "oprf_key":{"id":"1",
     "x":"18166959201346800007624274454748264099569154910741994195889360204497718998925",
     "y":"17198643698593566948834308934687875815952052155871236424838876937611092999400"}},
 "validity":3600,"depth":20}
```

- **The identifier** (`uid`) is one per passport for the registry's
  domain and scope. ZKPassport derives it from a hash of the chip's
  data and of the state's signature over it. With `oprf_key` it is
  **salted**: the hash also takes the output of ZKPassport's threshold
  OPRF (2 of 3 nodes, run by separate operators) under that key, on a
  blinded query, so the state that issued the passport cannot compute it
  alone. Without `oprf_key` it is the document's own, which that state
  can compute. A registry takes one type only (two types would give a
  passport two identifiers), and the key is pinned: the verifier checks
  the proof's OPRF key against the registry's, never against what the
  nodes serve, so an audit holds when they are gone. The key above is
  ZKPassport's mainnet key 1.
  A salted identifier comes with ZKPassport's strict **face match**:
  the app matches the holder's face to the chip's photo, on the phone,
  and the proofs carry that check; the SDK gives no salted identifier
  without it.

- The voter's **leaf** is `ID = H(T_id, registry, s)`; positions follow
  the log order (§4). The tree has fixed depth `depth` (≤ 32); empty
  leaves are 0; a node is `H(T_node, left, right)`.
- **Registration** (§6) is the only way into the tree. Rules: one
  registration per passport (`uid`) per registry, ever (`uid_used`); one
  per leaf (`id_used`); none once the tree is full (`full`).
- `provider: "dev"` accepts any registration whose proof bundle names a
  `uid`; it exists for tests and is refused by the ingest unless started
  with `--dev`.

## 6. Registration

1. **The scan comes first.** The browser draws a registration key `R`
   (secp256k1) and opens the passport request with
   `custom_data = H(T_reg, registry, R_lo, R_hi)` (R's x-only public key
   in two 16-byte big-endian limbs), the registry's domain and scope, its
   rules, the registry's identifier type (salted with `oprfKeyId` and
   the strict face match, or non-salted), on-device proving, validity
   `validity`.
2. **Then the key.** The browser obtains `s` (§14) and computes `ID`. The
   proof waits with `R` in the browser's storage until then.
3. **Post** `register` by the ledger's channels (§11.1):

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
which checkpoint, with which leaf. With a salted identifier, only whoever
can query the OPRF for that passport (its holder, or a state with 2 of
the 3 OPRF operators) can tell it is theirs; without, the issuing state
can compute every `uid`, and participation is public to it. Votes are
not, either way.

## 7. Polls

```json
{"v":1,"id":7,"version":1,"registry":1,"title":"…",
 "kind":{…},"encryption":{…},"publish":{…},"revote":"linked",
 "opens":1761900000,"closes":1777000000,"blackouts":[{"from":…,"to":…}],
 "circuit":{"name":"choice4_single_linked_d20","vk_hash":"0x…"}}
```

`circuit.name` is a variant name (circuits/gen.py): the kind's family and
slot count, the decryption mode (`single`, `tlock`; `threshold` later),
the re-vote chain, the registry depth (`d20`) and, for delta polls, the
ballot tree depth (`_b22`), which the poll also gives as `ballot_depth`. Optional fields at their default
(`blackouts: []`, `require_expiry: false`, `nationality: []`) are left
out: a body has one spelling (§3).

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
`v + 2`, and digits go P per **chunk**: `chunk = Σ d_k·2^(32k)`. P
follows from how the poll is decrypted, never from a setting: a single
authority may open each ballot (its digits are in [0, 4]: one table
lookup), sums the digits and proves the aggregate decrypts to the sums,
so P = 7, the most 32-bit digits below r, and a phone proves three to
four times fewer ciphertexts; a decryption by aggregate only (a
threshold committee, a later version) recovers the digit sums by a
bounded discrete logarithm, so P = 2. The circuit is named after the
mode (`single`, `threshold`, `tlock`), and the ingest refuses a poll
whose circuit is for another mode.
Plaintexts are thus non-negative integers far below both r and q: a
"negative" element of F would not be negative in Grumpkin's group, whose
order is q, and sums of ciphertexts would stop being sums of values. A
sum over N ballots has digits `Σv + 2N`, in `[0, 4N]`, below 2^32 for
N < 2^30 (so `depth ≤ 30`). Decrypting a chunk sum is a discrete
logarithm with both digits in `[2N − B, 2N + B]`, B the bound the kind
gives for a value sum (N for counts): a baby-step table over one digit,
reused for each candidate of the other.

### 7.2 Encryption

- **`elgamal`**: `{"mode":"elgamal","pk":"<point>","authority":
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
  a ballot counts if it has the highest `seq` of its nullifier, and
  `seq` may not exceed the last one by more than 16 (`seq_gap`: a huge
  seq would make a ballot final, a receipt a coercer could demand). The
  log shows when and how often a pseudonym changed its mind. With the
  ledger's `revote_gap` g > 0, a ballot of a pseudonym that already has
  one is refused as `too_soon` while its newest ballot is pending or was
  logged by a checkpoint less than g seconds before (a refused ballot
  does not count). It is a rate, not a total: whoever votes in the
  voter's place, a coercer included, cannot use up the voter's re-votes,
  and the voter's last ballot before the close counts. The device keeps
  its last `seq`; one that lost it (a new device) learns it from
  `stale_seq` refusals, raising `seq` until one is accepted (within the
  gap of 16).
- **`delta`**: every ballot has a fresh identifier
  `ident_i = H(T_bnull, poll, s, i)` (i = 0, 1, … private), carries the
  **correction** `new − old` (old = 0 for i = 0), and appends to the
  poll's **ballot tree** the leaf `H(T_bleaf, ident_i, cmt_i)` with
  `cmt_i = H(T_cmt, salt_i, new…)`, `salt_i = H(T_salt, poll, s, i)`. For
  i > 0 the proof shows that the leaf of ballot i − 1 is in the ballot
  tree (a root from a checkpoint) and opens to `old`. The tally is the
  sum of every ballot. Nothing links a correction to the ballot it
  corrects. `ident` must be unused (`duplicate`), so each voter has one
  chain; the tree's capacity (`full`) is shared by every ballot, and a
  voter may post corrections that change nothing, so a delta poll's tree
  should be deep (`b22` holds four million ballots).

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
by the auditor. With a single authority, "closed" means the public cannot
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

The browser proves with bb.js on Aztec's SRS (the BN254 points of its
ceremony: 2^17 G1 points, compressed, and the G2 point; the ballot
circuits need at most 2^16). Where the prover reads the SRS and bb.js's
wasm is the app's choice (js/README.md, "Pinned files"): each file it
pins is fetched whole and used only if its SHA-256 is the pinned one, so
a CDN that serves another file stops the proof instead of changing the
prover.

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
`broot` (and a browser drafts only against a checkpoint younger than 30
minutes by its own clock: a mirror serving one voter an old root would
single that voter's ballot out); points decode and are not at infinity (`malformed`); the
re-vote rule (`revote_off`, `stale_seq` when `seq` is not above the
pseudonym's last, `seq_gap`, `too_soon`, `duplicate`); `blob` ≤ 4 KiB (tlock); the proof against
the circuit of the setup with the public inputs rebuilt from the body,
the setup and the poll (`bad_proof`).

The committee key is reusable across polls because an authority only ever
decrypts aggregates it recomputed from one poll's logged ballots, never
a ciphertext it is handed, and because its proofs carry the poll and the
log position in their challenge.

## 10. Results

### 10.1 When

Deterministic over the log, so any authority and any auditor agree:

- `open`: at a checkpoint at time t, with `changed` the number of
  pseudonyms whose counted ballot changed since the last tally (delta:
  the number of ballots since), a tally is due when `changed ≥ k_real`,
  `t − last ≥ min_gap`, t is outside every blackout, and, with `coin`,
  the low bit of `SHA-256("isoloir/1/coin" ‖ checkpoint root)` is 1.
  The tally covers the log up to that checkpoint (`upto`, its last seq).
- `closed`: one tally, covering up to the `close` entry.

What an open poll reveals: the difference between two tallies is the
sum of the ballots counted in between. With `k_real` small, or at low
traffic, that is one ballot, in clear, and the log says which entry it
is. The ingest decides what each checkpoint holds, so it can make that
happen; the coin, drawn from the log root, does not stop an ingest that
chooses what to log. `k_real` and `min_gap` may only rise in a later
setup (§13). An open poll is a choice to publish ballots as they come,
with at most this much batching; a poll that must hide every ballot is
closed.
- At the close of an open poll, a final tally covering up to `close`,
  even during a blackout.

### 10.2 The counted ballots

Up to `upto`: none/linked, the ballot of each nullifier with the highest
seq; delta, every ballot. The **aggregate** of chunk j is the
component-wise sum of the counted ciphertexts' chunk j.

### 10.3 The `tally` entry (elgamal)

```json
{"v":1,"poll":7,"upto":4810,"checkpoint":233,"final":false,
 "values":[…counts…],"counted":2051,
 "aggregate":[["<A0>","<A1>"],…],
 "shares":[{"authority":1,"d":["<point>",…],"proofs":[["<c>","<z>"],…]}],
 "sig":"<Ed25519, hex>"}
```

`aggregate` repeats the aggregates so that a browser can check the
shares, the values and the signature from the tally alone; the ingest and
the auditor check that they are the log's.

For each chunk j with aggregate `(A0_j, A1_j)`: each share gives
`d_ij = sk_i·A0_j` and a Chaum–Pedersen proof that
`log_G(PK_i) = log_{A0_j}(d_ij)`, with challenge
`SHA-256("isoloir/1/dleq" ‖ poll ‖ upto ‖ j ‖ G ‖ PK_i ‖ A0_j ‖ d_ij ‖ a ‖ b) mod q`
(points in their 32-byte encodings, integers as 8-byte big-endian). The
decryption is `D_j = Σ λ_i·d_ij` (Lagrange at 0 over the authorities
present; one authority: `D_j = d_1j`), and the values must satisfy
`A1_j − D_j = pack(values)_j·G`. `sig` signs `SHA-256("isoloir/1/tally\n"
‖ canonical body without sig)` under the authority's `sign_key`.

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
`{"v":1,"poll":7,"at":<closes>,"last":<seq of the last ballot>}` at the
end of that checkpoint (`last` counts the ballots logged in it).
Ballots after are `closed`. Relays may still deliver ballots posted
before `closes` (§11): they are logged before `close` if they arrive
before it, else refused, and the complaint process (§11.3) covers a
ballot acknowledged and never logged.

## 11. Transport

### 11.1 Channels

Every message is a signed **envelope** in the format of a Nostr event
(NIP-01: id, pubkey, created_at, kind, tags, content, sig; BIP340 on
secp256k1), tag `["t","isoloir/1/<origin>"]`, content the body. The
envelope and its acknowledgement are the same whatever carries them; a
channel type only says how they travel. Channels are transport only:
the protocol and the audit never rely on a channel keeping a copy.

- **`nostr`**: public relays (`wss://`). The voter publishes the envelope;
  the ingest, subscribed to the relays, publishes the ack on the relay
  the envelope came from. Every kind is ephemeral (20000–29999, NIP-16):
  relays forward the events to the live subscriptions and keep none. The
  operator never sees a voter's address.
- **`iroh`** (not built yet; the form is fixed so that a ledger may list
  it): `{"type":"iroh","url":"iroh://<node id>","relay":"https://<relay>","state":"active"}`,
  the ingest's iroh node, reached only through the iroh relay (DERP)
  named, never directly, so that the ingest never sees the voter's
  address. One envelope per message, the ack back on the same
  connection.
- **`direct`**: the ingest's HTTP endpoint (`https://`).
  `POST <url>/v1/messages` with the envelope as JSON answers 200 with the
  ack, or 202 `{"pending":"<id>"}` when judgment waits (§11.2);
  `GET <url>/v1/acks/<id>` answers the ack, or 404. The operator sees
  each voter's address and timing.
- A channel type is a way to carry an envelope to the ingest and its ack
  back: a later type adds a variant here and in the ledger's `channels`;
  the envelope, the ack, the log and the mirror do not change.

Kinds:

| Kind | Content | Signed by |
|---|---|---|
| 27100 | register | a throwaway key |
| 27101 | ballot | a throwaway key |
| 27102 | ack | the ingest |
| 27103 | checkpoint note | the ingest |
| 27104 | device link | a throwaway key |
| 27105 | tally | a throwaway key (the body carries its own signature) |
| 27106 | complaint | a throwaway key |

Clients written before this version post 7100–7106 (kinds relays
store); the ingest still reads them and answers in the same range.

**Order.** A voter tries the active channels by type, `nostr` first,
then `iroh`, then `direct` last (it shows the voter's address to the
operator), and within a type by `H(T_relay, s, SHA-256(url) mod r)`,
lowest first: registrations go to the first relay, ballots start with
the second when there is more than one (so the two are not seen
together by one relay). The voter moves to the next channel when no ack
comes within 60 s, in a fresh envelope. The device link (§14) needs a
relay.

**Proof of work.** With the ledger's `pow` d > 0, every envelope carries
a tag `["pow","<t>","<nonce>"]`: `t` a time (Unix seconds, decimal),
`nonce` up to 32 ASCII characters, such that

```
SHA-256("isoloir/1/pow\n" ‖ origin ‖ "\n" ‖ pubkey ‖ "\n" ‖ t ‖ "\n" ‖ nonce)
```

(pubkey the envelope's, lower-case hex) starts with d zero bits, and
`now − 7200 ≤ t ≤ now + 300` at the ingest. The work is bound to the
throwaway key and a time, not to the envelope id: the id covers the
body, which exists only once the proof is made, and in NIP-01's
serialization the tags precede the content, so mining the id would
hash the whole ballot (about 22 KB) at every try and nothing could be
done in advance. Bound to the key, the device draws the key and does
the work in the background while it proves the ballot (d = 16: about
65,000 hashes of 150 bytes, well under a second on a phone), then signs
the envelope with it. One key carries one body: the ingest takes resends
of the same body under the key, and drops another body under it.
Checked first, with the tag and the signature: an envelope that fails
them is dropped unanswered (answering junk would cost the ingest a
signature and a post per junk message).

### 11.2 Acknowledgements

The ingest answers every message it has judged with an ack by the
channel it came from, tag `["e", <event id>]`:

```json
{"v":1,"of":"<event id>","hash":"<SHA-256 of the body>",
 "outcome":"accepted","checkpoint":234}
```

or `"outcome":"rejected","reason":"…"`. The ack's `created_at` is
rounded down to the minute (an ack is public: to the second, it would
date the entry it names). A message resent after a missed ack goes in a
fresh envelope; the ingest answers the same body with the same outcome
whatever its envelope. An accepted message is first
written to durable storage (pending), then acknowledged, then logged at
the named checkpoint in the same transaction as the checkpoint itself.
A message whose check failed for an infrastructure reason is neither
acknowledged nor refused; it is retried.

**Order of judgment.** The ingest judges in two steps. The cheap checks
come first, in arrival order: the envelope (tag, signature, proof of
work), then the body up to its proof (canonical form, version, setup,
signature, dates, roots, the identifiers it claims not used, the
re-vote rule); a message that fails them is refused at once. The
messages that pass wait for the proof check (the ballot proof, the
passport verifier) in a queue ordered by how long ago the identifier
they claim (the registration's `uid`, the ballot's `nullifier` or
`ident`) was last claimed by a message, never claimed first: a flood
replaying one identifier waits behind every fresh voter. Tallies come
first.

### 11.3 Receipts and complaints

The ack is the voter's receipt, signed by the ingest's Nostr key, which
nobody else holds:

- an `accepted` ack whose body is missing from the entries of the
  checkpoint it names proves the ingest dropped an accepted message;
- a `rejected` ack together with the body (whose hash the ack names)
  lets anyone judge the refusal again against the log at that time: a
  valid message refused proves a wrong refusal.

The browser keeps the ack and checks the entries of the named
checkpoint on the mirror for its body hash. Either case is a
**complaint**: `{"v":1,"ack":<the ack event>,"body":<the body, as
JSON>}` (the body is canonical, so embedding it as JSON is lossless),
kept by the voter and posted by the ledger's channels (kind 27106) to
whoever listens; anyone can judge it from the log and the ack's
signature.

The kind is ephemeral: a relay keeps no complaint, so the voter keeps
the signed event (its id, the throwaway key, the body above) and hands
it on whole, as a file or as the base64url (no padding) of its JSON,
for example in a link fragment `#c=<base64url>`. Judging it:

- **form**: the event's id and signature, the complaint body (`v`,
  `ack`, `body`, nothing else), the ack an ack event (27102, or 7102)
  signed by a key the ledger's setups named as `ingest`, its `e` tag its
  `of`, its `hash` the SHA-256 of the canonical body;
- **dropped** (an `accepted` ack naming checkpoint N): it holds when the
  entries of N lack the body (logged late when a later checkpoint holds
  it), fails when they hold it, and waits while the mirror does not
  cover N;
- **wrong refusal** (a `rejected` ack): the body is judged again (§9.3,
  §6) against the log of the checkpoints up to the ack's `created_at`,
  at the first and the last second of that minute, without and with the
  entries of the next checkpoint as messages pending then. It holds when
  every judgment accepts the body, fails when every one refuses it, and
  is undecided when they differ.

A message that is never answered proves nothing afterwards: no third
party keeps a copy. The device retries on the next channel, `direct`
last.

### 11.4 Refusals are not logged

The log holds accepted entries only. A refused message gets its signed
`rejected` ack (§11.2) and nothing else. A body over 256 KiB is refused
as `malformed`. The ingest keeps refused bodies (up to 256 KiB) in its
database for 30 days, for debugging, then deletes them; they are not
published.

Logs written before this version also hold, per refused message, a
`reject` entry `{"v":1,"of":"<event id>","hash":"…","reason":"…",
"kind":"ballot","raw":"<the body, base64>"}` (or, for a few weeks, with
`author` and `size` in place of `raw`), and possibly `rejects` entries
`{"v":1,"count":…,"size":…,"root":"0x…"}`. Readers accept them as
entries of the log; nothing is judged from them.

## 12. Reasons

`malformed`, `version`, `unknown`, `not_open`, `closed`, `bad_sig`,
`stale_date`, `uid_used`, `id_used`, `full`, `bad_proof`, `old_root`,
`revote_off`, `stale_seq`, `seq_gap`, `too_soon`, `duplicate`,
`not_due`, `bad_tally`.

## 13. Upgrades

- **Bodies**: `"v"`; readers dispatch on (kind, v) and refuse unknown
  versions. A new body version is added alongside the old one.
- **Setups** (`ledger`, `registry`, `poll`): a later entry with the same
  id and `version + 1` supersedes the previous. What may change:
  - `ledger`: `channels` (append, retire; a channel keeps its type),
    `ingest` (a new Nostr key), `checkpoint_period`,
    `anchor_age`, `revote_gap`, `pow`; never `origin`, `log_key`.
  - `registry`: `name`, `validity`; never `id`, `eligibility`, `depth`.
  - `poll`: `title`, `closes` (later only, before the close), `blackouts`
    (future ones only), `publish.k_real` and `publish.min_gap` (open
    polls; they may only rise), `circuit` (another build of the same
    variant);
    never `registry`, `kind`, `encryption`, `revote`, `publish.mode`,
    `opens`.
  A ballot names the setup it proves against (`setup`); the previous
  setup is accepted for 24 h after its successor is logged.
- **Protocol**: the leaf prefix and the relay tag carry `isoloir/1`. A ledger never changes protocol version;
  `isoloir/2` would be a new ledger.
- **Storage**: numbered migrations; the server refuses to start on a
  schema newer than it knows.
- **Circuits**: a circuit is named and its verification key hashed in
  the poll; a new circuit is a new name, so a setup change says exactly
  which one ballots prove against.

## 14. The voter secret

Where the platform offers the WebAuthn
PRF extension, `s = H(T_prf, prf_lo, prf_hi)` from a passkey's PRF output
on input `isoloir/1/<origin>/<registry>`; otherwise `s` comes from 12
words (BIP39, 128 bits) or is carried by a device link (ECDH secp256k1 +
XChaCha20-Poly1305 over a relay, confirmed by a six-digit code). No
ballot is cast before a backup is confirmed, unless the voter declined
one in so many words (the choice is recorded with the key; the app
carries the warning).

## 15. The mirror

Static files in a git repository whose history only grows (commits are
appended, never rewritten), so that a file is addressed for ever by a
commit:

```
checkpoint.txt                       the latest note
checkpoints/<index>.txt              every note
entries/<index>.json                 [{seq, kind, body}] of a checkpoint
stamps/<index>.ots                   the OpenTimestamps proof
setup/ledger.json, registries/<id>.json, polls/<id>.json
                                     {"setups":[<proven entry>…]}, every version
polls/<id>/close.json                <proven entry>
circuits/<name>/{artifact.json,vk}
registries/<id>/leaves/<k>.json      leaves 1024·k … 1024·k+1023
polls/<id>/ballots/<k>.json          ballot tree leaves (delta)
polls/<id>/tallies/latest.json, polls/<id>/tallies/<seq>.json
                                     <proven entry>
```

The mirror grows with the entries; the other files are few, or
rewritten in place (the newest leaves block, the setups, the latest
tally, the stamps as they are upgraded). Mirrors of earlier versions
also hold `registries/<id>/positions/` and `polls/<id>/pseudonyms/`,
no longer written: a device finds its tree position in the entries of
the checkpoint its registration's ack names (the registry's tree size
in the previous note, plus the rank of its registration among that
checkpoint's registrations of the registry, in log order), and keeps its
last `seq` (§7.4).

**Addressing.** Files are read by commit (a CDN serves
`<repo>@<commit>/<path>` for ever, while a branch is cached for hours).
Each checkpoint writes its files and commits them locally; a background
task pushes, and retries every 30 s what the remote lacks. A checkpoint
never waits for the push: the git host down or full never stops the
log. A note's `mirror <commit>:<index>` (§4) names the newest commit the
ingest knows the remote holds and the newest checkpoint that commit
covers. A reader takes the latest note from any source (its signature
and its time are what it trusts), reads `checkpoints/<index>.txt` and
the files of checkpoints up to `index` at that commit, and waits for a
later note to read files of a later checkpoint (a receipt check for a
checkpoint above `index`). Every file is checked against signed notes
(entries against the log root, setups and tallies by their proofs,
leaves against the registry root of the note of the same tree size), so
the commit only makes the files addressable, it vouches for nothing.

The ingest clones the mirror's repository at start when its disk is
empty, as a partial clone (`--filter=blob:none`: every commit and tree,
the newest version of each file, older versions fetched when a merge
needs them), not a shallow one: a push the remote refuses because it
moved (a commit from elsewhere, a README) is merged, never rebased, so
every pushed commit stays in the history. Commits not yet pushed when
the ingest restarts on an empty disk are written again from the log,
under other hashes; no note names them, since a note names only pushed
commits.

A **proven entry** is `{"seq","kind","body","checkpoint","size","path"}`:
the entry's log position, its body as a string, the checkpoint whose
note a reader verifies it against, that checkpoint's log size, and the
RFC 6962 inclusion proof (hex hashes) of leaf `seq` in the first `size`
leaves. A reader accepts a setup or a tally only with its proof: the
mirror cannot serve an ingest key, a channel, an authority key or a result
the log does not hold.

## 16. The audit

A check that cannot run (a missing verification key, a passport
verifier that is not configured) is a problem, not a pass: an audit that
could not verify something says so and fails.

From the log alone: every checkpoint signature and the log's consistency
between checkpoints; the stamps against Bitcoin block headers; every
setup against its predecessor (§13) and the matrix (§8); every
registration (signature, freshness, provider proof, uniqueness, tree
positions and roots); every ballot (roots in age, re-vote rule, proof);
every tally (due by §10.1, aggregate,
shares, combination, values, signature; tlock: beacon, openings, void
list); every close. `reject` and `rejects` entries of earlier logs are
read as entries (they count in the log's hashes) and counted, not judged.
With the mirror: its files are the log's. A message the ingest never
answered is out of the audit's reach (§11.3); a dropped or wrongly
refused message is proven by its voter's receipt.

## 17. What each party learns

| | Passport ↔ leaf | Leaf ↔ ballot | Ballot content | Re-vote history |
|---|---|---|---|---|
| Public | yes to the issuing state with a non-salted uid; salted: only with 2 of 3 OPRF operators (§5) | no | closed elgamal: aggregates only; open: tally differences, down to one ballot at low traffic or `k_real` 1 (§10.1); tlock: every ballot at the round | linked: per pseudonym, with the minute of each post; delta: the count of corrections per tally window |
| Ingest | yes | no, but it chooses what each checkpoint holds (§10.1) | as public | as public |
| Authority (elgamal) | yes | no | could decrypt any ballot of any poll under its key | as public |
| Relay (nostr, iroh) | yes | address and time of the post (an iroh relay: the address only); under tlock, the content at the round | as public | as public |
| Mirror host | no | the address that asks for a checkpoint's entries or a shard (browsers fetch windows, not one checkpoint) | as public | as public |
| Network observer | no | address ↔ relay ↔ time; defeated only by Tor or a VPN, which the app may recommend | as public | as public |
| Passkey provider | learns a passkey for the site exists; a compelled account yields `s` | | | |
| Whoever holds `s` or the words | | every ballot of the voter | delta: every choice (the chain is recoverable); tlock: the ballot | all |

The device keeps `s`, the words until they are confirmed, and the last
choice; a seized or compromised device reveals them.

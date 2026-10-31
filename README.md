# isoloir

Anonymous polls with passport eligibility: prove once, with a passport,
that you may vote; vote anonymously and encrypted; let anyone recount
from a public log. No blockchain, no network of the operator's: messages
travel through public Nostr relays, results are files on a static mirror,
checkpoints are timestamped in Bitcoin.

An isoloir is the voting booth: the curtain you vote behind, unseen.

- The protocol: [SPEC.md](SPEC.md) (normative).
- Running a ledger: [OPERATING.md](OPERATING.md).
- The plan and its status: [PLAN.md](PLAN.md).

## What a deployment can be

A **ledger** holds **registries** (who may vote: a passport rule such as
"French adults") and **polls**. One registration serves every poll of its
registry. A poll chooses:

| | Options |
|---|---|
| Ballot | single choice (yes/no, one of n) or a ranking of up to 3 (with or without pairwise margins), a blank slot or not |
| Encryption | ElGamal under a decrypter's key (one key may serve many polls), or drand time-lock |
| Results | open (published while the poll runs, every `k_real` changed ballots) or closed (one result after the close) |
| Re-votes | none, linked (one pseudonym per voter), delta (unlinkable corrections) |

Not every combination is safe; SPEC §8 has the table and the library
refuses the others.

## Crates

| Crate | What |
|---|---|
| `isoloir-core` | Poseidon2 (Barretenberg's), trees, Grumpkin ElGamal, Chaum–Pedersen, packing, canonical JSON |
| `isoloir-proto` | bodies and versions, kinds, the matrix, the log and signed checkpoints, the state machine, the judge, the policy, tallies, the audit, the voter's ballot drafting |
| `isoloir-zk` | the circuits through nargo and bb: build, prove, verify |
| `isoloir-decrypt` | drand time-lock (seal, open, beacon checks), the decrypter's keys |
| `isoloir-relay` | a Nostr relay pool, and a local relay for trials |
| `isoloir-stamps` | OpenTimestamps: submit, upgrade, verify against Bitcoin |
| `isoloir-server` | Postgres storage, the ingest, the trustee, the mirror, the passport verifier |
| `isoloir` | the command |
| `isoloir-wasm`, `js/` | the browser: the same Rust through WebAssembly, and a framework-free session |

`circuits/` holds the Noir library and `gen.py`, which writes one circuit
per variant (`choice4_elgamal_linked_d20`, `ranked12_elgamal_delta_d20_b22`…).

## A local trial in ten commands

Needs Rust, Postgres, `nargo` (1.0.0-beta.22) and `bb` (5.0.0, from
`@aztec/bb.js`; set `ISOLOIR_BB` to its path).

```sh
cargo build --release -p isoloir && alias isoloir=target/release/isoloir
isoloir relay &                                   # ws://127.0.0.1:7777, in memory
isoloir keygen log --origin trial.local/isoloir   # ISOLOIR_LOG_SEED, log_key
isoloir keygen nostr                              # ISOLOIR_NOSTR_KEY, ingest
isoloir keygen decrypter --out dec.json           # pk, sign_key
isoloir circuits choice4_elgamal_linked_d20 --mirror mirror   # prints the vk hash
export DATABASE_URL=postgresql://localhost/isoloir_trial ISOLOIR_LOG_SEED=… ISOLOIR_NOSTR_KEY=…
isoloir genesis ledger.json && isoloir ingest --mirror-dir mirror --dev --no-stamps &
isoloir submit registry registry.json && isoloir submit poll poll.json
S=$(isoloir voter secret); isoloir voter register --mirror mirror --registry 1 --secret $S --uid alice
isoloir voter vote --mirror mirror --poll 5 --secret $S --choice 0
isoloir trustee --mirror mirror --log-key "…" --keys dec.json --db $DATABASE_URL --once
isoloir audit --mirror mirror --log-key "…" --relays
```

The setup files are JSON bodies as SPEC §4.1, §5 and §7 show
(`provider: "dev"` for a trial registry). `crates/server/tests/ingest.rs`
and `crates/zk/tests/e2e.rs` do the same in code.

## Tests

```sh
cargo test --workspace                 # needs nargo and bb (ISOLOIR_BB), and Postgres
                                       # for the server (ISOLOIR_TEST_DATABASE, a server URL)
cd circuits/lib && nargo test
```

## Licence

MIT or Apache-2.0, at your option.

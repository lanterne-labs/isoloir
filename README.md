# isoloir

**Anonymous polls with passport eligibility, recountable by anyone.**

Prove once, with a passport, that you may vote. Vote anonymously and
encrypted. Let anyone recount from a public log. No blockchain needed:
messages travel by the channels the ledger declares (public Nostr relays,
the ingest's own HTTP endpoint, or both), results are files on a static
mirror, checkpoints are timestamped in Bitcoin.

An isoloir is the voting booth: the curtain you vote behind, unseen.

## Documentation

| Read | For |
|---|---|
| [SPEC.md](SPEC.md) | the protocol (normative): bodies, checks, the log, the mirror, the audit |
| [DESIGN.md](DESIGN.md) | what protects what, the limits, the extensions |
| [OPERATING.md](OPERATING.md) | running a ledger: keys, the ingest, the authority, the mirror |
| [docs/how-it-works.md](docs/how-it-works.md) | how a vote works, step by step, for a technical reader |
| [js/README.md](js/README.md) | the browser library `@isoloir/web`: sessions, proving, the in-browser audit |
| [PLAN.md](PLAN.md) | the plan and its status |

## What a deployment can be

A **ledger** holds **registries** (who may vote: a passport rule such as
"French adults") and **polls**. One registration serves every poll of its
registry. A poll chooses:

| | Options |
|---|---|
| Ballot | single choice (yes/no, one of n) or a ranking of up to 3 (with or without pairwise margins), a blank slot or not |
| Encryption | ElGamal under an authority's key (one key may serve many polls), or drand time-lock |
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
| `isoloir-decrypt` | drand time-lock (seal, open, beacon checks), the authority's keys |
| `isoloir-relay` | a Nostr relay pool, and a local relay for trials |
| `isoloir-stamps` | OpenTimestamps: submit, upgrade, verify against Bitcoin |
| `isoloir-server` | Postgres storage, the ingest, the authority, the mirror, the passport verifier |
| `isoloir` | the command |
| `isoloir-wasm`, `js/` | the browser: the same Rust through WebAssembly, and a framework-free session |

`circuits/` holds the Noir library and `gen.py`, which writes one circuit
per variant (`choice4_single_linked_d20`, `ranked12_single_delta_d20_b22`…).

## A local trial in ten commands

Needs Rust, Postgres, `nargo` (1.0.0-beta.22) and `bb` (5.0.0, from
`@aztec/bb.js`; set `ISOLOIR_BB` to its path).

```sh
cargo build --release -p isoloir && alias isoloir=target/release/isoloir
isoloir relay &                                   # ws://127.0.0.1:7777, in memory
isoloir keygen log --origin trial.local/isoloir   # ISOLOIR_LOG_SEED, log_key
isoloir keygen nostr                              # ISOLOIR_NOSTR_KEY, ingest
isoloir keygen authority --out dec.json           # pk, sign_key
isoloir circuits choice4_single_linked_d20 --mirror mirror   # prints the vk hash
export DATABASE_URL=postgresql://localhost/isoloir_trial ISOLOIR_LOG_SEED=… ISOLOIR_NOSTR_KEY=…
isoloir check registry registry.json && isoloir check poll poll.json --registry registry.json
isoloir genesis ledger.json && isoloir ingest --mirror-dir mirror --dev --no-stamps &
isoloir submit registry registry.json && isoloir submit poll poll.json
S=$(isoloir voter secret); isoloir voter register --mirror mirror --registry 1 --secret $S --uid alice
isoloir voter vote --mirror mirror --poll 5 --secret $S --choice 0
isoloir authority --mirror mirror --log-key "…" --keys dec.json --db $DATABASE_URL --once --dev
isoloir audit --mirror mirror --log-key "…" --relays --skip-passports --dev
```

Run it from the repository root (`circuits/` is where variants are
built from); create the database first.

How a vote works, step by step, for a technical reader:
[docs/how-it-works.md](docs/how-it-works.md).

Anyone can also audit from a web page: `audit()` of `@isoloir/web` runs
the same replay in the browser, with `bbVerifier` for the ballot proofs
and `zkPassportVerifier` for the passports (DESIGN §1.7).

The setup files are JSON bodies as SPEC §4.1, §5 and §7 show
(`provider: "dev"` for a trial registry: the ingest, the authority and
the audit accept it only with `--dev`, which they refuse on the host). `crates/server/tests/ingest.rs`
and `crates/zk/tests/e2e.rs` do the same in code.

## Tests

```sh
cargo test --workspace                 # needs nargo and bb (ISOLOIR_BB), and Postgres
                                       # for the server (ISOLOIR_TEST_DATABASE, a server URL)
cd circuits/lib && nargo test
```

## Licence

MIT or Apache-2.0, at your option.

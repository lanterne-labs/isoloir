# How an isoloir vote works (technical version)

This document explains, for a technically curious reader, what happens
at each step of an isoloir vote: registering with a passport, the
ballot, the count and the verification. The reference remains the
specification ([SPEC.md](../SPEC.md)); the mechanisms, the limits and
the planned extensions are in [DESIGN.md](../DESIGN.md).

The roles:

| Role | What it holds | What it does |
|---|---|---|
| Your browser | your secret `s` | registers, votes, verifies |
| The ZKPassport app | the chip reading | computes the eligibility proof, on the phone |
| The relays | nothing | carry the messages (public Nostr relays, run by others) |
| The registration server ("ingest") | the log key | verifies, registers, acknowledges, signs the checkpoints |
| The authority | the election key | decrypts the sums, never a published ballot on its own |
| The mirror | nothing | serves the log as static files |
| Anyone | nothing | recounts everything from the log |

## 1. Registering: one passport, one key

- Your browser creates your secret `s`, from a passkey (Face ID,
  fingerprint: the passkey's PRF output) or from 12 words. `s` never
  leaves your devices; only its public fingerprint, a leaf of the voter
  tree, is published.
- The ZKPassport app reads the passport's chip (NFC) and computes, on
  the phone, a zero-knowledge proof: the passport is genuine (signed by
  the issuing state), its holder is an adult of the required
  nationality, the document is valid. The proof is bound to the
  registration and reveals no name, photo or number: only an identifier
  specific to the passport and the site (`uid`), salted by a secret
  shared between three independent operators (ZKPassport's threshold
  OPRF, two of three).
- The registration goes out on a public relay. The server reads it,
  verifies the proof with the open verifier of the ZKPassport SDK (the
  roots of the certificate registry are read on Ethereum), refuses a
  `uid` already registered, then enters it in the public log, proof
  included.
- Anyone can therefore check that every voter comes from a real
  passport, and that no passport has two registrations. The `uid` is
  public, but salted: the state that signed the chip cannot recompute it
  alone to learn that a passport registered; it would need two of the
  three OPRF operators. And it never learns how anyone votes.

## 2. Voting: an encrypted ballot, without a name

- Your browser encrypts the ballot (exponential ElGamal on the Grumpkin
  curve) with the election's public key, then computes a proof (Noir,
  UltraHonk; Aztec's universal setup, no ceremony of our own): the
  ballot comes from a leaf of the voter tree, without saying which one;
  it follows the rules of the poll; it is correctly encrypted.
- The ballot carries a pseudonym `H(poll, s)`, the same for all your
  ballots in this poll and unlinked to your registration: a new ballot
  replaces the old one, only the last one counts.
- It is signed by a throwaway key and goes out on a public relay, chosen
  by a hash of `s`. It never goes through the organizer's server: the
  server reads it on the relays, among the others, and so never sees
  your IP address. The relay sees it, as any site you visit does, along
  with an encrypted ballot it cannot read.
- The server acknowledges with a signed message that names the upcoming
  checkpoint. Your browser then finds the ballot in the log, intact; if
  it is missing, the signed acknowledgement becomes a complaint that
  anyone can judge.

## 3. Counting without reading

- Encrypted ballots add up without being opened. The authority decrypts
  the sum of the last ballots of each pseudonym and attaches
  Chaum-Pedersen proofs: anyone can check the decryption without the
  key.
- For an open poll, a result is published after `k_real` changed
  ballots and `min_gap` seconds, outside the blackout periods. With
  `k_real` = 1, each update reveals the difference from the previous
  one, that is one ballot, unlinked to its author. These settings can
  only go up.
- A blank vote is a ballot in its own right: it counts among the
  voters. Withdrawing a vote is a ballot like any other: in the log,
  nothing tells it apart.

## 4. Verifying, without trust

- Everything goes into a public log: a Merkle tree (RFC 6962). The
  server signs its state at regular intervals (Ed25519 "signed notes",
  C2SP format), and each checkpoint is timestamped in Bitcoin through
  OpenTimestamps: no other log can later pass for the one of that date.
- Refusals are logged too, with the refused message: an auditor judges
  every message the server judged. The relays keep copies: a message
  received and never judged would show.
- The audit replays everything: every signature, every passport proof,
  every ballot proof, every refusal, every sum and every decryption. It
  runs on the command line (`isoloir audit`) or in a browser (`audit()`
  of `@isoloir/web`), with the same code. A check that could not be
  made is an anomaly, never a success.

## 5. What the organizer receives, what stays with you

Received: "adult, nationality, valid document: yes", the passport's
`uid` for this site, the public fingerprint of your key, encrypted
ballots read on the relays, and the decrypted sums.

Stays with you: your name, your photo, your date of birth, the passport
number; your secret and your 12 words; which ballot is yours; your IP
address, which goes only to the relays and the mirror.

## 6. The limits

- A single authority holds the election key: it could decrypt a single
  ballot, without knowing whose it is. Threshold decryption is planned,
  not yet built.
- A voter can prove their vote to a third party by revealing their
  secret: vote buying is not prevented.
- A log in two versions (a "fork") is detected, not prevented; see
  DESIGN §2 and §3.
- It takes an NFC smartphone and a chip passport. Someone with a full
  copy of the chip could register the passport before its holder.
- ZKPassport is open source and audited internally, not yet by a third
  party.

## Further reading

- [SPEC.md](../SPEC.md): the full protocol.
- [DESIGN.md](../DESIGN.md): mechanisms, limits, extensions.
- [OPERATING.md](../OPERATING.md): running a ledger, auditing it.
- ZKPassport: <https://github.com/zkpassport> · Noir:
  <https://noir-lang.org> · OpenTimestamps: <https://opentimestamps.org>

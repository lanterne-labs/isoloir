# @isoloir/web

The browser side of isoloir (`../SPEC.md`), with no framework: keys, passport registration, ballots, receipts, complaints and results. It posts signed envelopes through the channels the ledger lists: Nostr relays first, then iroh (when an app provides it), then the ingest's direct HTTP endpoint last, which shows the voter's address to the operator. Everything else it reads as static files from the mirror. Channels are transport only: the library never reads a relay's past events to recover anything.

Every protocol rule comes from the Rust crates compiled to WebAssembly (`../crates/wasm`): leaves, pseudonyms, ballot drafts, tlock sealing, checkpoint notes, log inclusion proofs, tally proofs and the 12 words. This package only orchestrates.

## Build

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-pack          # once
npm install
npm run wasm                     # wasm/web (browsers) and wasm/node (tests, with the dev helpers)
npm run check                    # tsc, strict
npm test                         # vitest: fake relays, a fake direct endpoint, a fake mirror, a fake ingest
# one real ballot, proven by bb.js's wasm with the SRS given by URL (opt-in):
ISOLOIR_CIRCUITS=../circuits/build ISOLOIR_SRS_DIR=<g1_compressed.dat, g2.dat, grumpkin_g1_v2.dat> npx vitest run test/prove.e2e.test.ts
npm run build                    # dist/
```

## The session, step by step

```ts
import { Session, loadWasm } from '@isoloir/web';

const session = new Session({
	core: await loadWasm(),               // or loadWasm(wasmUrl) when the .wasm is served elsewhere
	origin: 'vote.example/isoloir',
	verifierKey: 'vote.example/isoloir+1a2b3c4d+AQ…', // pinned: shipped with the app, never read from the mirror
	registry: 1,
	poll: 7,
	mirror: 'https://mirror.example/isoloir',      // or [jsDelivrSource('owner/repo'), dirSource(...)]
	prover,                                        // see "The prover"
	wordsLang: 'fr'
});
session.subscribe((state) => render(state));
session.on('link-offer', ({ code }) => askTheVoterToCompare(code));
await session.init();
```

`init()` reads `setup/ledger.json`, `registries/<id>.json` and `polls/<id>.json`. It uses none of them until it has checked each one's inclusion proof against the note of the checkpoint the file names, and that note was verified under the pinned key. It also checks that the ledger names the pinned log key. The session's channels come from that ledger. The app never chooses a transport.

1. **Scan.** The registration key is drawn before any voter key exists. Start the envelope's proof of work as the passport step begins (see "Envelopes" below), so it is ready when the registration goes:

   ```ts
   void session.startWork().catch(() => {});                                // the ledger's pow, mined in the background
   await session.scanPassport(async (req) => zkpassportScan(req, session)); // see the adapter below
   ```

   The proof is kept in the store until the key exists and the registration is posted. `scanPassport` starts the work itself when the app did not.

2. **Key.** Either `createKeyFromWords()`, which returns the 12 words to show, or `await createKeyWithPasskey()`.
   - A passkey counts only when the platform reports it as synced (WebAuthn backup state). Otherwise it throws `passkey_not_backed_up` and the app should offer the words instead.
   - When the platform says it has no PRF support, no passkey is created (`passkey_noprf`).
   - The names the platform shows default to the registry's name.

3. **Confirm.** There is no registration and no ballot before a backup exists (`backup_required`), or before the voter has declined one in so many words: `session.declineBackup()` records that choice with the key, and the app owns the warning (a lost device means the last ballot stays counted and cannot be changed). The words of a words key stay readable (`session.words()`) for a backup made later.
   - Ask the voter for the words at `session.wordChallenge()` (three 1-based positions).
   - Call `session.confirmWords(positions, answers)`, which returns `{ ok, wrong }`; `wrong` lists the 1-based positions that do not match.
   - Case and French accents do not matter.

4. **Submit.** `await session.submitRegistration()` signs the body and posts it to the key's first channel, then waits 60 s for the ingest's signed ack before trying the next channel, in a fresh envelope.
   - A missed ack is recovered with `resendRegistration()`: the same body in a fresh envelope. A registration sent and never acked is also found in the log when the ingest took it.
   - A kept registration whose proof went stale is replaced from a fresh scan of the same registration key.
   - The position comes from the entries of the checkpoint that logged the registration: the registry's size in that note, less its registrations there, plus this one's rank among them in log order. No positions file is read (mirrors no longer have one). A key restored on a new device finds its leaf among the registry's leaves (`leaves/<k>.json`, the whole tree, which a ballot reads anyway).
   - `session.register({ obtainProof, key: 'words', confirm })` runs steps 1 to 4 in one call.

5. **Cast.** `await session.cast({ pick: 1 })`, or `{ rank: [2, 0] }` for ranked polls.
   - The session refuses to draft against a checkpoint older than 30 minutes (`stale_mirror`).
   - Ballots go to the key's channels after the first one, never to the registration's channel.
   - Re-votes continue the key's chain: the next seq in linked polls, the correction of the previous ballot in delta polls.
   - The device keeps its last seq (mirrors no longer publish one per pseudonym). A device without it (restored words, a new device) starts at 0 and raises the seq on each `stale_seq` refusal, by steps of 1, 2, 4, 8, then 16 (the ingest's seq gap), proving again each time, until one is accepted.
   - With the ledger's `revote_gap`, a re-vote within the gap of the pseudonym's newest ballot, or while that ballot is not logged yet, is refused as `too_soon`. The session refuses it before proving when its record says so, and otherwise passes on the ingest's refusal. The error's `data` is `{ retryAt, waitSeconds, exact }`: when the next ballot counts (unix seconds, the server's clock), how long that is from now, and whether it is exact (the newest ballot was found in the log) or estimated from its ack. The voter's last ballot before the close always counts.
   - A ballot no channel acknowledged is kept: call `resendBallot()`, or `discardKeptBallot()` to drop it.

6. **Receipts and complaints.**
   - While something waits, `refresh()` reads the entries of every checkpoint since the post. It runs on a timer, and live checkpoints come from a relay that is neither the registration's nor the ballots'.
   - A note's `mirror <commit>:<index>` names the newest pushed commit and the newest checkpoint it covers. Files are read at that commit; the entries of a later checkpoint are read once a later note covers it, and a ballot is drafted against the roots of the covered checkpoint (`checkpoints/<index>.txt`, verified). Notes of earlier versions (`mirror <commit>`) cover themselves.
   - A body that is missing from the checkpoint its ack named becomes a complaint. It is posted to the relays, or to the direct endpoint when there are none, and the device keeps it whole (relays keep no copy), see "Complaints" below.
   - A refusal the voter holds wrong: `await session.complainOfRefusal('registration' | 'ballot')` makes a complaint of the signed rejected ack and the body, keeps it, posts it, and returns it.

7. **Results.** `state.tally` holds the last tally that verified (proven in the log; signature, decryption proofs and values checked). A newer tally that fails is kept apart in `state.tallyUnverified`. A tlock tally never reaches `ok`: the browser only checks its beacon, and the openings are an auditor's job.

Other calls:
- `restoreFromWords(words)` and `restoreWithPasskey()` restore a key on a new device.
- A device link needs a relay among the channels (`link_unavailable` otherwise):
  - The new device calls `receiveLink()` and shows the resulting `publicKey`.
  - The old device calls `sendKeyTo(publicKey)` and shows `{ code }`.
  - Once the voter has compared the codes, the new device calls `answer(true)`.
  - The sender counts the link as a backup only when its `confirmed` promise resolves to `true`.
- `state.storage` is `persistent`, `best-effort` or `memory`. The session asks for `navigator.storage.persist()`.

Every error is an `IsoloirError` whose `code` belongs to the `IsoloirErrorCode` union. Some codes carry `data`; for example `bad_words` includes `{ unknown: [3, 8] }`, and `too_soon` includes `{ retryAt, waitSeconds, exact }`. `pow` means the proof of work could not be made, `bad_complaint` that a complaint could not be read. An envelope the ingest drops for its work gets no answer: it shows as `no_ack` once every channel was tried.

## Envelopes: kinds, channels, proof of work

**Kinds.** Messages travel on the ephemeral Nostr kinds 27100–27106: relays forward them to live subscriptions and keep none. An ingest of an earlier version reads only 7100–7106; an ingest of this version reads both and answers each envelope in its own range. The `kinds` option picks the range:
- `'auto'` (default): the legacy range until the ledger shows an ingest of this version, then the ephemeral one. The signs: a `pow` or `revote_gap` in the ledger setup (an earlier ingest cannot read such a ledger), a note whose mirror line names the checkpoint it covers, or a checkpoint event of kind 27103 from the ingest on a relay. `state.kinds` says which range is in use.
- `'ephemeral'` or `'legacy'`: forced.

Acks are read in both ranges, and device links are listened for in both.

**Channels.** The session tries the ledger's active channels by type, `nostr` first, then `iroh`, then `direct`, and within a type by the key's ranking. It moves to the next channel when no ack comes within `ackTimeoutMs` (60 s), each time in a fresh envelope. A registration starts with the first relay. Ballots start with the second and never use the registration's relay when there is another; in the other types the first comes last. A `ChannelFactory` that returns `null` leaves a channel out: the default one does so for iroh, which is specified but not built. An app with an iroh transport gives a factory that returns an `IngestChannel` for it (`send` posts one envelope and resolves with the ack, or with null when none came). Nothing else changes.

**Proof of work.** With the ledger's `pow` d > 0 (for example `"pow":16`), every envelope to the ingest carries `["pow","<t>","<nonce>"]`. The tag makes `SHA-256("isoloir/1/pow\n" ‖ origin ‖ "\n" ‖ pubkey ‖ "\n" ‖ t ‖ "\n" ‖ nonce)` start with d zero bits. The work is bound to the envelope's throwaway key and a time `t`, not to the body, so the session draws the key and mines before the body exists. The ingest takes `t` from 2 h before its clock to 5 min after; the session uses a key's work up to 1 h 45 min old, then mines again. Every envelope takes its own key, and the next one is mined as soon as one is taken. With `pow` absent or 0, there is no tag and nothing to mine.
- `session.startWork()` starts the work and resolves once it is ready. Call it when the passport step begins and when the ballot screen opens. `scanPassport()` and `cast()` start it too; a registration or a ballot waits for the work only if it is not ready yet.
- `state.pow` is `{ bits, state: 'none' | 'mining' | 'ready' }`.
- The hashing is the wasm core's. It runs in slices of about 8 ms that give the thread back (`pow: { sliceMs, chunk, yieldTo }` to tune), so the page stays responsive.
- Measured with Node 24 on an Apple M5 Pro, the wasm miner does about 0.16 µs per hash. For d = 16 that is 9 ms on average and 29 ms at the 95th percentile. Assuming a phone 8 times slower, that is 70 ms on average and 0.23 s at the 95th percentile. d = 18 stays under 1 s at the 95th percentile on such a phone.

## Complaints

A complaint (SPEC §11.3) is a signed event (kind 27106) carrying the ingest's signed ack and the body it answered. Relays keep none, so the device keeps each one whole, with the key (across re-votes and reloads):
- `state.complaints`: every complaint this device made, oldest first (32 kept), as `SavedComplaint` `{ what: 'registration' | 'ballot', poll?, claim: 'dropped' | 'wrong_refusal', checkpoint, at, event, link }`. `link` is the event's base64url: put it in a link fragment (`https://…/complaint#c=${link}`) or a file the voter saves.
- `state.ballot.complaints` and `state.registration.complaints` still give the ids, and `complaintEvents` the events themselves, for the current records.
- The `complaint` event gives `{ what, checkpoint, events, complaint }`.

Anyone judges a complaint against the mirror, with no account and no session:

```ts
import { decodeComplaint, judgeComplaint, jsDelivrSource, loadWasm } from '@isoloir/web';

const wasm = await loadWasm();
const event = decodeComplaint(location.hash);        // '#c=…', the base64url alone, or the event's JSON
const v = await judgeComplaint(wasm, event, {
	mirror: [jsDelivrSource('owner/repo')],
	verifierKey: 'vote.example/isoloir+1a2b3c4d+AQ…',  // pinned, as for the session
	verifyProof, verifyPassport                       // only a refusal of a ballot or a registration needs them (audit's verifiers)
});
// v.verdict: 'holds' | 'fails' | 'pending' | 'uncertain' | 'unchecked' | 'invalid'; v.detail says why.
// v.claim: what it claims (claim, kind, body, hash, ack, ack_event, time, checkpoint, reason).
// v.found: where a "dropped" body is in the log (late: after the checkpoint its ack named).
// v.rejudged: a refusal's judgments again, at the first and last second of the ack's minute, without and with what was pending.
```

- **dropped** (an accepted ack): `holds` when the checkpoint the ack named lacks the body (`found.late` when a later one holds it), `fails` when it holds it, `pending` while the mirror does not cover that checkpoint.
- **wrong_refusal** (a rejected ack): the wasm judge replays the log up to the ack's minute and judges the body again. `holds` when it accepts the body, `fails` when it refuses it (the detail says when the reason differs from the ack's), `uncertain` when the answer depends on the second or on what was pending, `unchecked` when a proof could not be verified.
- `invalid`: not a complaint of this ledger (its form, a signature, an ack not signed by the ledger's ingest).

`readComplaint(wasm, input, ingestKeys?)` checks the form alone and returns the claim. `encodeComplaint(event)` gives the base64url.

## The audit

`audit()` replays a mirror with the wasm judge. It reads mirrors of every version:
- Earlier logs hold `reject` entries (with a raw body, or with `author` and `size`) and `rejects` summaries. They are counted, not judged.
- An entry's body may be its text or its JSON.
- When the newest note's commit covers fewer checkpoints than the note, the audit stops at the last one whose files are on the mirror and says so in `warnings` (`upto`, `latest`).

Channels keep no copies, so the audit does not compare the log with the relays.

## The ZKPassport adapter (the app writes it)

The ingest's verifier (`../zkverifier/verify.mjs`) rebuilds the query from the registry's eligibility and the binding, so the browser must ask for exactly the same query:

```ts
import { NullifierType, ZKPassport } from '@zkpassport/sdk';

async function zkpassportScan(req: RegistrationRequest, session: Session): Promise<PassportProof> {
	const e = req.eligibility;
	const day = new Date(session.serverNow());              // the proof's day, on the server's clock
	const zk = new ZKPassport(e.domain);
	// The registry's identifier type: salted by its OPRF key, or the document's own.
	const id = e.oprf_key ? { uniqueIdentifierType: NullifierType.SALTED, oprfKeyId: e.oprf_key.id } : { uniqueIdentifierType: NullifierType.NON_SALTED };
	let q = await zk.request({ name: '…', logo: '…', purpose: '…', scope: e.scope, mode: 'compressed', validity: req.validity, ...id });
	if (e.min_age) q = q.gte('age', e.min_age);
	if (e.nationality?.length) q = q.in('nationality', e.nationality);
	if (e.document_type) q = q.eq('document_type', e.document_type);
	if (e.require_expiry) q = q.gte('expiry_date', day);    // must be the proof's day (±1)
	q = q.bind('custom_data', req.customData);               // binds the registration key
	const r = q.done();
	showQr(r.url);
	const proofs: unknown[] = [];
	return new Promise((resolve, reject) => {
		r.onProofGenerated((p: unknown) => proofs.push(p));
		r.onResult(({ uniqueIdentifier, verified, result }) => {
			if (!verified || !uniqueIdentifier) return reject(new Error('not verified'));
			resolve({
				uid: uniqueIdentifier,                           // the registry's identifier (salted or not)
				proof: { proofs, result },                       // the bundle verify.mjs takes
				proofDate: Math.floor(session.serverNow() / 1000)
			});
		});
		r.onReject(() => reject(new Error('rejected')));
		r.onError(reject);
	});
}
```

Notes:
- The identifier must be of the registry's type: salted (`NullifierType.SALTED` with `oprfKeyId`) when its eligibility has `oprf_key`, else the document's own (`NullifierType.NON_SALTED`). A salted identifier is still one per document (the OPRF is deterministic under the key), and the state that issued the passport cannot compute it alone; the verifier checks the proof's OPRF key against the registry's pinned one (SPEC §5). A proof of the other type is refused.
- A salted identifier may need a face match in the ZKPassport app (its OPRF nodes authenticate the query with one): not yet confirmed with a real passport.
- The callback names follow the SDK version the reference app used; check them against yours.
- With the `dev` provider (tests, `--dev` ingests), the bundle only needs `{ uid }`.

## The prover

Ballots are proven with noir_js and bb.js (UltraHonk, `verifierTarget: 'noir-recursive'`, which is what the ingest verifies with `bb`), in a Web Worker:

```ts
import { WorkerProver } from '@isoloir/web';

const prover = new WorkerProver(
	() => new Worker(new URL('@isoloir/web/prove.worker', import.meta.url), { type: 'module' }),
	async (circuit) => (await fetch(`${mirror}/circuits/${circuit}/artifact.json`)).text()
);
await prover.warm(pollCircuitName); // optional: loads the circuit, the SRS and the key before the vote
```

`@aztec/bb.js` (5.0.0) and `@noir-lang/noir_js` (1.0.0-beta.22) are optional peer dependencies; the worker imports them. bb.js uses threads only when the page is cross-origin isolated. Serve the app with:

```
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp      (or credentialless)
```

Without these headers it proves on one thread, which still works but is several times slower on phones. If the host cannot set headers, a service worker can add them.

### Pinned files: the SRS and bb.js's wasm from a CDN

By default bb.js fetches the SRS from Aztec's CDN (`crs.aztec-cdn.foundation`, with Range requests) and its wasm from the app's bundle (a 4 MB JavaScript chunk holding it as base64). The provers take options that move both to URLs the app chooses, each file fetched whole and used only if its SHA-256 is the one pinned:

```ts
import { WorkerProver, type ProverOptions } from '@isoloir/web';

const options: ProverOptions = {
	srs: {
		g1: { url: `${srs}/g1_compressed.dat`, sha256: 'fad8203ae1fd103658d4bb33b2b4cf126a28352b5de4684737cff23cc15fb94b' },
		g2: { url: `${srs}/g2.dat`, sha256: '01797bfc4de5a96f0e516a9ea4537d18786dc30cb991aca4274c95822b69c32f' }
		// grumpkin: { url, sha256 }  optional, see below
	},
	wasm: {
		threads: {
			url: 'https://cdn.jsdelivr.net/npm/@aztec/bb.js@5.0.0/dest/node/barretenberg_wasm/barretenberg-threads.wasm.gz',
			sha256: '2da2861cee60c2af5a87621474517e56b5d833db8a765f075e6cbc5509308eaa'
		}
	}
};
const prover = new WorkerProver(spawn, loader, options); // or new LocalProver(loader, options)
```

A file whose hash differs fails the warm-up or the ballot with `pin_mismatch` (`data: { url, expected, actual }`), an unreachable one with `prover`. The options are plain data: `WorkerProver` hands them to the worker with each request. Without them, bb.js behaves as before.

- **`srs.g1`**: BN254 G1 points in bb.js 5.0.0's compressed form (32 B a point), the head of Aztec's `g1_compressed.dat`. bb.js accepts only whole blocks of 2^17 points: the first 4,194,304 B hold 2^17 points, which every ballot circuit fits (the largest, `rankedm16_single_linked_d20`, is 46,800 gates, 65,536 once rounded up).
- **`srs.g2`**: Aztec's `g2.dat`, 128 B.
- **`srs.grumpkin`** (optional): Grumpkin points (64 B a point), the head of `grumpkin_g1_v2.dat`. UltraHonk ballots do not use them; without the file none is loaded (bb.js's own loader would fetch 4,194,304 B).
- **`wasm.threads`**: the shared-memory build, used when the page is cross-origin isolated; the npm package ships it gzipped, which jsDelivr serves as is with CORS and `Cross-Origin-Resource-Policy: cross-origin` (fine under COEP `credentialless` or `require-corp`). **`wasm.single`** (optional): the build without shared memory, for pages that are not isolated; the package ships it only as base64 inside a JavaScript file, so an app pins its own copy or lets bb.js load its bundled one. Browsers only: in Node bb.js reads its wasm from its package.

bb.js 5.0.0 takes no wasm bytes and no integrity, only a `wasmPath` it fetches itself. The prover gives it a path on a reserved host (`bb-wasm.isoloir.invalid`) and answers that one URL, through a `fetch` hook in the prover's thread, with the bytes it fetched and checked; every other request goes through. Unanswered, the reserved host does not resolve, so a wasm is never used unchecked. bb.js's JavaScript, its thread worker and noir_js stay in the app's bundle (about 3.9 MB, noir_js's two wasm files being 3.6 MB of it); the bundled wasm chunks are still emitted but never fetched.

The session compares the public inputs bb.js reports with those the wasm core rebuilds from the body (`prover_mismatch`), so a wrong circuit fails before anything is posted.

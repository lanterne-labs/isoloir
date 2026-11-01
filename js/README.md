# @isoloir/web

The browser side of isoloir (`../SPEC.md`), with no framework: keys, passport registration, ballots, receipts, complaints and results. The browser never calls the operator's server. It posts signed envelopes through the channels the ledger lists (Nostr relays, or the ingest's direct HTTP endpoint when the ledger has no relay). Everything else it reads as static files from the mirror.

Every protocol rule comes from the Rust crates compiled to WebAssembly (`../crates/wasm`): leaves, pseudonyms, ballot drafts, tlock sealing, checkpoint notes, log inclusion proofs, tally proofs and the 12 words. This package only orchestrates.

## Build

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-pack          # once
npm install
npm run wasm                     # wasm/web (browsers) and wasm/node (tests, with the dev helpers)
npm run check                    # tsc, strict
npm test                         # vitest: fake relays, a fake direct endpoint, a fake mirror, a fake ingest
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

1. **Scan.** The registration key is drawn before any voter key exists:

   ```ts
   await session.scanPassport(async (req) => zkpassportScan(req, session)); // see the adapter below
   ```

   The proof is kept in the store until the key exists and the registration is posted.

2. **Key.** Either `createKeyFromWords()`, which returns the 12 words to show, or `await createKeyWithPasskey()`.
   - A passkey counts only when the platform reports it as synced (WebAuthn backup state). Otherwise it throws `passkey_not_backed_up` and the app should offer the words instead.
   - When the platform says it has no PRF support, no passkey is created (`passkey_noprf`).
   - The names the platform shows default to the registry's name.

3. **Confirm.** There is no registration and no ballot before a backup exists (`backup_required`), or before the voter has declined one in so many words: `session.declineBackup()` records that choice with the key, and the app owns the warning (a lost device means the last ballot stays counted and cannot be changed). The words of a words key stay readable (`session.words()`) for a backup made later.
   - Ask the voter for the words at `session.wordChallenge()` (three 1-based positions).
   - Call `session.confirmWords(positions, answers)`, which returns `{ ok, wrong }`; `wrong` lists the 1-based positions that do not match.
   - Case and French accents do not matter.

4. **Submit.** `await session.submitRegistration()` signs the body and posts it to the key's first channel, then waits 60 s for the ingest's signed ack before trying the next channel.
   - A missed ack is recovered with `resendRegistration()`: the same body in a fresh envelope.
   - A kept registration whose proof went stale is replaced from a fresh scan of the same registration key.
   - The position comes from the checkpoint entries the session reads in order.
   - `session.register({ obtainProof, key: 'words', confirm })` runs steps 1 to 4 in one call.

5. **Cast.** `await session.cast({ pick: 1 })`, or `{ rank: [2, 0] }` for ranked polls.
   - The session refuses to draft against a checkpoint older than 30 minutes (`stale_mirror`).
   - Ballots go to the key's channels after the first one, never to the registration's channel.
   - Re-votes continue the key's chain: the next seq in linked polls, the correction of the previous ballot in delta polls.
   - A ballot no channel acknowledged is kept: call `resendBallot()`, or `discardKeptBallot()` to drop it.

6. **Receipts and complaints.**
   - While something waits, `refresh()` reads the entries of every checkpoint since the post. It runs on a timer, and live checkpoints come from a relay that is neither the registration's nor the ballots'.
   - A body that is missing from the checkpoint its ack named becomes a complaint. It is posted to the relays, or to the direct endpoint when there are none, and it stays on the device with the signed ack.

7. **Results.** `state.tally` holds the last tally that verified (proven in the log; signature, decryption proofs and values checked). A newer tally that fails is kept apart in `state.tallyUnverified`. A tlock tally never reaches `ok`: the browser only checks its beacon, and the openings are an auditor's job.

Other calls:
- `restoreFromWords(words)` and `restoreWithPasskey()` restore a key on a new device.
- A device link needs a relay among the channels (`link_unavailable` otherwise):
  - The new device calls `receiveLink()` and shows the resulting `publicKey`.
  - The old device calls `sendKeyTo(publicKey)` and shows `{ code }`.
  - Once the voter has compared the codes, the new device calls `answer(true)`.
  - The sender counts the link as a backup only when its `confirmed` promise resolves to `true`.
- `state.storage` is `persistent`, `best-effort` or `memory`. The session asks for `navigator.storage.persist()`.

Every error is an `IsoloirError` whose `code` belongs to the `IsoloirErrorCode` union. Some codes carry `data`; for example `bad_words` includes `{ unknown: [3, 8] }`.

## The ZKPassport adapter (the app writes it)

The ingest's verifier (`../zkverifier/verify.mjs`) rebuilds the query from the registry's eligibility and the binding, so the browser must ask for exactly the same query:

```ts
import { ZKPassport } from '@zkpassport/sdk';

async function zkpassportScan(req: RegistrationRequest, session: Session): Promise<PassportProof> {
	const e = req.eligibility;
	const day = new Date(session.serverNow());              // the proof's day, on the server's clock
	const zk = new ZKPassport(e.domain);
	let q = await zk.request({ name: '…', logo: '…', purpose: '…', scope: e.scope, mode: 'compressed', validity: req.validity /* , devMode */ });
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
				uid: uniqueIdentifier,                           // the non-salted unique identifier
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
- The identifier must be the document's own, not salted (`NullifierType.NON_SALTED`; the mock type in dev mode). A salted identifier would let one passport register twice.
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

The session compares the public inputs bb.js reports with those the wasm core rebuilds from the body (`prover_mismatch`), so a wrong circuit fails before anything is posted.

// verify.mjs checks the ZKPassport proofs of one registration (isoloir SPEC §6).
// The ingest (crates/server/src/eligibility.rs) runs it once per registration:
// the request is one JSON object on stdin, the answer one JSON object on stdout.
//
// stdin:  { proofs, result, challenge (the custom data the proof binds), domain, scope, minAge, nationality, devMode, rpcUrl,
//           documentType, requireExpiry, proofDate }: with requireExpiry the proof must show a document not expired at
//           proofDate (the base proof does not check the expiry; the query expiry_date >= <date> does, and the date the
//           browser chose, kept in the result, must be the proof's day)
// stdout: { verified, uniqueIdentifier, errors }
//
// The query is rebuilt here from the server's own settings and the one-time
// challenge, never taken from the browser, so a tampered request cannot pass.
// Verification is local (verifierMode "local"): the open-source verifier
// bundled in @zkpassport/sdk checks the proofs; only the registry roots of
// the certificates are read on-chain (Ethereum, through rpcUrl or the SDK's
// public endpoint). No ZKPassport account, key or API is used.

import { createRequire } from 'node:module';

// The CommonJS build: the ESM one imports the browser polyfill path
// 'buffer/', which the Node ESM loader refuses.
const { ZKPassport } = createRequire(import.meta.url)('@zkpassport/sdk');
const { NullifierType } = createRequire(import.meta.url)('@zkpassport/utils');

async function readStdin() {
	const chunks = [];
	for await (const chunk of process.stdin) chunks.push(chunk);
	return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function reply(obj) {
	process.stdout.write(JSON.stringify(obj) + '\n', () => process.exit(0));
}

try {
	const req = await readStdin();
	for (const k of ['proofs', 'result', 'challenge', 'domain', 'scope']) {
		if (!req[k]) throw new Error(`missing ${k}`);
	}
	if (!Array.isArray(req.proofs) || req.proofs.length === 0) throw new Error('proofs must be a non-empty array');

	const zk = new ZKPassport(req.domain);
	let builder = zk.createQuery();
	if (req.minAge) builder = builder.gte('age', req.minAge);
	if (req.nationality && req.nationality.length) builder = builder.in('nationality', Array.isArray(req.nationality) ? req.nationality : [req.nationality]);
	// A registry may take passports only: a passport and an identity card
	// give two identifiers.
	if (req.documentType) builder = builder.eq('document_type', req.documentType);
	if (req.requireExpiry) {
		const expected = req.result?.expiry_date?.gte?.expected;
		if (!expected) throw new Error('the proof does not show the document is not expired (no expiry_date query)');
		const date = new Date(expected);
		const ref = req.proofDate ? new Date(req.proofDate) : new Date();
		const day = 86_400_000;
		if (!(date.getTime() >= ref.getTime() - 2 * day && date.getTime() <= ref.getTime() + day)) {
			throw new Error(`the expiry check is against ${date.toISOString().slice(0, 10)}, not the proof's day`);
		}
		builder = builder.gte('expiry_date', date);
	}
	builder = builder.bind('custom_data', req.challenge);
	const { query } = builder.done();

	// The identifier must be the document's own (non-salted): a salted one
	// would be another identifier for the same passport. The validity is
	// the caller's (the ingest bounds proof_date itself; the audit runs
	// months later): without it the SDK refuses a proof older than 7 days.
	const { verified, uniqueIdentifier, queryResultErrors } = await zk.verify({
		proofs: req.proofs,
		originalQuery: query,
		queryResult: req.result,
		scope: req.scope,
		devMode: Boolean(req.devMode),
		uniqueIdentifierType: req.devMode ? NullifierType.NON_SALTED_MOCK : NullifierType.NON_SALTED,
		validity: req.validity || 10 * 365 * 86_400,
		verifierMode: 'local',
		config: req.rpcUrl ? { rpcUrl: req.rpcUrl } : undefined
	});
	reply({ verified: Boolean(verified && uniqueIdentifier), uniqueIdentifier: uniqueIdentifier ?? '', errors: queryResultErrors ?? null });
} catch (err) {
	// A failure of ours (the certificate registry on Ethereum unreachable, a
	// network error, the SDK's own loading) is not a refusal: the ingest
	// judges the message again later. A malformed request or a proof that
	// does not verify is.
	const msg = String(err?.message ?? err);
	const infrastructure = /ECONN|ENOTFOUND|ETIMEDOUT|EAI_AGAIN|fetch failed|network|timeout|rpc|rate limit|429|50\d|socket|ENOENT/i.test(msg) && !/missing |must be a non-empty|not show the document/i.test(msg);
	reply({ verified: false, uniqueIdentifier: '', infrastructure, errors: { message: msg } });
}
